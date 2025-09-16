import concurrent.futures
import filecmp
import json
import logging
import logging.config
import os
import os.path
import pathlib
import queue
import re
import shlex
import requests
import secrets
import select
import signal
import shutil
import string
import subprocess
import tempfile
import threading
import time
import tempfile
import uuid
import re
import sys
import zipfile
from datetime import datetime
from os import urandom
from time import sleep
from typing import Dict, List
from copy import deepcopy

import flask
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    url_for,
)
import werkzeug.serving
from werkzeug.utils import secure_filename

import hotspot
import aggregators
import config
from flask_util import RouteManager, check_restart_lock
import gitlab
import sdr
import stats
import system
import util
from util import (
    create_fake_info,
    make_int,
    print_err,
    run_shell_captured,
    string2file,
    verbose,
)
from wifi import make_wifi

logger = None


def setup_logging():
    logging.setLoggerClass(util.FlashingLogger)
    fmt = '%(asctime)s|||%(module)s|||%(name)s|||%(levelname)s|||%(message)s'
    logging.config.dictConfig({
        'version': 1,
        'formatters': {'simple': {'format': fmt}},
        'handlers': {
            'stream_handler': {
                'class': 'logging.StreamHandler', 'formatter': 'simple'}},
        'root': {'level': 'DEBUG', 'handlers': ['stream_handler']},})

    class NoStatic(logging.Filter):
        def filter(self, record: logging.LogRecord):
            """Filter GETs for static assets and maybe others."""
            msg = record.getMessage()
            if "GET /static/" in msg:
                return False
            if not (verbose & 8) and "GET /api/" in msg:
                return False

            return True

    logging.getLogger("werkzeug").addFilter(NoStatic())


def url_for_with_empty_parameters(*args, **kwargs):
    empty_parameters = set()
    for parameter in list(kwargs):
        if parameter.startswith("_"):
            # Internal kwarg.
            continue
        if kwargs[parameter] is None:
            del kwargs[parameter]
            empty_parameters.add(parameter)
    url = flask.url_for(*args, **kwargs)
    if not empty_parameters:
        return url
    if "_anchor" in kwargs:
        raise ValueError("adding an anchor is not supported")
    parameter_string="&".join(empty_parameters)
    if "?" in url:
        # At least one parameter already, append after &.
        return f"{url}&{parameter_string}"
    # No other parameters, append after ?.
    return f"{url}?{parameter_string}"


class PidFile:
    PID_FILE = pathlib.Path("/run/adsb-feeder.pid")

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def __enter__(self):
        if self.PID_FILE.exists():
            self._logger.warning(
                f"PID file {self.PID_FILE} already exists. Overwriting it, "
                "since adsb-feeder should only run once.")
        self.PID_FILE.write_text(str(os.getpid()))
        return self

    def __exit__(self, *_):
        self.PID_FILE.unlink()
        return False


class DmesgMonitor:
    def __init__(self, *, on_usb_change, on_undervoltage):
        self._on_usb_change = on_usb_change
        self._on_undervoltage = on_undervoltage
        self._monitor_thread = None
        self._keep_running = True
        self._logger = logging.getLogger(type(self).__name__)

    def start(self):
        assert self._monitor_thread is None
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        assert self._monitor_thread is not None
        self._keep_running = False
        self._monitor_thread.join(2)
        if self._monitor_thread.is_alive():
            self._logger.warning("dmesg monitor thread failed to stop.")
        else:
            self._logger.info("Stopped dmesg monitor.")

    def _monitor_loop(self):
        while self._keep_running:
            poll = select.poll()
            try:
                self._monitor(poll)
            except:
                self._logger.exception(
                    "Error monitoring dmesg. Trying to restart in a few "
                    "seconds.")
                time.sleep(10)

    def _monitor(self, poll):
        self._logger.info("Starting dmesg monitor.")
        # --follow-new: Wait and print only new messages. bufsize=0 so we can
        # poll() repeatedly (otherwise the buffer hides new output).
        proc = subprocess.Popen(
            ["dmesg", "--follow-new"],
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=0,
        )
        poll.register(proc.stdout, select.POLLIN)
        try:
            while self._keep_running:
                new_output = ""
                while poll.poll(500):
                    new_output += proc.stdout.readline()
                if not new_output:
                    continue
                if ("New USB device found" in new_output
                        or "USB disconnect" in new_output):
                    self._on_usb_change()
                if ("Undervoltage" in new_output
                        or "under-voltage" in new_output):
                    self._on_undervoltage
        finally:
            poll.unregister(proc.stdout)


class HotspotApp:
    """
    Routes for the hotspot frontend.

    Handles flask requests to display the frontend for the hotspot with which
    you can set wifi credentials. Has a catch-all route, since the hotspot
    intercepts (almost) all requests.
    """
    def __init__(self, conf: config.Config, on_wifi_credentials):
        self._conf = conf
        self._on_wifi_credentials = on_wifi_credentials
        self.ssids = []
        self._restart_state = "done"
        self._message = ""

    def handle_request(self, request):
        if request.path == "/hotspot" and request.method in ["GET"]:
            return self.hotspot()
        elif request.path == "/restarting":
            return self.restarting()
        elif request.path == "/restart" and request.method in ["POST", "GET"]:
            return self.restart()
        else:
            return self.catch_all()

    def restart(self):
        return self._restart_state

    def hotspot(self):
        return flask.render_template(
            "hotspot.html", comment=self._message, ssids=self.ssids)

    def catch_all(self):
        # Catch all requests not explicitly handled. Since our fake DNS server
        # resolves all names to us, this may literally be any request the
        # client tries to make to anyone. If it looks like they're sending us
        # wifi credentials, try those and restart. In all other cases, render
        # the /hotspot page.
        try:
            ssid, password = self._get_request_wifi_credentials()
            self._on_wifi_credentials(ssid, password)
            self._restart_state = "restarting"
        except ValueError:
            # Wasn't a request with credentials.
            pass

        if self._restart_state == "restarting":
            return flask.redirect("/restarting")

        return self.hotspot()

    def _get_request_wifi_credentials(self):
        ssid = request.form.get("ssid")
        password = request.form.get("passwd")
        if request.method != "POST" or None in [ssid, password]:
            raise ValueError("no credentials")
        return ssid, password

    def restarting(self):
        return flask.render_template("hotspot-restarting.html")

    def on_wifi_test_status(self, success):
        if not success:
            self._message = (
                "Failed to connect, wrong SSID or password, please try again.")
        self._restart_state = "done"


class AdsbIm:
    def __init__(self, conf: config.Config, sys: system.System, hotspot_app):
        self._logger = logging.getLogger(type(self).__name__)
        print_err("starting AdsbIm.__init__", level=4)
        self._conf = conf
        self._system = sys
        self._hotspot_app = hotspot_app
        self._hotspot_mode = False
        self._server = self._server_thread = None
        self._executor = concurrent.futures.ThreadPoolExecutor()
        self._background_tasks = {}
        self.app = Flask(__name__)
        self.app.secret_key = urandom(16).hex()

        # set Cache-Control max-age for static files served
        # cachebust.sh ensures that the browser doesn't get outdated files
        self.app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 1209600
        self.app.jinja_env.add_extension("jinja2.ext.loopcontrols")

        self.exiting = False

        @self.app.context_processor
        def env_functions():
            return {
                "get_conf": self._conf.get,
                "url_for": url_for_with_empty_parameters,
                "is_reception_enabled": self.is_reception_enabled,
            }

        self._routemanager = RouteManager(self.app)
        self._reception_monitor = stats.ReceptionMonitor(self._conf)
        # let's only instantiate the Wifi class if we are on WiFi
        self.wifi = None
        self.wifi_ssid = ""

        self._sdrdevices = sdr.SDRDevices()

        self.last_dns_check = 0
        self.undervoltage_epoch = 0

        self._dmesg_monitor = DmesgMonitor(
            on_usb_change=self._sdrdevices.ensure_populated,
            on_undervoltage=self._set_undervoltage)

        self._next_url_from_director = ""

        self.lastSetGainWrite = 0

        # no one should share a CPU serial with AirNav, so always create fake cpuinfo;
        # also identify if we would use the thermal hack for RB and Ultrafeeder
        if create_fake_info():
            self._conf.set("rbthermalhack", "/sys/class/thermal")
        else:
            self._conf.set("rbthermalhack", "")

        self._routemanager.add_proxy_routes(self._conf)
        self.app.add_url_rule(
            "/healthz",
            "healthz",
            self._decide_route_hotspot_mode(self.healthz),
            methods=["OPTIONS", "GET"],
        )
        self.app.add_url_rule(
            "/restarting",
            "restarting",
            self._decide_route_hotspot_mode(self.restarting),
        )
        self.app.add_url_rule(
            "/shutdownpage",
            "shutdownpage",
            self._decide_route_hotspot_mode(self.shutdownpage),
        )
        self.app.add_url_rule(
            "/restart",
            "restart",
            self._decide_route_hotspot_mode(self.restart),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/waiting",
            "waiting",
            self._decide_route_hotspot_mode(self.waiting),
        )
        self.app.add_url_rule(
            "/stream-log",
            "stream_log",
            self._decide_route_hotspot_mode(self.stream_log),
        )
        self.app.add_url_rule(
            "/backup",
            "backup",
            self._decide_route_hotspot_mode(self.backup),
        )
        self.app.add_url_rule(
            "/backupexecutefull",
            "backupexecutefull",
            self._decide_route_hotspot_mode(self.backup_execute_full),
        )
        self.app.add_url_rule(
            "/backupexecutegraphs",
            "backupexecutegraphs",
            self._decide_route_hotspot_mode(self.backup_execute_graphs),
        )
        self.app.add_url_rule(
            "/backupexecuteconfig",
            "backupexecuteconfig",
            self._decide_route_hotspot_mode(self.backup_execute_config),
        )
        self.app.add_url_rule(
            "/restore",
            "restore",
            self._decide_route_hotspot_mode(self.restore),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/executerestore",
            "executerestore",
            self._decide_route_hotspot_mode(self.executerestore),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/sdr_setup",
            "sdr_setup",
            self._decide_route_hotspot_mode(self.sdr_setup),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/visualization",
            "visualization",
            self._decide_route_hotspot_mode(self.visualization),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/expert",
            "expert",
            self._decide_route_hotspot_mode(self.expert),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/systemmgmt",
            "systemmgmt",
            self._decide_route_hotspot_mode(self.systemmgmt),
            methods=["GET"],
        )
        self.app.add_url_rule(
            "/aggregators",
            "aggregators",
            self._decide_route_hotspot_mode(self.aggregators),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/",
            "director",
            self._decide_route_hotspot_mode(self.director),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/info",
            "info",
            self._decide_route_hotspot_mode(self.info),
        )
        self.app.add_url_rule(
            "/overview",
            "overview",
            self._decide_route_hotspot_mode(self.overview),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/support",
            "support",
            self._decide_route_hotspot_mode(self.support),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/setup",
            "setup",
            self._decide_route_hotspot_mode(self.setup),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/sdplay_license",
            "sdrplay_license",
            self._decide_route_hotspot_mode(self.sdrplay_license),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/api/sdr_info",
            "sdr_info",
            self._decide_route_hotspot_mode(self.sdr_info),
        )
        self.app.add_url_rule(
            "/api/stats",
            "stats",
            self._decide_route_hotspot_mode(self.get_stats),
        )
        self.app.add_url_rule(
            "/api/status/<agg_key>",
            "agg_status",
            self._decide_route_hotspot_mode(self.agg_status),
        )
        self.app.add_url_rule(
            "/api/get_temperatures.json",
            "temperatures",
            self._decide_route_hotspot_mode(self.temperatures),
        )
        self.app.add_url_rule(
            "/set-ssh-credentials",
            "set-ssh-credentials",
            self._decide_route_hotspot_mode(self.set_ssh_credentials),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/create-root-password",
            "create-root-password",
            self._decide_route_hotspot_mode(self.create_root_password),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/set-secure-image",
            "set-secure-image",
            self._decide_route_hotspot_mode(self.set_secure_image),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/shutdown-reboot",
            "shutdown-reboot",
            self._decide_route_hotspot_mode(self.shutdown_reboot),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/toggle-log-persistence",
            "toggle-log-persistence",
            self._decide_route_hotspot_mode(self.toggle_log_persistence),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/feeder-update",
            "feeder-update",
            self._decide_route_hotspot_mode(self.feeder_update),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/restart-containers",
            "restart-containers",
            self._decide_route_hotspot_mode(self.restart_containers),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/configure-zerotier",
            "configure-zerotier",
            self._decide_route_hotspot_mode(self.configure_zerotier),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/configure-tailscale",
            "configure-tailscale",
            self._decide_route_hotspot_mode(self.configure_tailscale),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/configure-wifi",
            "configure-wifi",
            self._decide_route_hotspot_mode(self.configure_wifi),
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/get-logs",
            "get-logs",
            self._decide_route_hotspot_mode(self.get_logs),
        )
        self.app.add_url_rule(
            "/view-logs",
            "view-logs",
            self._decide_route_hotspot_mode(self.view_logs),
        )
        # Catch-all rules for the hotspot app.
        self.app.add_url_rule(
            "/",
            "/",
            view_func=self._decide_route_hotspot_mode(None),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/<path:path>",
            view_func=self._decide_route_hotspot_mode(None),
            methods=["GET", "POST"],
        )
        self.update_meminfo()
        self.update_journal_state()

        # Write out the env file in case anything has changed.
        self._conf.write_env_file()

    def _decide_route_hotspot_mode(self, view_func):
        """
        Decide route based on hotspot mode setting.

        We can be put into hotspot mode, in which case almost all routes
        (including a catch-all) should return the routes of the separate
        hotspot app for the captive portal. The only exception is /overview,
        which should be available there as well. Otherwise, use the configured
        view function.
        """
        def handle_request(*args, **kwargs):
            if self._hotspot_mode and not self._hotspot_app:
                self._logger.error(
                    "We've been put into hotspot mode, but don't have a "
                    "hotspot. Disabling it.")
                self._hotspot_mode = False
            if request.path in ["/healthz", "/overview"]:
                return view_func(*args, **kwargs)
            elif self._hotspot_mode:
                return self._hotspot_app.handle_request(request)
            elif view_func:
                return view_func(*args, **kwargs)
            else:
                # This must have been the catch-all we only need in hotspot
                # mode.
                flask.abort(404)

        return handle_request

    def _set_undervoltage(self):
        self._conf.set("under_voltage", True)
        self.undervoltage_epoch = time.time()

    @property
    def hotspot_mode(self):
        return self._hotspot_mode

    @hotspot_mode.setter
    def hotspot_mode(self, value):
        self._hotspot_mode = value
        # Restart the mDNS services, since our IP has probably changed coming
        # in and out of hotspot mode.
        self._maybe_enable_mdns()

    @property
    def hostname(self):
        return self._conf.get("site_name")

    def is_reception_enabled(self, reception_type):
        if reception_type == "ais":
            return bool(self._conf.get("serial_devices.ais"))
        elif reception_type == "adsb":
            return bool(
                self._conf.get("serial_devices.1090")
                or self._conf.get("serial_devices.978"))
        else:
            raise ValueError(f"Unknown reception type {reception_type}.")

    def start(self):
        if self._server:
            raise RuntimeError("already started")
        assert self._server_thread is None
        self.update_config()

        # if using gpsd, try to update the location
        if self._conf.get("use_gpsd"):
            self.get_lat_lon_alt()

        every_minute_task = util.RepeatingTask(60, self.every_minute)
        every_minute_task.start(execute_now=True)
        self._background_tasks["every_minute"] = every_minute_task

        # reset undervoltage indicator
        self._conf.set("under_voltage", False)

        self._dmesg_monitor.start()
        self._reception_monitor.start()
        self._maybe_enable_mdns()

        self._server = werkzeug.serving.make_server(
            host="0.0.0.0", port=int(self._conf.get("ports.web")),
            app=self.app, threaded=True)
        self._server_thread = threading.Thread(
            target=self._server.serve_forever, name="AdsbIm")
        self._server_thread.start()

    def update_config(self):
        # hopefully very temporary hack to deal with a broken container that
        # doesn't run on Raspberry Pi 5 boards
        board = self._conf.get("board_name", default="")
        if board.startswith("Raspberry Pi 5"):
            self._conf.set(
                "images.planefinder",
                "ghcr.io/sdr-enthusiasts/docker-planefinder:5.0.161_arm64")

        self.handle_implied_settings()
        self._conf.write_env_file()

    def stop(self):
        if not self._server:
            raise RuntimeError("not started")
        assert self._server_thread is not None
        self._logger.info("Shutting down.")
        self.exiting = True
        self._reception_monitor.stop()
        self._dmesg_monitor.stop()
        for task in self._background_tasks.values():
            task.stop_and_wait()
        self._executor.shutdown()
        self._server.shutdown()
        self._server_thread.join(timeout=10)
        if self._server_thread.is_alive():
            self._logger.warning(
                "Server thread failed to finish within timeout. Trying to "
                "continue.")
        self._server.server_close()
        self._server = self._server_thread = None

    def update_meminfo(self):
        self._memtotal = 0
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        self._memtotal = make_int(line.split()[1])
                        break
        except:
            pass

    def update_journal_state(self):
        # with no config setting or an 'auto' setting, the journal is persistent IFF /var/log/journal exists
        self._persistent_journal = pathlib.Path("/var/log/journal").exists()
        # read journald.conf line by line and check if we override the default
        try:
            result = subprocess.run(
                "systemd-analyze cat-config systemd/journald.conf", shell=True, capture_output=True, timeout=2.0
            )
            config = result.stdout.decode("utf-8")
        except:
            config = "Storage=auto"
        for line in config:
            if line.startswith("Storage=volatile"):
                self._persistent_journal = False
                break

    def update_dns_state(self):
        def update_dns():
            dns_state = self._system.check_dns()
            self._conf.set("dns_state", dns_state)
            if not dns_state:
                print_err("ERROR: we appear to have lost DNS")

        self.last_dns_check = time.time()
        self._executor.submit(update_dns)

    def set_hostname_and_enable_mdns(self):
        if self.hostname:
            subprocess.run(["/usr/bin/hostnamectl", "hostname", self.hostname])
        self._maybe_enable_mdns()

    def _maybe_enable_mdns(self):
        if not self._conf.get("mdns.is_enabled"):
            return
        args = ["/bin/bash", "/opt/adsb/scripts/mdns-alias-setup.sh"]
        mdns_domains = ["porttracker-feeder.local"]
        if self.hostname:
            # If we have a hostname, make the mDNS script create an alias for
            # it as well.
            mdns_domains.append(f"{self.hostname}.local")
        self._conf.set("mdns.domains", mdns_domains)
        subprocess.run(args + mdns_domains)

    def set_tz(self, timezone):
        # timezones don't have spaces, only underscores
        # replace spaces with underscores to correct this common error
        timezone = timezone.replace(" ", "_")

        success = self.set_system_tz(timezone)
        if success:
            self._conf.set("tz", timezone)
        else:
            self._logger.warning(
                f"Timezone {timezone} probably invalid, defaulting to UTC.",
                flash_message=True)
            self._conf.set("tz", "UTC")
            self.set_system_tz("UTC")

    def set_system_tz(self, timezone):
        # timedatectl can fail on dietpi installs (Failed to connect to bus: No such file or directory)
        # thus don't rely on timedatectl and just set environment for containers regardless of timedatectl working
        try:
            print_err(f"calling timedatectl set-timezone {timezone}")
            subprocess.run(["timedatectl", "set-timezone", f"{timezone}"], check=True)
        except subprocess.SubprocessError:
            print_err(f"failed to set up timezone ({timezone}) using timedatectl, try dpkg-reconfigure instead")
            try:
                subprocess.run(["test", "-f", f"/usr/share/zoneinfo/{timezone}"], check=True)
            except:
                print_err(f"setting timezone: /usr/share/zoneinfo/{timezone} doesn't exist")
                return False
            try:
                subprocess.run(["ln", "-sf", f"/usr/share/zoneinfo/{timezone}", "/etc/localtime"])
                subprocess.run("dpkg-reconfigure --frontend noninteractive tzdata", shell=True)
            except:
                pass

        return True

    def healthz(self):
        if request.method == "OPTIONS":
            response = flask.make_response()
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "*")
            response.headers.add("Access-Control-Allow-Methods", "*")
        else:
            response = flask.make_response("ok")
            response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    def restarting(self):
        return render_template("restarting.html")

    def shutdownpage(self):
        if self.exiting:
            return render_template("shutdownpage.html")
        else:
            return render_template("restarting.html")

    def restart(self):
        if self.exiting:
            return "exiting"

        self._system._restart.wait_restart_done(timeout=0.9)
        return self._system._restart.state

    def backup(self):
        return render_template("/backup.html")

    def backup_execute_config(self):
        return self.create_backup_zip()

    def backup_execute_graphs(self):
        return self.create_backup_zip(include_graphs=True)

    def backup_execute_full(self):
        return self.create_backup_zip(include_graphs=True, include_heatmap=True)

    def create_backup_zip(self, include_graphs=False, include_heatmap=False):
        adsb_path = config.CONFIG_DIR

        def graphs1090_writeback(uf_path):
            # the rrd file will be updated via move after collectd is done writing it out
            # so killing collectd and waiting for the mtime to change is enough

            rrd_file = uf_path / "graphs1090/rrd/localhost.tar.gz"

            def timeSinceWrite(rrd_file):
                # because of the way the file gets updated, it will briefly not exist
                # when the new copy is moved in place, which will make os.stat unhappy
                try:
                    return time.time() - os.stat(rrd_file).st_mtime
                except:
                    return time.time() - 0  # fallback to long time since last write

            t = timeSinceWrite(rrd_file)
            if t < 120:
                self._logger.info(
                    "graphs1090 writeback: not needed, timeSinceWrite: "
                    f"{round(t)}s")
                return

            self._logger.info(f"graphs1090 writeback: requesting")
            try:
                subprocess.run(
                    "docker exec ultrafeeder pkill collectd",
                    timeout=10.0,
                    shell=True,
                    check=True,
                )
            except:
                self._logger.exception(
                    f"graphs1090 writeback: docker exec failed - backed up graph data "
                    "might miss up to 6h", flash_message=True)
            else:
                count = 0
                increment = 0.1
                # give up after 30 seconds
                while count < 30:
                    count += increment
                    sleep(increment)
                    if timeSinceWrite(rrd_file) < 120:
                        print_err(f"graphs1090 writeback: success")
                        return

                self._logger.error(
                    "graphs1090 writeback: writeback timed out - backed up "
                    "graph data might miss up to 6h", flash_message=True)

        fdOut, fdIn = os.pipe()
        pipeOut = os.fdopen(fdOut, "rb")
        pipeIn = os.fdopen(fdIn, "wb")

        def zip2fobj(fobj, include_graphs, include_heatmap):
            try:
                with fobj as file, zipfile.ZipFile(file,
                                                   mode="w") as backup_zip:
                    backup_zip.write(
                        adsb_path / "config.json", arcname="config.json")

                    uf_path = adsb_path / "ultrafeeder"
                    gh_path = uf_path / "globe_history"
                    if include_heatmap and gh_path.is_dir():
                        for subpath in gh_path.iterdir():
                            pstring = str(subpath)
                            if subpath.name == "internal_state":
                                continue
                            if subpath.name == "tar1090-update":
                                continue

                            print_err(f"add: {pstring}")
                            for f in subpath.rglob("*"):
                                backup_zip.write(
                                    f, arcname=f.relative_to(adsb_path))

                    # do graphs after heatmap data as this can pause a couple
                    # seconds in graphs1090_writeback due to buffers, the
                    # download won't be recognized by the browsers until some
                    # data is added to the zipfile
                    if include_graphs:
                        graphs1090_writeback(uf_path)
                        graphs_path = (
                            uf_path / "graphs1090/rrd/localhost.tar.gz")
                        if graphs_path.exists():
                            backup_zip.write(
                                graphs_path,
                                arcname=graphs_path.relative_to(adsb_path))
                        else:
                            self._logger.error(
                                "graphs1090 backup failed, file not "
                                f"found: {graphs_path}", flash_message=True)

            except BrokenPipeError:
                self._logger.exception(
                    f"warning: backup download aborted mid-stream",
                    flash_message=True)

        self._executor.submit(
            zip2fobj,
            fobj=pipeIn,
            include_graphs=include_graphs,
            include_heatmap=include_heatmap,
        )

        now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
        download_name = f"adsb-feeder-config-{self.hostname}-{now}.backup"
        try:
            return send_file(
                pipeOut,
                mimetype="application/zip",
                as_attachment=True,
                download_name=download_name,
            )
        except TypeError:
            return send_file(
                pipeOut,
                mimetype="application/zip",
                as_attachment=True,
                attachment_filename=download_name,
            )

    def restore(self):
        if request.method == "POST":
            # check if the post request has the file part
            if "file" not in request.files:
                flash("No file submitted")
                return redirect(request.url)
            file = request.files["file"]
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == "":
                flash("No file selected")
                return redirect(request.url)
            if file.filename.endswith(".zip") or file.filename.endswith(".backup"):
                filename = secure_filename(file.filename)
                restore_path = config.CONFIG_DIR / "restore"
                # clean up the restore path when saving a fresh zipfile
                shutil.rmtree(restore_path, ignore_errors=True)
                restore_path.mkdir(mode=0o644, exist_ok=True)
                file.save(restore_path / filename)
                print_err(f"saved restore file to {restore_path / filename}")
                return redirect(url_for("executerestore", zipfile=filename))
            else:
                flash("Please only submit ADS-B Feeder Image backup files")
                return redirect(request.url)
        else:
            return render_template("/restore.html")

    def executerestore(self):
        if request.method == "GET":
            return self.restore_get(request)
        if request.method == "POST":
            form = deepcopy(request.form)

            def do_restore_post():
                self.restore_post(form)

            self._system._restart.bg_run(func=do_restore_post)
            return render_template("/restarting.html")

    def restore_get(self, request):
        # TODO
        raise NotImplementedError
        # the user has uploaded a zip file and we need to take a look.
        # be very careful with the content of this zip file...
        print_err("zip file uploaded, looking at the content")
        filename = request.args["zipfile"]
        restore_path = config.CONFIG_DIR / "restore"
        restore_path.mkdir(mode=0o755, exist_ok=True)
        restored_files: List[str] = []
        with zipfile.ZipFile(restore_path / filename, "r") as restore_zip:
            for name in restore_zip.namelist():
                print_err(f"found file {name} in archive")
                # remove files with a name that results in a path that doesn't start with our decompress path
                if not str(os.path.normpath(os.path.join(restore_path, name))).startswith(str(restore_path)):
                    print_err(f"restore skipped for path breakout name: {name}")
                    continue
                # only accept the .env file and config.json and files for ultrafeeder
                if name != ".env" and name != "config.json" and not name.startswith("ultrafeeder/"):
                    continue
                restore_zip.extract(name, restore_path)
                restored_files.append(name)
        # now check which ones are different from the installed versions
        changed: List[str] = []
        unchanged: List[str] = []
        saw_globe_history = False
        saw_graphs = False
        uf_paths = set()
        for name in restored_files:
            if name.startswith("ultrafeeder/"):
                parts = name.split("/")
                if len(parts) < 3:
                    continue
                uf_paths.add(parts[0] + "/" + parts[1] + "/")
            elif os.path.isfile(config.CONFIG_DIR / name):
                if filecmp.cmp(
                    config.CONFIG_DIR / name,
                    restore_path / name):
                    print_err(f"{name} is unchanged")
                    unchanged.append(name)
                else:
                    print_err(f"{name} is different from current version")
                    changed.append(name)

        changed += list(uf_paths)

        print_err(f"offering the usr to restore the changed files: {changed}")
        return render_template("/restoreexecute.html", changed=changed, unchanged=unchanged)

    def restore_post(self, form):
        # TODO
        raise NotImplementedError
        # they have selected the files to restore
        print_err("restoring the files the user selected")
        (config.CONFIG_DIR / "ultrafeeder").mkdir(
            mode=0o755, exist_ok=True)
        restore_path = config.CONFIG_DIR / "restore"
        restore_path.mkdir(mode=0o755, exist_ok=True)
        try:
            subprocess.call("/opt/adsb/docker-compose-adsb down -t 20", timeout=40.0, shell=True)
        except subprocess.TimeoutExpired:
            print_err("timeout expired stopping docker... trying to continue...")
        for name, value in form.items():
            if value == "1":
                print_err(f"restoring {name}")
                dest = config.CONFIG_DIR / name
                if dest.is_file():
                    shutil.move(dest, config.CONFIG_DIR / (name + ".dist"))
                elif dest.is_dir():
                    shutil.rmtree(dest, ignore_errors=True)

                if name != "config.json" and name != ".env":
                    shutil.move(restore_path / name, dest)
                    continue

                with config_lock:
                    shutil.move(restore_path / name, dest)

                    if name == ".env":
                        if "config.json" in form.keys():
                            # if we are restoring the config.json file, we don't need to restore the .env
                            # this should never happen, but better safe than sorry
                            continue
                        # so this is a backup from an older system, let's try to make this work
                        # read them in, replace the ones that match a norestore tag with the current value
                        # and then write this all back out as config.json
                        values = read_values_from_env_file()
                        for e in self._d._env:
                            if "norestore" in e.tags:
                                # this overwrites the value in the file we just restored with the current value of the running image,
                                # iow it doesn't restore that value from the backup
                                values[e.name] = e.value
                        write_values_to_config_json(values, reason="execute_restore from .env")

        # clean up the restore path
        restore_path = config.CONFIG_DIR / "restore"
        shutil.rmtree(restore_path, ignore_errors=True)

        # now that everything has been moved into place we need to read all the values from config.json
        # of course we do not want to pull values marked as norestore
        print_err("finished restoring files, syncing the configuration")

        for e in self._d._env:
            e._reconcile(e._value, pull=("norestore" not in e.tags))
            print_err(f"{'wrote out' if 'norestore' in e.tags else 'read in'} {e.name}: {e.value}")

        self.set_tz(self._conf.get("tz"))

        # make sure we are connected to the right Zerotier network
        zt_network = self._conf.get("zerotierid")
        if zt_network and len(zt_network) == 16:  # that's the length of a valid network id
            try:
                subprocess.call(
                    ["zerotier-cli", "join", f"{zt_network}"],
                    timeout=30.0,
                )
            except subprocess.TimeoutExpired:
                self._logger.exception(
                    "Timeout expired joining Zerotier network... trying to "
                    "continue...", flash_message=True)

        self.handle_implied_settings()
        self._conf.write_env_file()

        try:
            subprocess.call("/opt/adsb/docker-compose-start", timeout=180.0, shell=True)
        except subprocess.TimeoutExpired:
            self._logger.exception(
                "Timeout expired re-starting docker... trying to continue...",
                flash_message=True)

    def base_is_configured(self):
        mandatory_setting_key_paths = {"lon", "lat", "alt", "site_name"}
        for key_path in list(mandatory_setting_key_paths):
            if self._conf.get(key_path) is not None:
                mandatory_setting_key_paths.discard(key_path)
            else:
                self._logger.info(
                    f"Basic setup incomplete: {key_path} is missing.")
        return len(mandatory_setting_key_paths) == 0

    def at_least_one_aggregator(self) -> bool:
        return any(
            agg.enabled() for agg in aggregators.all_aggregators().values())

    def sdr_info(self):
        # get our guess for the right SDR to frequency mapping
        # and then update with the actual settings
        serial_guess: dict[str, str] = self._sdrdevices.addresses_per_frequency
        print_err(f"serial guess: {serial_guess}")
        serials: dict[str, str] = {
            purpose: self._conf.get(f"serial_devices.{purpose}")
            for purpose in ["978", "1090", "ais"]}
        configured_serials = {
            self._conf.get(f"serial_devices.{purpose}")
            for purpose in self._sdrdevices.purposes()}
        available_serials = [sdr.serial for sdr in self._sdrdevices.sdrs]
        for purpose in ["978", "1090", "ais"]:
            if (
                    (not serials[purpose]
                    or serials[purpose] not in available_serials)
                    and serial_guess[purpose] not in configured_serials):
                serials[purpose] = serial_guess[purpose]

        print_err(f"sdr_info->frequencies: {str(serials)}")
        jsonString = json.dumps(
            {
                "sdrdevices": [sdr._json for sdr in self._sdrdevices.sdrs],
                "frequencies": serials,
                "duplicates": ", ".join(self._sdrdevices.duplicates),
                "lsusb_output": self._sdrdevices.lsusb_output,
            },
            indent=2,
        )
        return Response(jsonString, mimetype="application/json")

    def get_lat_lon_alt(self):
        # get lat, lon, alt of an integrated or micro feeder either from gps data
        # or from the env variables
        lat = self._conf.get("lat", default=0)
        lon = self._conf.get("lon", default=0)
        alt = self._conf.get("alt", default=0)
        gps_json = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/gpsd.json")
        if self._conf.get("use_gpsd") and gps_json.exists():
            with gps_json.open() as f:
                gps = json.load(f)
                if "lat" in gps and "lon" in gps:
                    lat = float(gps["lat"])
                    lon = float(gps["lon"])
                    self._conf.set("lat", lat)
                    self._conf.set("lon", lon)
                if "alt" in gps:
                    alt = float(gps["alt"])
                    self._conf.set("alt", alt)
        return lat, lon, alt

    def get_stats(self):
        current_stats = self._reception_monitor.get_current_stats()
        stats = self._reception_monitor.stats
        ais = self._make_stats(
            self.is_reception_enabled("ais"), current_stats.ais,
            stats.ais.history)
        adsb = self._make_stats(
            self.is_reception_enabled("adsb"), current_stats.adsb,
            stats.adsb.history)
        return {"ais": ais, "adsb": adsb}

    def _make_stats(
            self, enabled: bool, current_stats: stats.CurrentCraftStats,
            history: list[stats.TimeFrameStats]):
        return {
            "enabled": enabled,
            "uptime": current_stats.uptime if enabled else None,
            "current": {
                "num": current_stats.num_crafts,
                "pps": current_stats.position_message_rate},
            "history": [{
                "ts": s.ts,
                "num": len(s.craft_ids),
                "pps": s.position_message_rate,} for s in history],}

    def agg_status(self, agg_key):
        try:
            aggregator = aggregators.all_aggregators()[agg_key]
        except KeyError:
            flask.abort(404)
        if not aggregator.enabled():
            return {}
        return aggregator.status

    @check_restart_lock
    def sdr_setup(self):
        if request.method == "POST":
            return self.update()
        return render_template("sdr_setup.html")

    def visualization(self):
        if request.method == "POST":
            return self.update()
        return render_template("visualization.html", site="", m=0)

    def clear_range_outline(self):
        self._logger.info("Resetting range outline for ultrafeeder.")
        setGainPath = pathlib.Path(f"/run/adsb-feeder-ultrafeeder/readsb/setGain")

        self.waitSetGainRace()
        string2file(path=setGainPath, string="resetRangeOutline", verbose=True)

    def waitSetGainRace(self):
        # readsb checks this the setGain file every 0.2 seconds
        # avoid races by only writing to it every 0.25 seconds
        wait = self.lastSetGainWrite + 0.25 - time.time()

        if wait > 0:
            time.sleep(wait)

        self.lastSetGainWrite = time.time()

    def set_rpw(self):
        issues_encountered = False
        success, output = run_shell_captured(f"echo 'root:{self.rpw}' | chpasswd")
        if not success:
            print_err(f"failed to overwrite root password: {output}")
            issues_encountered = True

        if os.path.exists("/etc/ssh/sshd_config"):
            success, output = run_shell_captured(
                "sed -i '/^PermitRootLogin.*/d' /etc/ssh/sshd_config &&"
                + "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && "
                + "systemctl restart sshd",
                timeout=5,
            )
            if not success:
                print_err(f"failed to allow root ssh login: {output}")
                issues_encountered = True

        success, output = run_shell_captured(
            "systemctl is-enabled ssh || systemctl is-enabled dropbear || "
            + "systemctl enable --now ssh || systemctl enable --now dropbear",
            timeout=60,
        )
        if not success:
            print_err(f"failed to enable ssh: {output}")
            issues_encountered = True

        if issues_encountered:
            self._logger.error(
                "Failure while setting root password, check logs for details",
                flash_message=True)

    def import_graphs_and_history_from_remote(self, ip, port):
        print_err(f"importing graphs and history from {ip}")
        # first make sure that there isn't any old data that needs to be moved
        # out of the way
        if pathlib.Path(config.CONFIG_DIR / "ultrafeeder" / ip).exists():
            now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
            shutil.move(
                config.CONFIG_DIR / "ultrafeeder" / ip,
                config.CONFIG_DIR / "ultrafeeder" / f"{ip}-{now}",
            )

        url = f"http://{ip}:{port}/backupexecutefull"
        # make tmpfile
        os.makedirs(config.CONFIG_DIR / "ultrafeeder", exist_ok=True)
        fd, tmpfile = tempfile.mkstemp(
            dir=config.CONFIG_DIR / "ultrafeeder")
        os.close(fd)

        # stream writing to a file with requests library is a pain so just use curl
        try:
            subprocess.run(
                ["curl", "-o", f"{tmpfile}", f"{url}"],
                check=True,
            )

            with zipfile.ZipFile(tmpfile) as zf:
                zf.extractall(path=config.CONFIG_DIR / "ultrafeeder" / ip)
            # deal with the duplicate "ultrafeeder in the path"
            shutil.move(
                config.CONFIG_DIR / "ultrafeeder" / ip / "ultrafeeder" / "globe_history",
                config.CONFIG_DIR / "ultrafeeder" / ip / "globe_history",
            )
            shutil.move(
                config.CONFIG_DIR / "ultrafeeder" / ip / "ultrafeeder" / "graphs1090",
                config.CONFIG_DIR / "ultrafeeder" / ip / "graphs1090",
            )

            print_err(f"done importing graphs and history from {ip}")
        except:
            self._logger.exception(
                f"ERROR when importing graphs and history from {ip}",
                flash_message=True)
        finally:
            os.remove(tmpfile)

    def setRtlGain(self):
        gaindir = (
            config.CONFIG_DIR / "ultrafeeder/globe_history/autogain")
        setGainPath = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/setGain")
        try:
            gaindir.mkdir(exist_ok=True, parents=True)
        except:
            pass
        gain = self._conf.get("gain")

        # autogain is configured via the container env vars to be always enabled
        # so we can change gain on the fly without changing env vars
        # for manual gain the autogain script in the container can be asked to do nothing
        # by touching the suspend file

        # the container based autogain script is never used now but the env var
        # READSB_GAIN=autogain must remain set so we can change the gain
        # without recreating the container, be it a change to a number or to
        # 'auto' gain built into readsb
        if False:
            (gaindir / "suspend").unlink(missing_ok=True)
        else:
            (gaindir / "suspend").touch(exist_ok=True)

            # this file sets the gain on readsb start
            string2file(path=(gaindir / "gain"), string=f"{gain}\n")

            # this adjusts the gain while readsb is running
            self.waitSetGainRace()
            string2file(path=setGainPath, string=f"{gain}\n")

    def handle_implied_settings(self):
        self._conf.set("mlathub_disable", False)

        ac_db = True
        if self._memtotal < 900000:
            ac_db = False
            # save 100 MB of memory for low memory setups

        self._conf.set("tar1090_ac_db", ac_db)

        # Set hostname and restart mDNS services in case the user changed the
        # hostname.
        self.set_hostname_and_enable_mdns()

        # make sure the uuids are populated:
        if not self._conf.get("adsblol_uuid"):
            self._conf.set("adsblol_uuid", str(uuid.uuid4()))
        if not self._conf.get("ultrafeeder_uuid"):
            self._conf.set("ultrafeeder_uuid", str(uuid.uuid4()))

        for agg in aggregators.all_aggregators().values():
            if (agg.enabled() and agg.needs_key
                    and not self._conf.get(f"aggregators.{agg.agg_key}.key")):
                self._logger.warning(f"Empty key, disabling {agg}.")
                self._conf.set(f"aggregators.{agg.agg_key}.is_enabled", False)

        # Explicitly enable mlathub unless disabled.
        self._conf.set("mlathub_enable", not self._conf.get("mlathub_disable"))

        if self._conf.get("tar1090_image_config_link") != "":
            self._conf.set("tar1090_image_config_link",
                f"http://HOSTNAME:{self._conf.get('ports.web')}/")

        self._conf.set(
            "ports.tar1090adjusted", self._conf.get("ports.tar1090"))

        # for regular feeders or micro feeders a max range of 300nm seem reasonable
        self._conf.set("max_range", 300)

        # fix up airspy installs without proper serial number configuration
        if self._conf.get("airspy"):
            if (
                    self._conf.get("serial_devices.1090") == ""
                    or self._conf.get("serial_devices.1090", default="").startswith("AIRSPY SN:")):
                self._sdrdevices.ensure_populated()
                airspy_serials = [sdr.serial for sdr in self._sdrdevices.sdrs if sdr.type == "airspy"]
                if len(airspy_serials) == 1:
                    self._conf.set("serial_devices.1090", airspy_serials[0])

        # make all the smart choices for plugged in SDRs
        # only run this for initial setup or when the SDR setup is requested via the interface
        if not self._conf.get("sdrs_locked"):
            # first grab the SDRs plugged in and check if we have one identified for UAT
            self._sdrdevices.ensure_populated()
            serial_978 = self._conf.get(f"serial_devices.978")
            serial_1090 = self._conf.get(f"serial_devices.1090")
            serial_ais = self._conf.get(f"serial_devices.ais")
            if serial_978 and not any([sdr.serial == serial_978 for sdr in self._sdrdevices.sdrs]):
                self._conf.set(f"serial_devices.978", "")
            if serial_1090 and not any([sdr.serial == serial_1090 for sdr in self._sdrdevices.sdrs]):
                self._conf.set(f"serial_devices.1090", "")
            if serial_ais and not any([sdr.serial == serial_ais for sdr in self._sdrdevices.sdrs]):
                self._conf.set(f"serial_devices.ais", "")
            auto_assignment = self._sdrdevices.addresses_per_frequency

            purposes = self._sdrdevices.purposes()

            # if we have an actual asignment, that overrides the auto-assignment,
            # delete the auto-assignment
            for frequency in ["978", "1090", "ais"]:
                if any(
                        auto_assignment[frequency] == self._conf.get(f"serial_devices.{purpose}")
                        for purpose in purposes):
                    auto_assignment[frequency] = ""
            if not self._conf.get("serial_devices.1090") and auto_assignment["1090"]:
                self._conf.set("serial_devices.1090", auto_assignment["1090"])
            if not self._conf.get("serial_devices.978") and auto_assignment["978"]:
                self._conf.set("serial_devices.978", auto_assignment["978"])
            if not self._conf.get("serial_devices.ais") and auto_assignment["ais"]:
                self._conf.set("serial_devices.ais", auto_assignment["ais"])

            stratuxv3 = any(
                [sdr.serial == self._conf.get("serial_devices.978") and sdr.type == "stratuxv3" for sdr in self._sdrdevices.sdrs]
            )
            if stratuxv3:
                self._conf.set("uat_device_type", "stratuxv3")
            else:
                self._conf.set("uat_device_type", "rtlsdr")

            # handle 978 settings for stage1
            if self._conf.get("serial_devices.978"):
                self._conf.set("uat978", True)
                self._conf.set("978url", "http://dump978/skyaware978")
                self._conf.set("978host", "dump978")
                self._conf.set("978piaware", "relay")
            else:
                self._conf.set("uat978", False)
                self._conf.set("978url", "")
                self._conf.set("978host", "")
                self._conf.set("978piaware", "")

            # next check for airspy devices
            airspy = any([sdr.serial == self._conf.get("serial_devices.1090") and sdr.type == "airspy" for sdr in self._sdrdevices.sdrs])
            self._conf.set("airspy", airspy)
            self._conf.set("airspyurl", "http://airspy_adsb" if airspy else "")
            # SDRplay devices
            sdrplay = any([sdr.serial == self._conf.get("serial_devices.1090") and sdr.type == "sdrplay" for sdr in self._sdrdevices.sdrs])
            self._conf.set("sdrplay", sdrplay)
            # Mode-S Beast
            modesbeast = any(
                [sdr.serial == self._conf.get("serial_devices.1090") and sdr.type == "modesbeast" for sdr in self._sdrdevices.sdrs]
            )

            # rtl-sdr
            rtlsdr = any(
                sdr.type == "rtlsdr"
                and sdr.serial in {
                    self._conf.get("serial_devices.1090"),
                    self._conf.get("serial_devices.ais")}
                for sdr in self._sdrdevices.sdrs)

            if rtlsdr:
                self._conf.set("readsb_device_type", "rtlsdr")
            elif modesbeast:
                self._conf.set("readsb_device_type", "modesbeast")
            else:
                self._conf.set("readsb_device_type", "")

            if rtlsdr:
                # set rtl-sdr 1090 gain, bit hacky but means we don't have to restart the bulky ultrafeeder for gain changes
                self.setRtlGain()

            if airspy:
                # make sure airspy gain is within bounds
                gain = self._conf.get(["gain"])
                if gain.startswith("auto"):
                    self._conf.set("gain_airspy", "auto")
                elif make_int(gain) > 21:
                    self._conf.set("gain_airspy", "21")
                    self._conf.set("gain", "21")
                elif make_int(gain) < 0:
                    self._conf.set("gain_airspy", "0")
                    self._conf.set("gain", "0")
                else:
                    self._conf.set("gain_airspy", gain)

            if verbose & 1:
                print_err(f"in the end we have")
                print_err(f"serial_devices.1090 {self._conf.get('serial_devices.1090')}")
                print_err(f"serial_devices.978 {self._conf.get('serial_devices.978')}")
                print_err(f"serial_devices.ais {self._conf.get('serial_devices.ais')}")
                print_err(f"airspy container is {self._conf.get('airspy')}")
                print_err(f"SDRplay container is {self._conf.get('sdrplay')}")
                print_err(f"dump978 container {self._conf.get('uat978')}")

            # if the base config is completed, lock down further SDR changes so they only happen on
            # user request
            if self.base_is_configured():
                self._conf.set("sdrs_locked", True)

        # finally, check if this has given us enough configuration info to
        # start the containers
        if self.base_is_configured():
            self._conf.set("base_config", True)
            if self.at_least_one_aggregator():
                self._conf.set("aggregators_chosen", True)

            if not self._conf.get("journal_configured"):
                try:
                    cmd = "/opt/adsb/scripts/journal-set-volatile.sh"
                    print_err(cmd)
                    subprocess.run(cmd, shell=True, timeout=5.0)
                    self.update_journal_state()
                    self._conf.set("journal_configured", True)
                except:
                    pass

    def set_docker_concurrent(self, value):
        self._conf.set("docker_concurrent", value)
        if not os.path.exists("/etc/docker/daemon.json") and value:
            # this is the default, nothing to do
            return
        try:
            with open("/etc/docker/daemon.json", "r") as f:
                daemon_json = json.load(f)
        except:
            daemon_json = {}
        new_daemon_json = daemon_json.copy()
        if value:
            del new_daemon_json["max-concurrent-downloads"]
        else:
            new_daemon_json["max-concurrent-downloads"] = 1
        if new_daemon_json != daemon_json:
            print_err(f"set_docker_concurrent({value}): applying change")
            with open("/etc/docker/daemon.json", "w") as f:
                json.dump(new_daemon_json, f, indent=2)
            # reload docker config (this is sufficient for the max-concurrent-downloads setting)
            success, output = run_shell_captured("bash -c 'kill -s SIGHUP $(pidof dockerd)'", timeout=5)
            if not success:
                print_err(f"failed to reload docker config: {output}")

    @check_restart_lock
    def update(self, *, needs_docker_restart=False):
        description = """
            This is the one endpoint that handles all the updates coming in from the UI.
            It walks through the form data and figures out what to do about the information provided.
        """
        # let's try and figure out where we came from - for reasons I don't understand
        # the regexp didn't capture the site number, so let's do this the hard way
        site = ""
        sitenum = 0
        extra_args = ""
        referer = request.headers.get("referer")
        allow_insecure = not self._conf.get("secure_image")
        print_err(f"handling input from {referer} and site # {sitenum} / {site} (allow insecure is {allow_insecure})")
        form: Dict = request.form
        seen_go = False
        next_url = None
        for key, value in form.items():
            emptyStringPrint = "''"
            print_err(f"handling {key} -> {emptyStringPrint if value == '' else value}")
            # this seems like cheating... let's capture all of the submit buttons
            if value == "go" or value.startswith("go-"):
                seen_go = True
            if value == "go" or value.startswith("go-") or value == "wait":
                if key == "showmap" and value.startswith("go-"):
                    idx = make_int(value[3:])
                    self._next_url_from_director = f"/map_{idx}/"
                    print_err(f"after applying changes, go to map at {self._next_url_from_director}")
                if key == "sdrplay_license_accept":
                    self._conf.set("sdrplay_license_accepted", True)
                if key == "sdrplay_license_reject":
                    self._conf.set("sdrplay_license_accepted", False)
                if key == "aggregators":
                    # user has clicked Submit on Aggregator page
                    self._conf.set("aggregators_chosen", True)
                    # set this to individual so if people have set "all" before can still deselect individual aggregators
                    self._conf.set("aggregator_choice", "individual")

                if key == "sdr_setup" and value == "go":
                    self._conf.set("sdrs_locked", False)
                if key == "no_config_link":
                    self._conf.set("tar1090_image_config_link", "")
                if key == "allow_config_link":
                    self._conf.set(
                        "tar1090_image_config_link",
                        "WILL_BE_SET_IN_IMPLIED_SETTINGS")
                if key == "turn_on_gpsd":
                    self._conf.set("use_gpsd", True)
                    # this updates the lat/lon/alt env variables as side effect, if there is a GPS fix
                    self.get_lat_lon_alt()
                if key == "turn_off_gpsd":
                    self._conf.set("use_gpsd", False)
                if key in ["enable_parallel_docker", "disable_parallel_docker"]:
                    self.set_docker_concurrent(key == "enable_parallel_docker")
                if key == "os_update":
                    self._system._restart.bg_run(func=self._system.os_update)
                    self._next_url_from_director = request.url
                    return render_template("/restarting.html")
            # now handle other form input
            if key == "clear_range" and util.checkbox_checked(value):
                self.clear_range_outline()
                continue
            if key == "resetgain" and util.checkbox_checked(value):
                # tell the ultrafeeder container to restart the autogain processing
                cmdline = "docker exec ultrafeeder /usr/local/bin/autogain1090 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    self._logger.exception(
                        "Error running Ultrafeeder autogain reset",
                        flash_message=True)
                continue
            if key == "resetuatgain" and util.checkbox_checked(value):
                # tell the dump978 container to restart the autogain processing
                cmdline = "docker exec dump978 /usr/local/bin/autogain978 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    self._logger.exception(
                        "Error running UAT autogain reset", flash_message=True)
                continue
            if key == "enable-prometheus-metrics":
                self._ensure_prometheus_metrics_state(
                    util.checkbox_checked(value))
                continue
            if key == "tz":
                self.set_tz(value)
                continue
            # Form data can directly set config variables if the key has the
            # format set_config--<data_type>--<key_path>, where data_type is
            # one of str, bool, or float, and key_path is the one in the
            # config. The data_type is used to parse the input into the
            # appropriate type.
            set_config_match = re.match(
                r"set_config--(?P<data_type>\S+)--(?P<key_path>\S+)", key)
            if set_config_match:
                data_type = set_config_match.group("data_type")
                key_path = set_config_match.group("key_path")
                try:
                    if data_type == "bool":
                        # Only checkboxes can be used as bool inputs. There is
                        # a small script hooking into any form submit that sets
                        # enabled checkboxes' values to "1", and disabled ones'
                        # to "0" (rather than leaving them out of the form
                        # altogether).
                        value = util.checkbox_checked(value)
                    elif data_type == "float":
                        # Remove letters, spaces, degree symbols before
                        # parsing.
                        value = float(re.sub("[a-zA-Z° ]", "", value))
                    else:
                        assert data_type == "str"
                except:
                    self._logger.exception(
                        f"Error parsing config setting {key_path}.",
                        flash_message=True)
                    continue

                if key_path == "uatgain" and value in ["", "auto"]:
                    value = "autogain"
                elif key_path == "gain" and value == "":
                    value = "auto"
                elif key_path == "site_name":
                    value = "".join(
                        c for c in value if c.isalnum() or c == "-")
                    value = value.strip("-")[:63]
                # If user is changing to 'individual' selection (either in
                # initial setup or when coming back to that setting later),
                # show them the aggregator selection page next.
                if (key_path == "aggregator_choice" and value == "individual"
                        and self._conf.get("aggregator_choice")
                        != "individual"):
                    next_url = url_for("aggregators")
                # If this is an assignment of an SDR device to a purpose (i.e.
                # ais, 1090 etc.), make sure that device is only assigned once
                # by clearing all of its other assignments.
                purposes = [
                    f"serial_devices.{p}" for p in self._sdrdevices.purposes()]
                if key_path in purposes and value != "":
                    for other_purpose in purposes:
                        if (key_path == other_purpose
                            or value != self._conf.get(other_purpose)):
                            continue
                        self._logger.info(
                            f"Device {value} was just assigned to purpose "
                            f"{key_path}, but still had a previous assignment "
                            f"to {other_purpose}. Clearing the old one so it "
                            "only has one purpose.")
                        self._conf.set(other_purpose, "")
                self._conf.set(key_path, value)

        # done handling the input data
        # what implied settings do we have (and could we simplify them?)

        self.handle_implied_settings()

        # write all this out to the .env file so that a docker-compose run will find it
        self._conf.write_env_file()

        if needs_docker_restart or seen_go:
            # Restart (i.e. up) the compose files if we're changing the page
            # via a "go" type submit button, or we've been explicitly told that
            # it's needed.
            self._system._restart.bg_run(
                cmdline="/opt/adsb/docker-compose-start", silent=False)

        # if the button simply updated some field, stay on the same page
        if not seen_go:
            print_err("no go button, so stay on the same page", level=2)
            return redirect(request.url)

        # where do we go from here?
        if next_url:  # we figured it out above
            return redirect(next_url)
        if self._conf.get("base_config"):
            print_err("base config is completed", level=2)
            if self._conf.get("sdrplay") and not self._conf.get("sdrplay_license_accepted"):
                return redirect(url_for("sdrplay_license"))
            return render_template("/restarting.html", extra_args=extra_args)
        print_err("base config not completed", level=2)
        return redirect(url_for("director"))

    def _ensure_prometheus_metrics_state(self, should_be_enabled: bool):
        currently_enabled = self._conf.get("prometheus.is_enabled")
        if currently_enabled != should_be_enabled:
            self._logger.info(
                f"Toggling Prometheus metrics state from {currently_enabled} "
                f"to {should_be_enabled}.")
        command = "enable" if should_be_enabled else "disable"
        proc, = system.systemctl().run(
            [f"{command} --now"], ["adsb-push-prometheus-metrics.timer"])
        if proc.returncode != 0:
            self._logger.error(
                "Error enabling/disabling Prometheus metrics state: "
                f"{proc.stdout}", flash_message=True)
            return
        self._conf.set("prometheus.is_enabled", should_be_enabled)

    @check_restart_lock
    def expert(self):
        if request.method == "POST":
            return self.update()
        return render_template("expert.html")

    @check_restart_lock
    def systemmgmt(self):
        tailscale_info = self._system.get_tailscale_info()
        if tailscale_info.status in [system.TailscaleStatus.ERROR,
                                     system.TailscaleStatus.NOT_INSTALLED,
                                     system.TailscaleStatus.DISABLED]:
            # Reset the login link in the config if Tailscale is not running.
            self._conf.set("tailscale.login_link", None)
        zerotier_running = False
        success, output = run_shell_captured("ps -e", timeout=2)
        zerotier_running = "zerotier-one" in output
        # create a potential new root password in case the user wants to change it
        alphabet = string.ascii_letters + string.digits
        self.rpw = "".join(secrets.choice(alphabet) for i in range(12))
        available_versions = gitlab.gitlab_repo().get_semver_tags()
        return render_template(
            "systemmgmt.html",
            tailscale_info=tailscale_info,
            zerotier_running=zerotier_running,
            rpw=self.rpw,
            available_versions=available_versions,
            containers=self._system.containers,
            persistent_journal=self._persistent_journal,
            wifi=self.wifi_ssid,
            is_semver=util.is_semver,
        )

    @check_restart_lock
    def sdrplay_license(self):
        if request.method == "POST":
            return self.update()
        return render_template("sdrplay_license.html")

    @check_restart_lock
    def aggregators(self):
        if request.method == "POST":
            self._configure_aggregators(request.form)
            return self.update(needs_docker_restart=True)

        any_non_adsblol_uf_aggregators = any(
            agg.enabled()
            for agg in aggregators.all_aggregators().values()
            if isinstance(agg, aggregators.UltrafeederAggregator)
            and not isinstance(agg, aggregators.AdsbLolAggregator))
        return render_template(
            "aggregators.html",
            aggregators=aggregators.all_aggregators(),
            any_non_adsblol_uf_aggregators=any_non_adsblol_uf_aggregators,
        )

    def _configure_aggregators(self, form: dict[str, str]):
        for agg_key in ["flightradar", "flightaware", "radarbox", "opensky"]:
            if f"{agg_key}-request-key" in form:
                # These aggregators have their own submit buttons to
                # automatically request keys etc. They used to have special
                # handling, but now we just configure all aggregators as usual
                # (including making these special requests if necessary).
                self._logger.info(
                    f"Aggregator form submitted from {agg_key} button.")
        for aggregator in aggregators.all_aggregators().values():
            configure_kwargs = self._make_configure_kwargs(
                aggregator.agg_key, form)
            self._logger.info(f"Configuring {aggregator}.")
            try:
                aggregator.configure(**configure_kwargs)
            except Exception as e:
                message = f"Failed to configure {aggregator.name}."
                if isinstance(e, aggregators.ConfigureError):
                    message = f"Failed to configure {aggregator.name}: {e}."
                self._logger.error(message, flash_message=True)
                self._logger.exception(
                    f"{message} (kwargs: {configure_kwargs})")

    def _make_configure_kwargs(self, agg_key: str,
                               form: dict[str, str]) -> dict[str, str | bool]:
        """Parse aggregator POST form data for aggregator configuration."""
        # All aggregators need the enabled arg, which is always called
        # {agg_key}-is-enabled.
        kwargs = {
            "enabled": util.checkbox_checked(form[f"{agg_key}-is-enabled"])}
        if agg_key in ["planewatch", "planefinder", "adsbhub", "radarvirtuel",
                       "1090uk"]:
            # These are the simple cases of account-based aggregators which
            # only require a key. This must be present in the form as
            # {agg_key}-key.
            kwargs["key"] = request.form.get(f"{agg_key}-key", "")
        elif agg_key == "flightradar":
            kwargs["adsb_sharing_key_or_email"] = (
                request.form.get("flightradar-key-or-email") or None)
            kwargs["uat_sharing_key_or_email"] = (
                request.form.get("flightradar-uat-key-or-email") or None)
        elif agg_key == "flightaware":
            kwargs["feeder_id"] = (
                request.form.get("flightaware-feeder-id") or None)
        elif agg_key == "radarbox":
            kwargs["sharing_key"] = (
                request.form.get("radarbox-sharing-key") or None)
        elif agg_key == "opensky":
            kwargs["user"] = request.form.get("opensky-user", "")
            kwargs["serial"] = request.form.get("opensky-serial") or None
        elif agg_key == "sdrmap":
            kwargs["user"] = request.form.get("sdrmap-user", "")
            kwargs["password"] = request.form.get("sdrmap-password", "")
        elif agg_key == "porttracker":
            kwargs["station_id"] = (
                request.form.get("porttracker-station-id", ""))
            kwargs["data_sharing_key"] = (
                request.form.get("porttracker-data-sharing-key", ""))
            kwargs["mqtt_protocol"] = (
                request.form.get("porttracker-mqtt-protocol", ""))
            kwargs["mqtt_host"] = request.form.get("porttracker-mqtt-host", "")
            kwargs["mqtt_port"] = request.form.get("porttracker-mqtt-port", "")
            kwargs["mqtt_username"] = (
                request.form.get("porttracker-mqtt-username", ""))
            kwargs["mqtt_password"] = (
                request.form.get("porttracker-mqtt-password", ""))
            kwargs["mqtt_topic"] = (
                request.form.get("porttracker-mqtt-topic", ""))
        elif agg_key == "aiscatcher":
            kwargs["feeder_key"] = (
                request.form.get("aiscatcher-feeder-key") or None)
        elif agg_key == "aishub":
            kwargs["udp_port"] = request.form.get("aishub-udp-port") or None
        return kwargs

    @check_restart_lock
    def director(self):
        # figure out where to go:
        if request.method == "POST":
            return self.update()
        if not self._conf.get("base_config"):
            print_err(f"director redirecting to setup, base_config not completed")
            return flask.redirect("/setup")
        # if we already figured out where to go next, let's just do that
        if self._next_url_from_director:
            print_err(f"director redirecting to next_url_from_director: {self._next_url_from_director}")
            url = self._next_url_from_director
            self._next_url_from_director = ""
            if re.match(r"^http://\d+\.\d+\.\d+\.\d+:\d+$", url):
                # this looks like it could be a forward to a tar1090 map
                # give it a few moments until this page is ready
                # but don't risk hanging out here forever
                testurl = url + "/data/receiver.json"
                for i in range(5):
                    sleep(1.0)
                    try:
                        response = requests.get(testurl, timeout=2.0)
                        if response.status_code == 200:
                            break
                    except:
                        pass
            return redirect(url)
        # If we have more than one SDR, or one of them is an airspy,
        # we need to go to sdr_setup - unless we have at least one of the serials set up
        # for 978 or 1090 reporting

        # do we have duplicate SDR serials?
        if len(self._sdrdevices.duplicates) > 0:
            print_err("duplicate SDR serials detected")
            # return self.sdr_setup()

        # check if any of the SDRs aren't configured
        configured_serials = [
            self._conf.get(f"serial_devices.{purpose}")
            for purpose in self._sdrdevices.purposes()]
        configured_serials = [
            serial for serial in configured_serials if serial != ""]
        available_serials = [sdr.serial for sdr in self._sdrdevices.sdrs]
        if any([serial not in configured_serials for serial in available_serials]):
            print_err(f"configured serials: {configured_serials}")
            print_err(f"available serials: {available_serials}")
            print_err("director redirecting to sdr_setup: unconfigured devices present")
            return flask.redirect("/sdr_setup")

        used_serials = [self._conf.get(f"serial_devices.{purpose}")
                        for purpose in ["978","1090","ais"]]
        used_serials = [serial for serial in used_serials if serial]
        if any([serial not in available_serials for serial in used_serials]):
            print_err(f"used serials: {used_serials}")
            print_err(f"available serials: {available_serials}")
            print_err("director redirecting to sdr_setup: at least one used device is not present")
            return flask.redirect("/sdr_setup")

        # if the user chose to individually pick aggregators but hasn't done so,
        # they need to go to the aggregator page
        if self.at_least_one_aggregator() or self._conf.get("aggregators_chosen"):
            return flask.redirect("/overview")
        print_err("director redirecting to aggregators: to be configured")
        return flask.redirect("/aggregators")

    def update_net_dev(self):
        try:
            result = subprocess.run(
                "ip route get 1 | head -1  | cut -d' ' -f5,7",
                shell=True,
                capture_output=True,
                timeout=2.0,
            ).stdout
        except:
            result = ""
        else:
            result = result.decode().strip()
            if " " in result:
                dev, addr = result.split(" ")
            else:
                dev = result
                addr = ""
        if result and addr:
            self.local_address = addr
            self.local_dev = dev
        else:
            self.local_address = ""
            self.local_dev = ""

        if self.local_dev.startswith("wlan"):
            if self.wifi is None:
                self.wifi = make_wifi()
            self.wifi_ssid = self.wifi.get_ssid()
        else:
            self.wifi_ssid = ""

    def every_minute(self):
        # make sure DNS works, every 5 minutes is sufficient
        if time.time() - self.last_dns_check > 300:
            self.update_dns_state()

        self._sdrdevices.ensure_populated()

        self.update_net_dev()

        zt_network = self._conf.get("zerotierid")
        if zt_network:
            try:
                result = subprocess.run(
                    ["zerotier-cli", "get", f"{zt_network}", "ip4"],
                    shell=True,
                    capture_output=True,
                    timeout=2.0,
                ).stdout
            except:
                result = ""
            else:
                result = result.decode().strip()
            self.zerotier_address = result
        else:
            self.zerotier_address = ""

        # reset undervoltage warning after 2h
        if self._conf.get("under_voltage") and time.time() - self.undervoltage_epoch > 2 * 3600:
            self._conf.set("under_voltage", False)

        # now let's check for disk space
        self._conf.set(
            "low_disk", shutil.disk_usage("/").free < 1024 * 1024 * 1024)

    @check_restart_lock
    def overview(self):
        enabled_aggregators = {
            k: a
            for k, a in aggregators.all_aggregators().items()
            if a.enabled()}
        for aggregator in enabled_aggregators.values():
            aggregator.refresh_status_cache()
        # if we get to show the feeder homepage, the user should have everything figured out
        # and we can remove the pre-installed ssh-keys and password
        if os.path.exists("/opt/adsb/adsb.im.passwd.and.keys"):
            print_err(
                "removing pre-installed ssh-keys, overwriting root password")
            authkeys = "/root/.ssh/authorized_keys"
            shutil.copyfile(authkeys, authkeys + ".bak")
            with open("/root/.ssh/adsb.im.installkey", "r") as installkey_file:
                installkey = installkey_file.read().strip()
            with open(authkeys + ".bak", "r") as org_authfile:
                with open(authkeys, "w") as new_authfile:
                    for line in org_authfile.readlines():
                        if "adsb.im" not in line and installkey not in line:
                            new_authfile.write(line)
            # now overwrite the root password with something random
            alphabet = string.ascii_letters + string.digits
            self.rpw = "".join(secrets.choice(alphabet) for i in range(12))
            self.set_rpw()
            os.remove("/opt/adsb/adsb.im.passwd.and.keys")

        if self.local_address:
            local_address = self.local_address
        else:
            local_address = request.host.split(":")[0]

        # this indicates that the last docker-compose-adsb up call failed
        compose_up_failed = os.path.exists("/opt/adsb/state/compose_up_failed")

        ipv6_broken = False
        if compose_up_failed:
            ipv6_broken = self._system.is_ipv6_broken()
            if ipv6_broken:
                print_err("ERROR: broken IPv6 state detected")

        def sdr_assignment(sdr):
            for purpose in ["1090", "978", "ais"]:
                if self._conf.get(f"serial_devices.{purpose}") == sdr.serial:
                    return purpose
            return None

        available_tags = gitlab.gitlab_repo().get_tags()
        # Prepare dicts describing all the different ways of reaching this
        # feeder.
        tailscale_info = self._system.get_tailscale_info()
        device_hosts = []
        device_hosts += [{
            "host": di.ip,
            "comment": f"device { di.device } via { di.gateway }"
        } for di in self._system.system_info.network_device_infos]
        device_hosts += [{"host": domain, "comment": None}
                         for domain in self._conf.get("mdns.domains")]
        if tailscale_info.dns_name:
            device_hosts.append({
                "host": tailscale_info.dns_name, "comment": "via Tailscale"})
        device_hosts += [{"host": str(ip), "comment": "via Tailscale"}
                         for ip in tailscale_info.ipv4s]
        return render_template(
            "overview.html",
            enabled_aggregators=enabled_aggregators,
            local_address=local_address,
            zerotier_address=self.zerotier_address,
            compose_up_failed=compose_up_failed,
            containers=self._system.containers,
            sdrs=self._sdrdevices.sdrs,
            sdr_assignment=sdr_assignment,
            tags=available_tags,
            system_info=self._system.system_info,
            device_hosts=device_hosts,
        )

    @check_restart_lock
    def setup(self):
        if request.method == "POST" and request.form.get("submit") == "go":
            return self.update()
        # make sure DNS works
        self.update_dns_state()
        return render_template("setup.html", mem=self._memtotal)

    def temperatures(self):
        temperature_json = {}
        try:
            with open("/run/adsb-feeder-ultrafeeder/temperature.json", "r") as temperature_file:
                temperature_json = json.load(temperature_file)
                now = int(time.time())
                age = now - int(temperature_json.get("now", "0"))
                temperature_json["age"] = age
        except:
            pass
        return temperature_json

    def support(self):
        print_err(f"support request, {request.form}")
        if request.method != "POST":
            return render_template("support.html", url="")

        url = "Internal Error uploading logs"

        target = request.form.get("upload")
        print_err(f'trying to upload the logs with target: "{target}"')

        if not target:
            print_err(f"ERROR: support POST request without target")
            return render_template("support.html", url="Error, unspecified upload target!")

        if target == "0x0.st":
            success, output = run_shell_captured(
                command="bash /opt/adsb/log-sanitizer.sh 2>&1 | curl -F'expires=168' -F'file=@-'  https://0x0.st",
                timeout=60,
            )
            url = output.strip()
            if success:
                print_err(f"uploaded logs to {url}")
            else:
                print_err(f"failed to upload logs, output: {output}")
                self._logger.error(
                    "Failed to upload logs.", flash_message=True)
            return render_template("support.html", url=url)

        if target == "termbin.com":
            success, output = run_shell_captured(
                command="bash /opt/adsb/log-sanitizer.sh 2>&1 | nc termbin.com 9999",
                timeout=60,
            )
            # strip extra chars for termbin
            url = output.strip("\0\n").strip()
            if success:
                print_err(f"uploaded logs to {url}")
            else:
                print_err(f"failed to upload logs, output: {output}")
                self._logger.error(
                    "Failed to upload logs.", flash_message=True)
            return render_template("support.html", url=url)

        if target == "local_view" or target == "local_download":
            return self.download_logs(target)

        return render_template("support.html", url="upload logs: unexpected code path")

    def get_logs(self):
        return self.download_logs("local_download")

    def view_logs(self):
        return self.download_logs("local_view")

    def download_logs(self, target):
        as_attachment = target == "local_download"

        fdOut, fdIn = os.pipe()
        pipeOut = os.fdopen(fdOut, "rb")
        pipeIn = os.fdopen(fdIn, "wb")

        def get_log(fobj):
            subprocess.run(
                "bash /opt/adsb/log-sanitizer.sh",
                shell=True,
                stdout=fobj,
                stderr=subprocess.STDOUT,
                timeout=30,
            )

        self._executor.submit(get_log, fobj=pipeIn)

        now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
        download_name = f"adsb-feeder-config-{self.hostname}-{now}.txt"
        return send_file(
            pipeOut,
            as_attachment=as_attachment,
            download_name=download_name,
        )

    def info(self):
        sdrs = [f"{sdr}" for sdr in self._sdrdevices.sdrs] if len(self._sdrdevices.sdrs) > 0 else ["none"]

        def simple_cmd_result(cmd):
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=2.0)
                return result.stdout.decode("utf-8")
            except:
                return f"failed to run '{cmd}'"

        storage = simple_cmd_result("df -h | grep -v overlay")
        kernel = simple_cmd_result("uname -rvmo")
        memory = simple_cmd_result("free -h")
        top = simple_cmd_result("top -b -n1 | head -n5")
        journal = "persistent on disk" if self._persistent_journal else "in memory"

        if self._system.is_ipv6_broken():
            ipv6 = "IPv6 is broken (IPv6 address assigned but can't connect to IPv6 hosts)"
        else:
            ipv6 = "IPv6 is working or disabled"

        netdog = simple_cmd_result("tail -n 10 /opt/adsb/logs/netdog.log 2>/dev/null")

        images = [
            image_setting.get("")
            for _, image_setting in self._conf.get_setting("images")]
        return render_template(
            "info.html",
            system_info=self._system.system_info,
            memory=memory,
            top=top,
            storage=storage,
            kernel=kernel,
            journal=journal,
            ipv6=ipv6,
            images=images,
            sdrs=sdrs,
            netdog=netdog,
        )

    def waiting(self):
        return render_template("waiting.html", title="ADS-B Feeder performing requested actions")

    def stream_log(self):
        logfile = "/run/adsb-feeder-image.log"

        def tail():
            with open(logfile, "r") as file:
                ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                tmp = file.read()[-16 * 1024 :]
                # discard anything but the last 16 kB
                while self._system._restart.state == "busy":
                    tmp += file.read(16 * 1024)
                    if tmp and tmp.find("\n") != -1:
                        block, tmp = tmp.rsplit("\n", 1)
                        block = ansi_escape.sub("", block)
                        lines = block.split("\n")
                        data = "".join(["data: " + line + "\n" for line in lines])
                        yield data + "\n\n"
                    else:
                        time.sleep(0.2)

        return Response(tail(), mimetype="text/event-stream")

    def set_ssh_credentials(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot set SSH credentials.", 400
        ssh_dir = pathlib.Path("/root/.ssh")
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        with open(ssh_dir / "authorized_keys", "a+") as authorized_keys:
            authorized_keys.write(f"{request.form['ssh-public-key']}\n")
        self._conf.set("ssh_configured", True)
        success, output = run_shell_captured(
            "systemctl is-enabled ssh || systemctl is-enabled dropbear || "
            + "systemctl enable --now ssh || systemctl enable --now dropbear",
            timeout=60,
        )
        if not success:
            self._logger.error(
                f"Failed to enable ssh: {output}",
                flash_message="Failed to enable ssh - check the logs "
                "for details.")
        return redirect(url_for("systemmgmt"))

    def create_root_password(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot set root password.", 400
        self._logger.info("Updating the root password.")
        self.set_rpw()
        return redirect(url_for("systemmgmt"))

    def set_secure_image(self):
        self._conf.set("secure_image", True)
        return redirect(url_for("systemmgmt"))

    @check_restart_lock
    def shutdown_reboot(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot shutdown or reboot.", 400
        if "shutdown" in request.form:
            # schedule shutdown in 0.5 seconds
            self._system.shutdown(delay=0.5)
            self.exiting = True
            return redirect(url_for("shutdownpage"))
        elif "reboot" in request.form:
            # schedule reboot in 0.5 seconds
            self._system.reboot(delay=0.5)
            self.exiting = True
            return redirect(url_for("restarting"))
        else:
            self._logger.warning(
                "Shutdown/reboot endpoint called, but neither shutdown nor "
                "reboot were in the form.")
        return redirect(url_for("systemmgmt"))

    def toggle_log_persistence(self):
        if self._persistent_journal:
            cmd = "/opt/adsb/scripts/journal-set-volatile.sh"
        else:
            cmd = "/opt/adsb/scripts/journal-set-persist.sh"
        try:
            subprocess.run(cmd, shell=True, timeout=5.0)
            self.update_journal_state()
        except:
            self._logger.exception("Error toggling log persistence.")
        return redirect(url_for("systemmgmt"))

    @check_restart_lock
    def feeder_update(self):
        tag = request.form["tag"]
        self._logger.info(f"Starting update to {tag}.")
        # Submit the update script as a transient systemd unit, so the
        # process is independent from us and can shut us down.
        try:
            system.systemctl().run_transient(
                "adsb-feeder-update",
                ["/opt/adsb/scripts/update-feeder.bash", tag])
        except:
            self._logger.exception(
                "Error starting update. Trying to redirect to home.")
            return flask.redirect("/")
        # Set the exiting flag, so the /restart endpoint can tell the
        # restarting page that this instance is still going down. The new
        # version will then say that the restart is complete.
        self.exiting = True
        return render_template("/restarting.html")

    def restart_containers(self):
        containers_to_restart = []
        for container in self._system.containers:
            # Only restart the ones that have been checked.
            if util.checkbox_checked(request.form[container.name]):
                containers_to_restart.append(container.name)
        self._conf.write_env_file()
        if "recreate" in request.form:
            self._system.recreate_containers(containers_to_restart)
        else:
            self._system.restart_containers(containers_to_restart)
        return render_template("/restarting.html")

    def configure_zerotier(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot configure zerotier.", 400
        if (not util.checkbox_checked(request.form["enabled"])
                or "zerotierid" not in request.form):
            self._conf.set("zerotierid", "")
            success, output = run_shell_captured(
                "systemctl disable --now zerotier-one && systemctl mask zerotier-one", timeout=30
            )
            return redirect(url_for("systemmgmt"))
        zerotier_id = request.form["zerotierid"]
        try:
            system.systemctl().run(["unmask", "enable --now"],
                                    ["zerotier-one"])
            # Wait for the service to get ready...
            sleep(5.0)
            subprocess.call([
                "/usr/sbin/zerotier-cli", "join", zerotier_id])
        except:
            self._logger.exception(
                "Exception trying to set up zerotier - giving up",
                flash_message=True)
        return redirect(url_for("systemmgmt"))

    def configure_tailscale(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot configure tailscale.", 400
        if self._system.get_tailscale_info().status in [
                system.TailscaleStatus.NOT_INSTALLED,
                system.TailscaleStatus.ERROR]:
            self._conf.set("tailscale.is_enabled", False)
            return "Tailscale is not installed (properly)", 500
        if not util.checkbox_checked(request.form["enabled"]):
            system.systemctl().run(["disable --now", "mask"],
                                   ["tailscaled.service"])
            self._conf.set("tailscale.is_enabled", False)
            self._logger.info("Disabled Tailscale.")
            return redirect(url_for("systemmgmt"))
        self._conf.set("tailscale.is_enabled", True)
        try:
            system.systemctl().run(["unmask", "enable --now"],
                                   ["tailscaled.service"])
        except:
            self._logger.exception(
                "Error starting Tailscale daemon.", flash_message=True)
            return "Error starting Tailscale.", 500
        ts_args = request.form.get("tailscale-extras", "")
        if ts_args:
            # right now we really only want to allow the login server arg
            try:
                ts_cli_switch, ts_cli_value = ts_args.split("=")
            except:
                ts_cli_switch, ts_cli_value = ["", ""]
            if ts_cli_switch != "--login-server":
                self._logger.warning(
                    "At this point we only allow the "
                    "--login-server=<server> argument.",
                flash_message=True)
                return f"Unsupported switch {ts_cli_switch}.", 400
            match = re.match(
                r"^https?://[-a-zA-Z0-9._\+~=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?::[0-9]{1,5})?(?:[-a-zA-Z0-9()_\+.~/=]*)$",
                ts_cli_value,
            )
            if not match:
                self._logger.error(
                    "The login server URL didn't make sense "
                    f"{ts_cli_value}", flash_message=True)
                return f"Invalid login server URL {ts_cli_value}.", 400
        self._conf.set("tailscale.extras", ts_args)
        self._logger.info(f"Starting Tailscale with args {ts_args}")
        try:
            # due to the following error, we just add --reset to the options
            # Error: changing settings via 'tailscale up' requires mentioning
            # all non-default flags. To proceed, either re-run your command
            # with --reset or use the command below to explicitly mention the
            # current value of all non-default settings:
            cmd = [
                "/usr/bin/tailscale",
                "up",
                "--reset",
                f"--hostname={self.hostname}",
                "--accept-dns=false",]
            if ts_args:
                cmd += [f"--login-server={shlex.quote(ts_cli_value)}"]
            proc = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                text=True,
            )
            os.set_blocking(proc.stderr.fileno(), False)
        except:
            self._logger.exception(
                "Exception trying to set up tailscale - giving up",
                flash_message=True)
            return "Error setting up Tailscale.", 500
        start_time = time.time()
        match = None
        while time.time() - start_time < 30:
            output = proc.stderr.readline()
            if not output:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            # standard tailscale result
            match = re.search(r"(https://login\.tailscale.*)", output)
            if match:
                break
            # when using a login-server
            match = re.search(r"(https://.*/register/nodekey.*)", output)
            if match:
                break

        proc.terminate()

        if match:
            login_link = match.group(1)
            self._logger.info(f"Found Tailscale login link {login_link}")
            self._conf.set("tailscale.login_link", login_link)
        elif proc.returncode == 0:
            # tailscale up will return immediately with successful return if
            # it's already logged in.
            info = self._system.get_tailscale_info()
            if info.status == system.TailscaleStatus.LOGGED_IN:
                self._logger.info(
                    "Started Tailscale (was already logged in).")
                return redirect(url_for("systemmgmt"))
        else:
            self._logger.error(
                "ERROR: tailscale didn't provide a login link "
                "within 30 seconds", flash_message=True)
            return "Unable to get a login link", 500
        return redirect(url_for("systemmgmt"))

    @check_restart_lock
    def configure_wifi(self):
        if self._conf.get("secure_image"):
            return "Image is secured, cannot configure wifi.", 400
        ssid = request.form.get("wifi_ssid")
        password = request.form.get("wifi_password")

        def connect_wifi():
            if self.wifi is None:
                self.wifi = make_wifi()
            status = self.wifi.wifi_connect(ssid, password)
            self._logger.debug(f"wifi_connect returned {status}")
            self.update_net_dev()

        self._system._restart.bg_run(func=connect_wifi)
        return redirect(url_for("systemmgmt"))


class Manager:
    """
    Application manager.

    The main purpose of this manager is to decide whether the main app should
    be running, or the hotspot app used to provide a convenient way of
    configuring a wifi password.

    This decision is based mostly on input from the ConnectivityMonitor, which
    regularly checks whether we can reach the open internet. If we can, we want
    to run the main app, otherwise the hotspot.

    However, an additional criterion is that the hotspot shouldn't run for too
    long if it yields no success. That's because it blocks the wifi device, so
    in case a lost connection is actually an upstream issue (e.g. in the
    router), we have to stop the hotspot or we won't notice this. So after a
    while, the hotspot is disabled an the main app started. If we then find we
    have connection again, it is kept running, otherwise the hotspot is started
    again.
    """
    CONNECTIVITY_CHECK_INTERVAL = 60
    HOTSPOT_TIMEOUT = 300
    HOTSPOT_RECHECK_TIMEOUT = CONNECTIVITY_CHECK_INTERVAL * 2 + 10

    def __init__(self, conf: config.Config, sys: system.System):
        self._event_queue = queue.Queue(maxsize=10)
        self._connectivity_monitor = None
        self._connectivity_change_thread = None
        self._hotspot_app = HotspotApp(conf, self._on_wifi_credentials)
        self._hotspot = hotspot.make_hotspot(conf, self._on_wifi_test_status)
        self._adsb_im = AdsbIm(conf, sys, self._hotspot_app)
        self._hotspot_timer = None
        self._keep_running = True
        self._logger = logging.getLogger(type(self).__name__)

    def __enter__(self):
        assert self._connectivity_monitor is None
        assert self._connectivity_change_thread is None
        self._keep_running = True
        self._connectivity_monitor = hotspot.ConnectivityMonitor(
            self._event_queue, check_interval=self.CONNECTIVITY_CHECK_INTERVAL)
        self._connectivity_change_thread = threading.Thread(
            target=self._connectivity_change_loop)
        self._connectivity_change_thread.start()
        self._connectivity_monitor.start()
        self._adsb_im.start()
        return self

    def __exit__(self, *_):
        assert self._connectivity_monitor is not None
        assert self._connectivity_change_thread is not None
        self._keep_running = False
        self._connectivity_monitor.stop()
        self._connectivity_monitor = None
        self._connectivity_change_thread.join(2)
        if self._connectivity_change_thread.is_alive():
            self._logger.error(
                "Connectivity change thread failed to terminate.")
        self._maybe_stop_hotspot_timer()
        self._adsb_im.stop()
        self._maybe_stop_hotspot()
        return False

    def _maybe_stop_hotspot(self):
        if self._hotspot:
            self._hotspot.stop()

    def _connectivity_change_loop(self):
        self._logger.info(
            "Waiting for the connectivity monitor to tell us whether we have "
            "internet access.")
        while self._keep_running:
            try:
                event_type, value = self._event_queue.get(timeout=1)
            except queue.Empty:
                continue
            if event_type == "connectivity_change":
                self._handle_connectivity_change(value)
            elif event_type == "hotspot_timeout":
                self._handle_hotspot_timeout()
            elif event_type == "hotspot_recheck_timeout":
                self._handle_hotspot_recheck_timeout()

    def _handle_connectivity_change(self, has_access):
        if has_access:
            if not self._adsb_im.hotspot_mode:
                self._logger.info(
                    "Connectivity monitor says we have connection, but we're "
                    "already in regular mode.")
                return
            self._logger.info(
                "We have internet access, enabling regular mode.")
            self._enable_regular_mode()
        elif self._hotspot is None:
            self._logger.warning(
                "Connectivity monitor says we don't have connection, but we "
                "don't have a hotspot we could start. Enabling regular mode.")
            self._enable_regular_mode()
        else:
            if self._adsb_im.hotspot_mode:
                self._logger.info(
                    "Connectivity monitor says we don't have connection, but "
                    "we're already in hotspot mode.")
                return
            self._logger.info(
                "We don't have internet access, enabling hotspot mode.")
            self._enable_hotspot_mode()

    def _handle_hotspot_timeout(self):
        self._logger.info(
            "Hotspot has been active for a while without success. Shutting it "
            "down to see if connectivity has returned.")
        self._enable_regular_mode(hotspot_recheck=True)

    def _handle_hotspot_recheck_timeout(self):
        assert self._hotspot is not None
        self._maybe_stop_hotspot_timer()
        if self._connectivity_monitor.current_status:
            self._logger.info(
                "After shutting down the hotspot, connectivity has returned. "
                "Staying in regular mode.")
        else:
            self._logger.info(
                "After shutting down the hotspot, we still don't have "
                "connectivity. Switching back to the hotspot.")
            self._enable_hotspot_mode()

    def _enable_regular_mode(self, *, hotspot_recheck=False):
        self._maybe_stop_hotspot_timer()
        self._adsb_im.hotspot_mode = False
        self._maybe_stop_hotspot()
        if hotspot_recheck:
            # We're starting this to see if we have connectivity again. Switch
            # back to regular mode again after a while if not.
            self._hotspot_timer = threading.Timer(
                self.HOTSPOT_RECHECK_TIMEOUT, self._event_queue.put,
                args=(("hotspot_recheck_timeout", None),))
            self._hotspot_timer.start()

    def _enable_hotspot_mode(self):
        assert self._hotspot is not None
        if self._adsb_im.hotspot_mode:
            return
        self._maybe_stop_hotspot_timer()
        self._adsb_im.hotspot_mode = True
        ssids = self._hotspot.start()
        self._hotspot_app.ssids = ssids
        self._hotspot_timer = threading.Timer(
            self.HOTSPOT_TIMEOUT, self._event_queue.put,
            args=(("hotspot_timeout", None),))
        self._hotspot_timer.start()

    def _maybe_stop_hotspot_timer(self):
        if self._hotspot_timer:
            self._hotspot_timer.cancel()
            self._hotspot_timer.join()
            self._hotspot_timer = None

    def _on_wifi_credentials(self, ssid, password):
        if not self._hotspot:
            self._logger.warning(
                "Got wifi credentials to try, but we don't even have a "
                "hotspot.")
            return
        if not self._hotspot.active:
            self._logger.warning(
                "Got wifi credentials, but the hotspot isn't active. Where "
                "did they come from?")
        try:
            self._hotspot.start_wifi_test(ssid, password)
        except:
            self._logger.exception(
                "Unable to start a wifi test with the new credentials.")

    def _on_wifi_test_status(self, success):
        if not self._hotspot:
            self._logger.warning(
                "Got a wifi test status, but no hotspot exists. Where did "
                "that come from?")
        self._maybe_stop_hotspot_timer()
        self._hotspot_app.on_wifi_test_status(success)
        if success:
            self._enable_regular_mode(hotspot_recheck=True)
            if self._hotspot and self._hotspot.active:
                self._logger.error(
                    "The hotspot reports a successful wifi connection, but is "
                    "still active. It should have shut itself off.")
        else:
            if self._hotspot and not self._hotspot.active:
                self._logger.error(
                    "The hotspot reports an unsuccessful wifi connection "
                    "attempt, but is not active. It should have stayed on.")
            self._hotspot_timer = threading.Timer(
                self.HOTSPOT_TIMEOUT, self._event_queue.put,
                args=(("hotspot_timeout", None),))
            self._hotspot_timer.start()


def main():
    with system.System() as sys_:
        conf = config.ensure_config_exists()
        aggregators.init_aggregators(conf, sys_)
        conf.write_env_file()
        if "--update-config" in sys.argv:
            # Just get AdsbIm to do some housekeeping and exit.
            AdsbIm(conf, sys_, None).update_config()
            sys.exit(0)
        _run_app(conf, sys_)


def _run_app(conf, sys_):
    shutdown_event = threading.Event()

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, setting shutdown event.")
        shutdown_event.set()
        signal.signal(sig, signal.SIG_DFL)  # Restore default handler

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    with PidFile(), Manager(conf, sys_):
        shutdown_event.wait()
    logger.info("Shut down.")


if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    main()
