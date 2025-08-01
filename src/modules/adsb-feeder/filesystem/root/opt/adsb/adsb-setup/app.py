import concurrent.futures
import filecmp
import json
import logging
import logging.config
import os
import os.path
import pathlib
import platform
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
from uuid import uuid4
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
import utils.aggregators
from utils.config import (
    config_lock,
    read_values_from_env_file,
    write_values_to_config_json,
    write_values_to_env_file,
)
import utils.data
from utils.environment import Env
from utils.flask import RouteManager, check_restart_lock
import utils.gitlab as gitlab
import utils.netconfig
from utils.sdr import SDRDevices
import utils.stats
import utils.system
import utils.util
from utils.util import (
    cleanup_str,
    create_fake_info,
    is_true,
    make_int,
    print_err,
    run_shell_captured,
    string2file,
    verbose,
)
from utils.wifi import make_wifi

logger = None


def setup_logging():
    logging.setLoggerClass(utils.util.FlashingLogger)
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


def only_alphanum_dash(name):
    new_name = "".join(c for c in name if c.isalnum() or c == "-")
    new_name = new_name.strip("-")[:63]
    return new_name

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
    def __init__(self, data: utils.data.Data, on_wifi_credentials):
        self._d = data
        self._on_wifi_credentials = on_wifi_credentials
        self.ssids = []
        self._restart_state = "done"
        self._message = ""

    def handle_request(self, request):
        if request.path == "/healthz" and request.method in ["OPTIONS", "GET"]:
            return self.healthz()
        elif request.path == "/hotspot" and request.method in ["GET"]:
            return self.hotspot()
        elif request.path == "/restarting":
            return self.restarting()
        elif request.path == "/restart" and request.method in ["POST", "GET"]:
            return self.restart()
        else:
            return self.catch_all()

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

    def restart(self):
        return self._restart_state

    def hotspot(self):
        return flask.render_template(
            "hotspot.html", version=self._d.env_by_tags("base_version").value,
            comment=self._message, ssids=self.ssids,
            mdns_enabled=self._d.is_enabled("mdns"))

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
    def __init__(self, data: utils.data.Data, hotspot_app):
        self._logger = logging.getLogger(type(self).__name__)
        print_err("starting AdsbIm.__init__", level=4)
        self._d = data
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
            def get_value(tags):
                e = self._d.env_by_tags(tags)
                return e.value if e else ""

            def list_value_by_tags(tags, idx):
                e = self._d.env_by_tags(tags)
                return e.list_get(idx) if e else ""

            return {
                "is_enabled": lambda tag: self._d.is_enabled(tag),
                "list_is_enabled": lambda tag, idx: self._d.list_is_enabled(tag, idx=idx),
                "env_value_by_tag": lambda tag: get_value([tag]),  # single tag
                "env_value_by_tags": lambda tags: get_value(tags),  # list of tags
                "list_value_by_tag": lambda tag, idx: list_value_by_tags([tag], idx),
                "list_value_by_tags": lambda tags: list_value_by_tags(tags, 0),
                "url_for": url_for_with_empty_parameters,
                "is_reception_enabled": self.is_reception_enabled,
            }

        self._routemanager = RouteManager(self.app)
        self._system = utils.system.System(data=self._d)
        self._reception_monitor = utils.stats.ReceptionMonitor(self._d)
        # let's only instantiate the Wifi class if we are on WiFi
        self.wifi = None
        self.wifi_ssid = ""

        self._sdrdevices = SDRDevices()
        self._ultrafeeder_config = utils.netconfig.UltrafeederConfig(
            data=self._d)

        self.last_dns_check = 0
        self.undervoltage_epoch = 0

        self._dmesg_monitor = DmesgMonitor(
            on_usb_change=self._sdrdevices._ensure_populated,
            on_undervoltage=self._set_undervoltage)

        self._current_site_name = None
        self._next_url_from_director = ""

        self.lastSetGainWrite = 0

        # no one should share a CPU serial with AirNav, so always create fake cpuinfo;
        # also identify if we would use the thermal hack for RB and Ultrafeeder
        if create_fake_info([0]):
            self._d.env_by_tags("rbthermalhack").value = "/sys/class/thermal"
        else:
            self._d.env_by_tags("rbthermalhack").value = ""

        # Ensure secure_image is set the new way if before the update it was set only as env variable
        if self._d.is_enabled("secure_image"):
            self.set_secure_image()

        self._routemanager.add_proxy_routes(self._d.proxy_routes)
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
            methods=["GET", "POST"],
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
            "/api/ip_info",
            "ip_info",
            self._decide_route_hotspot_mode(self.ip_info),
        )
        self.app.add_url_rule(
            "/api/sdr_info",
            "sdr_info",
            self._decide_route_hotspot_mode(self.sdr_info),
        )
        self.app.add_url_rule(
            "/api/stats",
            "stats",
            self._decide_route_hotspot_mode(self.stats),
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
            "/feeder-update",
            "feeder-update",
            self._decide_route_hotspot_mode(self.feeder_update),
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
        self.update_boardname()
        self.update_version()
        self.update_meminfo()
        self.update_journal_state()

        # now all the envs are loaded and reconciled with the data on file - which means we should
        # actually write out the potentially updated values (e.g. when plain values were converted
        # to lists)
        with config_lock:
            write_values_to_config_json(self._d.env_values, reason="Startup")

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
            if request.path == "/overview":
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
        self._d.env_by_tags("under_voltage").value = True
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
        if not self._current_site_name:
            return ""
        return only_alphanum_dash(self._current_site_name)

    def is_reception_enabled(self, reception_type):
        if reception_type == "ais":
            return bool(self._d.env_by_tags("aisserial").value)
        elif reception_type == "adsb":
            return bool(
                self._d.env_by_tags("1090serial").value
                or self._d.env_by_tags("978serial").value)
        else:
            raise ValueError(f"Unknown reception type {reception_type}.")

    def _all_aggregators(self) -> dict[str, utils.aggregators.Aggregator]:
        return utils.aggregators.all_aggregators(self._d, self._system)

    def start(self):
        if self._server:
            raise RuntimeError("already started")
        assert self._server_thread is None
        self.update_config()

        # if using gpsd, try to update the location
        if self._d.is_enabled("use_gpsd"):
            self.get_lat_lon_alt()

        every_minute_task = utils.util.RepeatingTask(60, self.every_minute)
        every_minute_task.start(execute_now=True)
        self._background_tasks["every_minute"] = every_minute_task

        # reset undervoltage indicator
        self._d.env_by_tags("under_voltage").value = False

        self._dmesg_monitor.start()
        self._reception_monitor.start()

        self._server = werkzeug.serving.make_server(
            host="0.0.0.0", port=int(self._d.env_by_tags("webport").value),
            app=self.app, threaded=True)
        self._server_thread = threading.Thread(
            target=self._server.serve_forever, name="AdsbIm")
        self._server_thread.start()

    def update_config(self):
        # hopefully very temporary hack to deal with a broken container that
        # doesn't run on Raspberry Pi 5 boards
        board = self._d.env_by_tags("board_name").value
        if board.startswith("Raspberry Pi 5"):
            self._d.env_by_tags(["container", "planefinder"]).value = (
                "ghcr.io/sdr-enthusiasts/docker-planefinder:5.0.161_arm64"
            )

        self.handle_implied_settings()
        self.write_envfile()

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

    def update_boardname(self):
        board = ""
        if pathlib.Path("/sys/firmware/devicetree/base/model").exists():
            # that's some kind of SBC most likely
            with open("/sys/firmware/devicetree/base/model", "r") as model:
                board = cleanup_str(model.read().strip())
        else:
            # are we virtualized?
            try:
                output = subprocess.run(
                    "systemd-detect-virt",
                    timeout=2.0,
                    shell=True,
                    capture_output=True,
                )
            except subprocess.SubprocessError:
                pass  # whatever
            else:
                virt = output.stdout.decode().strip()
                if virt and virt != "none":
                    board = f"Virtualized {platform.machine()} environment under {virt}"
                else:
                    prod = ""
                    manufacturer = ""
                    try:
                        prod = subprocess.run(
                            "dmidecode -s system-product-name",
                            shell=True,
                            capture_output=True,
                            text=True,
                        )
                        manufacturer = subprocess.run(
                            "dmidecode -s system-manufacturer",
                            shell=True,
                            capture_output=True,
                            text=True,
                        )
                    except:
                        pass
                    if prod or manufacturer:
                        board = f"Native on {manufacturer.stdout.strip()} {prod.stdout.strip()} {platform.machine()} system"
                    else:
                        board = f"Native on {platform.machine()} system"
        if board == "":
            board = f"Unknown {platform.machine()} system"
        if board == "Firefly roc-rk3328-cc":
            board = f"Libre Computer Renegade ({board})"
        elif board == "Libre Computer AML-S905X-CC":
            board = "Libre Computer Le Potato (AML-S905X-CC)"
        self._d.env_by_tags("board_name").value = board

    def update_version(self):
        self._d.env_by_tags("base_version").value = self._d.read_version()

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

    def check_secure_image(self):
        return utils.data.SECURE_IMAGE_FILE.exists()

    def set_secure_image(self):
        # set legacy env variable as well for webinterface
        self._d.env_by_tags("secure_image").value = True
        if not self.check_secure_image():
            utils.data.SECURE_IMAGE_FILE.touch(exist_ok=True)
            print_err("secure_image has been set")

    def update_dns_state(self):
        def update_dns():
            dns_state = self._system.check_dns()
            self._d.env_by_tags("dns_state").value = dns_state
            if not dns_state:
                print_err("ERROR: we appear to have lost DNS")

        self.last_dns_check = time.time()
        self._executor.submit(update_dns)

    def write_envfile(self):
        write_values_to_env_file(self._d.envs_for_envfile)

    def _setup_ultrafeeder_args(self):
        self._d.env_by_tags("ultrafeeder_config").list_set(
            0, self._ultrafeeder_config.generate())

    def set_hostname_and_enable_mdns(self, site_name: str):
        self._current_site_name = site_name
        if self.hostname:
            subprocess.run(["/usr/bin/hostnamectl", "hostname", self.hostname])

    def _maybe_enable_mdns(self):
        if not self._d.is_enabled("mdns"):
            return
        args = ["/bin/bash", "/opt/adsb/scripts/mdns-alias-setup.sh"]
        if self.hostname:
            # If we have a hostname, make the mDNS script create an alias for
            # it as well.
            args.append(self.hostname)
        subprocess.run(args)

    def set_tz(self, timezone):
        # timezones don't have spaces, only underscores
        # replace spaces with underscores to correct this common error
        timezone = timezone.replace(" ", "_")

        success = self.set_system_tz(timezone)
        if success:
            self._d.env("FEEDER_TZ").list_set(0, timezone)
        else:
            self._logger.warning(
                f"Timezone {timezone} probably invalid, defaulting to UTC.",
                flash_message=True)
            self._d.env("FEEDER_TZ").list_set(0, "UTC")
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
        adsb_path = utils.data.CONFIG_DIR

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

        site_name = self._d.env_by_tags("site_name_sanitized").list_get(0)
        now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
        download_name = f"adsb-feeder-config-{site_name}-{now}.backup"
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
                restore_path = utils.data.CONFIG_DIR / "restore"
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
        # the user has uploaded a zip file and we need to take a look.
        # be very careful with the content of this zip file...
        print_err("zip file uploaded, looking at the content")
        filename = request.args["zipfile"]
        restore_path = utils.data.CONFIG_DIR / "restore"
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
            elif os.path.isfile(utils.data.CONFIG_DIR / name):
                if filecmp.cmp(
                    utils.data.CONFIG_DIR / name,
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
        # they have selected the files to restore
        print_err("restoring the files the user selected")
        (utils.data.CONFIG_DIR / "ultrafeeder").mkdir(
            mode=0o755, exist_ok=True)
        restore_path = utils.data.CONFIG_DIR / "restore"
        restore_path.mkdir(mode=0o755, exist_ok=True)
        try:
            subprocess.call("/opt/adsb/docker-compose-adsb down -t 20", timeout=40.0, shell=True)
        except subprocess.TimeoutExpired:
            print_err("timeout expired stopping docker... trying to continue...")
        for name, value in form.items():
            if value == "1":
                print_err(f"restoring {name}")
                dest = utils.data.CONFIG_DIR / name
                if dest.is_file():
                    shutil.move(dest, utils.data.CONFIG_DIR / (name + ".dist"))
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
        restore_path = utils.data.CONFIG_DIR / "restore"
        shutil.rmtree(restore_path, ignore_errors=True)

        # now that everything has been moved into place we need to read all the values from config.json
        # of course we do not want to pull values marked as norestore
        print_err("finished restoring files, syncing the configuration")

        for e in self._d._env:
            e._reconcile(e._value, pull=("norestore" not in e.tags))
            print_err(f"{'wrote out' if 'norestore' in e.tags else 'read in'} {e.name}: {e.value}")

        # finally make sure that a couple of the key settings are up to date
        self.update_boardname()
        self.update_version()

        self.set_tz(self._d.env("FEEDER_TZ").list_get(0))

        # make sure we are connected to the right Zerotier network
        zt_network = self._d.env_by_tags("zerotierid").value
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
        self.write_envfile()

        try:
            subprocess.call("/opt/adsb/docker-compose-start", timeout=180.0, shell=True)
        except subprocess.TimeoutExpired:
            self._logger.exception(
                "Timeout expired re-starting docker... trying to continue...",
                flash_message=True)

    def base_is_configured(self):
        base_config: set[Env] = {env for env in self._d._env if env.is_mandatory}
        for env in base_config:
            if env._value == None or (type(env._value) == list and not env.list_get(0)):
                print_err(f"base_is_configured: {env} isn't set up yet")
                return False
        return True

    def at_least_one_aggregator(self) -> bool:
        return any(agg.enabled() for agg in self._all_aggregators().values())

    def ip_info(self):
        ip, status = self._system.check_ip()
        if status == 200:
            self._d.env_by_tags(["feeder_ip"]).value = ip
            self._d.env_by_tags(["mf_ip"]).list_set(0, ip)
        jsonString = json.dumps(
            {
                "feeder_ip": ip,
            },
            indent=2,
        )
        return Response(jsonString, mimetype="application/json")

    def sdr_info(self):
        # get our guess for the right SDR to frequency mapping
        # and then update with the actual settings
        serial_guess: Dict[str, str] = self._sdrdevices.addresses_per_frequency
        print_err(f"serial guess: {serial_guess}")
        serials: Dict[str, str] = {f: self._d.env_by_tags(f"{f}serial").value for f in [978, 1090, "ais"]}
        configured_serials = {self._d.env_by_tags(f).value for f in self._sdrdevices.purposes()}
        available_serials = [sdr._serial for sdr in self._sdrdevices.sdrs]
        for f in [978, 1090, "ais"]:
            if (not serials[f] or serials[f] not in available_serials) and serial_guess[f] not in configured_serials:
                serials[f] = serial_guess[f]

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
        lat = self._d.env_by_tags("lat").list_get(0)
        lon = self._d.env_by_tags("lon").list_get(0)
        alt = self._d.env_by_tags("alt").list_get(0)
        gps_json = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/gpsd.json")
        if self._d.is_enabled("use_gpsd") and gps_json.exists():
            with gps_json.open() as f:
                gps = json.load(f)
                if "lat" in gps and "lon" in gps:
                    lat = gps["lat"]
                    lon = gps["lon"]
                    # normalize to no more than 5 digits after the decimal point for lat/lon
                    lat = f"{float(lat):.5f}"
                    lon = f"{float(lon):.5f}"
                    self._d.env_by_tags("lat").list_set(0, lat)
                    self._d.env_by_tags("lon").list_set(0, lon)
                if "alt" in gps:
                    alt = gps["alt"]
                    # normalize to whole meters for alt
                    alt = f"{float(alt):.0f}"
                    self._d.env_by_tags("alt").list_set(0, alt)
        return lat, lon, alt

    def stats(self):
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
            self, enabled: bool, current_stats: utils.stats.CurrentCraftStats,
            history: list[utils.stats.TimeFrameStats]):
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
            aggregator = self._all_aggregators()[agg_key]
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

    def unique_site_name(self, name, idx=-1):
        # make sure that a site name is unique - if the idx is given that's
        # the current value and excluded from the check
        existing_names = self._d.env_by_tags("site_name")
        names = [existing_names.list_get(n) for n in range(0, len(existing_names.value)) if n != idx]
        while name in names:
            name += "_"
        return name

    def import_graphs_and_history_from_remote(self, ip, port):
        print_err(f"importing graphs and history from {ip}")
        # first make sure that there isn't any old data that needs to be moved
        # out of the way
        if pathlib.Path(utils.data.CONFIG_DIR / "ultrafeeder" / ip).exists():
            now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
            shutil.move(
                utils.data.CONFIG_DIR / "ultrafeeder" / ip,
                utils.data.CONFIG_DIR / "ultrafeeder" / f"{ip}-{now}",
            )

        url = f"http://{ip}:{port}/backupexecutefull"
        # make tmpfile
        os.makedirs(utils.data.CONFIG_DIR / "ultrafeeder", exist_ok=True)
        fd, tmpfile = tempfile.mkstemp(
            dir=utils.data.CONFIG_DIR / "ultrafeeder")
        os.close(fd)

        # stream writing to a file with requests library is a pain so just use curl
        try:
            subprocess.run(
                ["curl", "-o", f"{tmpfile}", f"{url}"],
                check=True,
            )

            with zipfile.ZipFile(tmpfile) as zf:
                zf.extractall(path=utils.data.CONFIG_DIR / "ultrafeeder" / ip)
            # deal with the duplicate "ultrafeeder in the path"
            shutil.move(
                utils.data.CONFIG_DIR / "ultrafeeder" / ip / "ultrafeeder" / "globe_history",
                utils.data.CONFIG_DIR / "ultrafeeder" / ip / "globe_history",
            )
            shutil.move(
                utils.data.CONFIG_DIR / "ultrafeeder" / ip / "ultrafeeder" / "graphs1090",
                utils.data.CONFIG_DIR / "ultrafeeder" / ip / "graphs1090",
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
            utils.data.CONFIG_DIR / "ultrafeeder/globe_history/autogain")
        setGainPath = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/setGain")
        try:
            gaindir.mkdir(exist_ok=True, parents=True)
        except:
            pass
        gain = self._d.env_by_tags(["gain"]).value

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

    def setup_or_disable_uat(self, sitenum):
        if sitenum and self._d.list_is_enabled(["uat978"], sitenum):
            # always get UAT from the readsb uat_replay
            self._d.env_by_tags("replay978").list_set(sitenum, "--net-uat-replay-port 30978")
            self._d.env_by_tags("978host").list_set(sitenum, f"uf_{sitenum}")
            self._d.env_by_tags("rb978host").list_set(sitenum, self._d.env_by_tags("mf_ip").list_get(sitenum))
            self._d.env_by_tags("978piaware").list_set(sitenum, "relay")
        else:
            self._d.env_by_tags("replay978").list_set(sitenum, "")
            self._d.env_by_tags("978host").list_set(sitenum, "")
            self._d.env_by_tags("rb978host").list_set(sitenum, "")
            self._d.env_by_tags("978piaware").list_set(sitenum, "")

    def handle_implied_settings(self):
        ac_db = True
        self._d.env_by_tags(["mlathub_disable"]).value = False

        if self._memtotal < 900000:
            ac_db = False
            # save 100 MB of memory for low memory setups

        self._d.env_by_tags(["tar1090_ac_db"]).value = ac_db

        # make sure the avahi alias service runs on an adsb.im image
        self.set_hostname_and_enable_mdns(self._d.env_by_tags("site_name").list_get(0))

        self._d.env_by_tags("stage2_nano").value = False
        self._d.env_by_tags("nano_beast_port").value = "30005"
        self._d.env_by_tags("nano_beastreduce_port").value = "30006"

        site_name = self._d.env_by_tags("site_name").list_get(0)
        sanitized = "".join(c if c.isalnum() or c in "-_." else "_" for c in site_name)
        self._d.env_by_tags("site_name_sanitized").list_set(0, sanitized)

        # fixup altitude mishaps by stripping the value
        # strip meter units and whitespace for good measure
        alt = self._d.env_by_tags("alt").list_get(0)
        alt_m = alt.strip().strip("m").strip()
        self._d.env_by_tags("alt").list_set(0, alt_m)

        # make sure use_route_api is populated with the default:
        self._d.env_by_tags("route_api").list_get(0)

        # make sure the uuids are populated:
        if not self._d.env_by_tags("adsblol_uuid").list_get(0):
            self._d.env_by_tags("adsblol_uuid").list_set(0, str(uuid4()))
        if not self._d.env_by_tags("ultrafeeder_uuid").list_get(0):
            self._d.env_by_tags("ultrafeeder_uuid").list_set(0, str(uuid4()))

        for agg in self._all_aggregators().values():
            if (agg.enabled() and agg.needs_key and self._d.env_by_tags([
                    agg.agg_key, "key"]).list_get(0) == ""):
                self._logger.warning(f"Empty key, disabling {agg}.")
                self._d.env_by_tags([agg.agg_key,
                                     "is_enabled"]).list_set(0, False)

        # explicitely enable mlathub unless disabled
        self._d.env_by_tags(["mlathub_enable"]).value = not self._d.env_by_tags(["mlathub_disable"]).value

        self._d.env_by_tags("beast-reduce-optimize-for-mlat").value = False

        if self._d.env_by_tags("tar1090_image_config_link").value != "":
            self._d.env_by_tags("tar1090_image_config_link").value = (
                f"http://HOSTNAME:{self._d.env_by_tags('webport').value}/"
            )

        self._d.env_by_tags("tar1090portadjusted").value = self._d.env_by_tags("tar1090port").value
        self._d.env_by_tags("nanotar1090portadjusted").value = self._d.env_by_tags("tar1090port").value

        # for regular feeders or micro feeders a max range of 300nm seem reasonable
        self._d.env_by_tags("max_range").list_set(0, 300)

        # fix up airspy installs without proper serial number configuration
        if self._d.is_enabled("airspy"):
            if self._d.env_by_tags("1090serial").value == "" or self._d.env_by_tags("1090serial").value.startswith("AIRSPY SN:"):
                self._sdrdevices._ensure_populated()
                airspy_serials = [sdr._serial for sdr in self._sdrdevices.sdrs if sdr._type == "airspy"]
                if len(airspy_serials) == 1:
                    self._d.env_by_tags("1090serial").value = airspy_serials[0]

        # make all the smart choices for plugged in SDRs
        # only run this for initial setup or when the SDR setup is requested via the interface
        if not self._d.env_by_tags("sdrs_locked").value:
            # first grab the SDRs plugged in and check if we have one identified for UAT
            self._sdrdevices._ensure_populated()
            env978 = self._d.env_by_tags("978serial")
            env1090 = self._d.env_by_tags("1090serial")
            envais = self._d.env_by_tags("aisserial")
            if env978.value != "" and not any([sdr._serial == env978.value for sdr in self._sdrdevices.sdrs]):
                env978.value = ""
            if env1090.value != "" and not any([sdr._serial == env1090.value for sdr in self._sdrdevices.sdrs]):
                env1090.value = ""
            if envais.value != "" and not any([sdr._serial == envais.value for sdr in self._sdrdevices.sdrs]):
                envais.value = ""
            auto_assignment = self._sdrdevices.addresses_per_frequency

            purposes = self._sdrdevices.purposes()

            # if we have an actual asignment, that overrides the auto-assignment,
            # delete the auto-assignment
            for frequency in [978, 1090, "ais"]:
                if any(auto_assignment[frequency] == self._d.env_by_tags(purpose).value for purpose in purposes):
                    auto_assignment[frequency] = ""
            if not env1090.value and auto_assignment[1090]:
                env1090.value = auto_assignment[1090]
            if not env978.value and auto_assignment[978]:
                env978.value = auto_assignment[978]
            if not envais.value and auto_assignment["ais"]:
                envais.value = auto_assignment["ais"]

            stratuxv3 = any(
                [sdr._serial == env978.value and sdr._type == "stratuxv3" for sdr in self._sdrdevices.sdrs]
            )
            if stratuxv3:
                self._d.env_by_tags("uat_device_type").value = "stratuxv3"
            else:
                self._d.env_by_tags("uat_device_type").value = "rtlsdr"

            # handle 978 settings for stage1
            if env978.value:
                self._d.env_by_tags(["uat978", "is_enabled"]).list_set(0, True)
                self._d.env_by_tags("978url").list_set(0, "http://dump978/skyaware978")
                self._d.env_by_tags("978host").list_set(0, "dump978")
                self._d.env_by_tags("978piaware").list_set(0, "relay")
            else:
                self._d.env_by_tags(["uat978", "is_enabled"]).list_set(0, False)
                self._d.env_by_tags("978url").list_set(0, "")
                self._d.env_by_tags("978host").list_set(0, "")
                self._d.env_by_tags("978piaware").list_set(0, "")

            # next check for airspy devices
            airspy = any([sdr._serial == env1090.value and sdr._type == "airspy" for sdr in self._sdrdevices.sdrs])
            self._d.env_by_tags(["airspy", "is_enabled"]).value = airspy
            self._d.env_by_tags("airspyurl").list_set(0, f"http://airspy_adsb" if airspy else "")
            # SDRplay devices
            sdrplay = any([sdr._serial == env1090.value and sdr._type == "sdrplay" for sdr in self._sdrdevices.sdrs])
            self._d.env_by_tags(["sdrplay", "is_enabled"]).value = sdrplay
            # Mode-S Beast
            modesbeast = any(
                [sdr._serial == env1090.value and sdr._type == "modesbeast" for sdr in self._sdrdevices.sdrs]
            )

            # rtl-sdr
            rtlsdr = any(sdr._type == "rtlsdr" and sdr._serial in {env1090.value, envais.value} for sdr in self._sdrdevices.sdrs)

            if rtlsdr:
                self._d.env_by_tags("readsb_device_type").value = "rtlsdr"
            elif modesbeast:
                self._d.env_by_tags("readsb_device_type").value = "modesbeast"
            else:
                self._d.env_by_tags("readsb_device_type").value = ""

            if rtlsdr:
                # set rtl-sdr 1090 gain, bit hacky but means we don't have to restart the bulky ultrafeeder for gain changes
                self.setRtlGain()

            if airspy:
                # make sure airspy gain is within bounds
                gain = self._d.env_by_tags(["gain"]).value
                if gain.startswith("auto"):
                    self._d.env_by_tags(["gain_airspy"]).value = "auto"
                elif make_int(gain) > 21:
                    self._d.env_by_tags(["gain_airspy"]).value = "21"
                    self._d.env_by_tags(["gain"]).value = "21"
                elif make_int(gain) < 0:
                    self._d.env_by_tags(["gain_airspy"]).value = "0"
                    self._d.env_by_tags(["gain"]).value = "0"
                else:
                    self._d.env_by_tags(["gain_airspy"]).value = gain

            if verbose & 1:
                print_err(f"in the end we have")
                print_err(f"1090serial {env1090.value}")
                print_err(f"978serial {env978.value}")
                print_err(f"aisserial {envais.value}")
                print_err(f"airspy container is {self._d.is_enabled(['airspy'])}")
                print_err(f"SDRplay container is {self._d.is_enabled(['sdrplay'])}")
                print_err(f"dump978 container {self._d.list_is_enabled(['uat978'], 0)}")

            # if the base config is completed, lock down further SDR changes so they only happen on
            # user request
            if self.base_is_configured():
                self._d.env_by_tags("sdrs_locked").value = True

        # set all of the ultrafeeder config data up
        self._setup_ultrafeeder_args()

        # finally, check if this has given us enough configuration info to
        # start the containers
        if self.base_is_configured():
            self._d.env_by_tags(["base_config", "is_enabled"]).value = True
            if self.at_least_one_aggregator():
                self._d.env_by_tags("aggregators_chosen").value = True

            if not self._d.env_by_tags("journal_configured").value:
                try:
                    cmd = "/opt/adsb/scripts/journal-set-volatile.sh"
                    print_err(cmd)
                    subprocess.run(cmd, shell=True, timeout=5.0)
                    self.update_journal_state()
                    self._d.env_by_tags("journal_configured").value = True
                except:
                    pass

    def set_docker_concurrent(self, value):
        self._d.env_by_tags("docker_concurrent").value = value
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
        allow_insecure = not self.check_secure_image()
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
                    self._d.env_by_tags("sdrplay_license_accepted").value = True
                if key == "sdrplay_license_reject":
                    self._d.env_by_tags("sdrplay_license_accepted").value = False
                if key == "aggregators":
                    # user has clicked Submit on Aggregator page
                    self._d.env_by_tags("aggregators_chosen").value = True
                    # set this to individual so if people have set "all" before can still deselect individual aggregators
                    self._d.env_by_tags("aggregator_choice").value = "individual"

                if key == "sdr_setup" and value == "go":
                    self._d.env_by_tags("sdrs_locked").value = False

                if allow_insecure and key == "shutdown":
                    # schedule shutdown in 0.5 seconds
                    self._system.shutdown(delay=0.5)
                    self.exiting = True
                    return redirect(url_for("shutdownpage"))
                if allow_insecure and key == "reboot":
                    # schedule reboot in 0.5 seconds
                    self._system.reboot(delay=0.5)
                    self.exiting = True
                    return redirect(url_for("restarting"))
                if key == "restart_containers" or key == "recreate_containers":
                    containers = self._system.list_containers()
                    containers_to_restart = []
                    for container in containers:
                        # only restart the ones that have been checked
                        user_selection = form.get(f"restart-{container}", "0")
                        if user_selection == "1":
                            containers_to_restart.append(container)
                    self.write_envfile()
                    if key == "restart_containers":
                        self._system.restart_containers(containers_to_restart)
                    else:
                        self._system.recreate_containers(containers_to_restart)
                    self._next_url_from_director = request.url
                    return render_template("/restarting.html")
                if key == "log_persistence_toggle":
                    if self._persistent_journal:
                        cmd = "/opt/adsb/scripts/journal-set-volatile.sh"
                    else:
                        cmd = "/opt/adsb/scripts/journal-set-persist.sh"
                    try:
                        print_err(cmd)
                        subprocess.run(cmd, shell=True, timeout=5.0)
                        self.update_journal_state()
                    except:
                        pass
                    self._next_url_from_director = request.url
                if key == "secure_image":
                    self.set_secure_image()
                if key == "no_config_link":
                    self._d.env_by_tags("tar1090_image_config_link").value = ""
                if key == "allow_config_link":
                    self._d.env_by_tags("tar1090_image_config_link").value = f"WILL_BE_SET_IN_IMPLIED_SETTINGS"
                if key == "turn_on_gpsd":
                    self._d.env_by_tags(["use_gpsd", "is_enabled"]).value = True
                    # this updates the lat/lon/alt env variables as side effect, if there is a GPS fix
                    self.get_lat_lon_alt()
                if key == "turn_off_gpsd":
                    self._d.env_by_tags(["use_gpsd", "is_enabled"]).value = False
                if key in ["enable_parallel_docker", "disable_parallel_docker"]:
                    self.set_docker_concurrent(key == "enable_parallel_docker")
                if key == "nightly_update" or key == "zerotier":
                    # this will be handled through the separate key/value pairs
                    pass
                if key == "os_update":
                    self._system._restart.bg_run(func=self._system.os_update)
                    self._next_url_from_director = request.url
                    return render_template("/restarting.html")
                if allow_insecure and key == "tailscale_disable_go" and form.get("tailscale_disable") == "disable":
                    success, output = run_shell_captured(
                        "systemctl disable --now tailscaled && systemctl mask tailscaled", timeout=30
                    )
                    continue
                if allow_insecure and key == "zerotier" and form.get("zerotier_disable") == "disable":
                    self._d.env_by_tags("zerotierid").value = ""
                    success, output = run_shell_captured(
                        "systemctl disable --now zerotier-one && systemctl mask zerotier-one", timeout=30
                    )
                    continue
                if allow_insecure and key == "tailscale":
                    # grab extra arguments if given
                    ts_args = form.get("tailscale_extras", "")
                    if ts_args:
                        # right now we really only want to allow the login server arg
                        try:
                            ts_cli_switch, ts_cli_value = ts_args.split("=")
                        except:
                            ts_cli_switch, ts_cli_value = ["", ""]

                        if ts_cli_switch != "--login-server":
                            self._logger.warning(
                                "at this point we only allow the "
                                "--login-server=<server> argument; please let "
                                "us know at the Zulip support link why you "
                                f"need this to support {ts_cli_switch}",
                            flash_message=True)
                            continue
                        print_err(f"login server arg is {ts_cli_value}")
                        match = re.match(
                            r"^https?://[-a-zA-Z0-9._\+~=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?::[0-9]{1,5})?(?:[-a-zA-Z0-9()_\+.~/=]*)$",
                            ts_cli_value,
                        )
                        if not match:
                            self._logger.error(
                                "The login server URL didn't make sense "
                                f"{ts_cli_value}", flash_message=True)
                            continue
                    print_err(f"starting tailscale (args='{ts_args}')")
                    try:
                        subprocess.run(
                            ["/usr/bin/systemctl", "unmask", "tailscaled"],
                            timeout=20.0,
                        )
                        subprocess.run(
                            ["/usr/bin/systemctl", "enable", "--now", "tailscaled"],
                            timeout=20.0,
                        )
                        cmd = ["/usr/bin/tailscale", "up"]

                        name = only_alphanum_dash(self._d.env_by_tags("site_name").list_get(0))
                        # due to the following error, we just add --reset to the options
                        # Error: changing settings via 'tailscale up' requires mentioning all
                        # non-default flags. To proceed, either re-run your command with --reset or
                        # use the command below to explicitly mention the current value of
                        # all non-default settings:
                        cmd += ["--reset"]
                        cmd += [f"--hostname={name}"]

                        if ts_args:
                            cmd += [f"--login-server={shlex.quote(ts_cli_value)}"]
                        cmd += ["--accept-dns=false"]
                        print_err(f"running {cmd}")
                        proc = subprocess.Popen(
                            cmd,
                            stderr=subprocess.PIPE,
                            stdout=subprocess.DEVNULL,
                            text=True,
                        )
                        os.set_blocking(proc.stderr.fileno(), False)
                    except:
                        # this really needs a user visible error...
                        self._logger.exception(
                            "Exception trying to set up tailscale - giving up",
                            flash_message=True)
                        continue
                    else:
                        startTime = time.time()
                        match = None
                        while time.time() - startTime < 30:
                            output = proc.stderr.readline()
                            if not output:
                                if proc.poll() != None:
                                    break
                                time.sleep(0.1)
                                continue
                            print_err(output.rstrip("\n"))
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
                        print_err(f"found login link {login_link}")
                        self._d.env_by_tags("tailscale_ll").value = login_link
                    else:
                        self._logger.error(
                            "ERROR: tailscale didn't provide a login link "
                            "within 30 seconds", flash_message=True)
                    return redirect(url_for("systemmgmt"))
                # tailscale handling uses 'continue' to avoid deep nesting - don't add other keys
                # here at the end - instead insert them before tailscale
                continue
            if value == "stay" or value.startswith("stay-"):
                if allow_insecure and key == "rpw":
                    print_err("updating the root password")
                    self.set_rpw()
                    continue
                if key == "wifi":
                    print_err("updating the wifi settings")
                    ssid = form.get("wifi_ssid")
                    password = form.get("wifi_password")

                    def connect_wifi():
                        if self.wifi is None:
                            self.wifi = make_wifi()
                        status = self.wifi.wifi_connect(ssid, password)
                        print_err(f"wifi_connect returned {status}")
                        self.update_net_dev()

                    self._system._restart.bg_run(func=connect_wifi)
                    self._next_url_from_director = url_for("systemmgmt")
                    # FIXME: let user know
            # now handle other form input
            if key == "clear_range" and value == "1":
                self.clear_range_outline()
                continue
            if key == "resetgain" and value == "1":
                # tell the ultrafeeder container to restart the autogain processing
                cmdline = "docker exec ultrafeeder /usr/local/bin/autogain1090 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    self._logger.exception(
                        "Error running Ultrafeeder autogain reset",
                        flash_message=True)
                continue
            if key == "resetuatgain" and value == "1":
                # tell the dump978 container to restart the autogain processing
                cmdline = "docker exec dump978 /usr/local/bin/autogain978 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    self._logger.exception(
                        "Error running UAT autogain reset", flash_message=True)
                continue
            if allow_insecure and key == "ssh_pub":
                ssh_dir = pathlib.Path("/root/.ssh")
                ssh_dir.mkdir(mode=0o700, exist_ok=True)
                with open(ssh_dir / "authorized_keys", "a+") as authorized_keys:
                    authorized_keys.write(f"{value}\n")
                self._d.env_by_tags("ssh_configured").value = True
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
                continue
            if key == "enable-prometheus-metrics":
                self._ensure_prometheus_metrics_state(is_true(value))
                continue
            if key == "tz":
                self.set_tz(value)
                continue
            # Form data can directly set config variables if the key, when
            # split by the string "--" is a subset of the config variable's
            # tags (this includes the case where the key is equal to one of the
            # tags). At the time of this writing, the only cases where
            # splitting by "--" is done is for <something>--is_enabled, to
            # enable certain features directly from a template. Other uses
            # exist, but there the key is exactly one of the tags.
            tags = key.split("--")
            env = self._d.env_by_tags(tags)
            if env:
                if allow_insecure and key == "zerotierid":
                    try:
                        utils.system.systemctl().run(
                            ["unmask", "enable --now"], ["zerotier-one"])
                        # Wait for the service to get ready...
                        sleep(5.0)
                        subprocess.call([
                            "/usr/sbin/zerotier-cli", "join", f"{value}"])
                    except:
                        self._logger.exception(
                            "Exception trying to set up zerotier - giving up",
                            flash_message=True)
                elif key in {"lat", "lon"}:
                    # remove letters, spaces, degree symbols
                    value = str(float(re.sub("[a-zA-Z° ]", "", value)))
                elif key == "uatgain" and value in ["", "auto"]:
                    value = "autogain"
                elif key == "gain" and value == "":
                    value = "auto"
                elif key == "site_name":
                    value = self.unique_site_name(value, 0)
                # If user is changing to 'individual' selection (either in
                # initial setup or when coming back to that setting later),
                # show them the aggregator selection page next.
                if (key == "aggregator_choice" and value == "individual"
                        and self._d.env_by_tags("aggregator_choice").value
                        != "individual"):
                    next_url = url_for("aggregators")
                # If this is an assignment of an SDR device to a purpose (i.e.
                # ais, 1090 etc.), make sure that device is only assigned once
                # by clearing all of its other assignments.
                purposes = self._sdrdevices.purposes()
                if key in purposes and value != "":
                    for other_purpose in purposes:
                        if key == other_purpose or value != self._d.env_by_tags(
                                other_purpose).value:
                            continue
                        self._logger.info(
                            f"Device {value} was just assigned to purpose "
                            f"{key}, but still had a previous assignment to "
                            f"{other_purpose}. Clearing the old one so it "
                            "only has one purpose.")
                        self._d.env_by_tags(other_purpose).value = ""
                if type(env._value) == list:
                    env.list_set(0, value)
                else:
                    env.value = value

        # done handling the input data
        # what implied settings do we have (and could we simplify them?)

        self.handle_implied_settings()

        # write all this out to the .env file so that a docker-compose run will find it
        self.write_envfile()

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
        if self._d.is_enabled("base_config"):
            print_err("base config is completed", level=2)
            if self._d.is_enabled("sdrplay") and not self._d.is_enabled("sdrplay_license_accepted"):
                return redirect(url_for("sdrplay_license"))
            return render_template("/restarting.html", extra_args=extra_args)
        print_err("base config not completed", level=2)
        return redirect(url_for("director"))

    def _ensure_prometheus_metrics_state(self, should_be_enabled: bool):
        currently_enabled = self._d.is_enabled("prometheus_exporter")
        if currently_enabled != should_be_enabled:
            self._logger.info(
                f"Toggling Prometheus metrics state from {currently_enabled} "
                f"to {should_be_enabled}.")
        command = "enable" if should_be_enabled else "disable"
        proc, = utils.system.systemctl().run(
            [f"{command} --now"], ["adsb-push-prometheus-metrics.timer"])
        if proc.returncode != 0:
            self._logger.error(
                "Error enabling/disabling Prometheus metrics state: "
                f"{proc.stdout}", flash_message=True)
            return
        self._d.env_by_tags("prometheus_exporter").value = should_be_enabled

    @check_restart_lock
    def expert(self):
        if request.method == "POST":
            return self.update()
        # make sure we only show the gpsd option if gpsd is correctly configured and running
        self._d.env_by_tags("has_gpsd").value = self._system.check_gpsd()
        return render_template("expert.html")

    @check_restart_lock
    def systemmgmt(self):
        if request.method == "POST":
            return self.update()
        tailscale_running = False
        zerotier_running = False
        success, output = run_shell_captured("ps -e", timeout=2)
        zerotier_running = "zerotier-one" in output
        tailscale_running = "tailscaled" in output
        # is tailscale set up?
        try:
            if not tailscale_running:
                raise ProcessLookupError
            result = subprocess.run(
                "tailscale status --json 2>/dev/null",
                shell=True,
                check=True,
                capture_output=True,
            )
        except:
            # a non-zero return value means tailscale isn't configured or tailscale is disabled
            # reset both associated env vars
            # if tailscale recovers / is re-enabled and the system management page is visited,
            # the code below will set the appropriate tailscale_name once more.
            self._d.env_by_tags("tailscale_name").value = ""
            self._d.env_by_tags("tailscale_ll").value = ""
        else:
            ts_status = json.loads(result.stdout.decode())
            if ts_status.get("BackendState") == "Running" and ts_status.get("Self"):
                tailscale_name = ts_status.get("Self").get("HostName")
                print_err(f"configured as {tailscale_name} on tailscale")
                self._d.env_by_tags("tailscale_name").value = tailscale_name
                self._d.env_by_tags("tailscale_ll").value = ""
            else:
                self._d.env_by_tags("tailscale_name").value = ""
        # create a potential new root password in case the user wants to change it
        alphabet = string.ascii_letters + string.digits
        self.rpw = "".join(secrets.choice(alphabet) for i in range(12))
        available_tags = gitlab.gitlab_repo().get_tags()
        return render_template(
            "systemmgmt.html",
            tailscale_running=tailscale_running,
            zerotier_running=zerotier_running,
            rpw=self.rpw,
            tags=available_tags,
            containers=self._system.list_containers(),
            persistent_journal=self._persistent_journal,
            wifi=self.wifi_ssid,
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
            for agg in self._all_aggregators().values()
            if isinstance(agg, utils.aggregators.UltrafeederAggregator)
            and not isinstance(agg, utils.aggregators.AdsbLolAggregator))
        return render_template(
            "aggregators.html",
            aggregators=self._all_aggregators(),
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
        for aggregator in self._all_aggregators().values():
            configure_kwargs = self._make_configure_kwargs(
                aggregator.agg_key, form)
            self._logger.info(f"Configuring {aggregator}.")
            try:
                aggregator.configure(**configure_kwargs)
            except Exception as e:
                message = f"Failed to configure {aggregator.name}."
                if isinstance(e, utils.aggregators.ConfigureError):
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
            "enabled": utils.util.parse_post_bool(
                form.get(f"{agg_key}-is-enabled"))}
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
        return kwargs

    @check_restart_lock
    def director(self):
        # figure out where to go:
        if request.method == "POST":
            return self.update()
        if not self._d.is_enabled("base_config"):
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
        configured_serials = [self._d.env_by_tags(purpose).value for purpose in self._sdrdevices.purposes()]
        configured_serials = [serial for serial in configured_serials if serial != ""]
        available_serials = [sdr._serial for sdr in self._sdrdevices.sdrs]
        if any([serial not in configured_serials for serial in available_serials]):
            print_err(f"configured serials: {configured_serials}")
            print_err(f"available serials: {available_serials}")
            print_err("director redirecting to sdr_setup: unconfigured devices present")
            return flask.redirect("/sdr_setup")

        used_serials = [self._d.env_by_tags(purpose).value for purpose in ["978serial","1090serial","aisserial"]]
        used_serials = [serial for serial in used_serials if serial != ""]
        if any([serial not in available_serials for serial in used_serials]):
            print_err(f"used serials: {used_serials}")
            print_err(f"available serials: {available_serials}")
            print_err("director redirecting to sdr_setup: at least one used device is not present")
            return flask.redirect("/sdr_setup")

        # if the user chose to individually pick aggregators but hasn't done so,
        # they need to go to the aggregator page
        if self.at_least_one_aggregator() or self._d.env_by_tags("aggregators_chosen"):
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

        self._sdrdevices._ensure_populated()

        self.update_net_dev()

        if self._d.env_by_tags("tailscale_name").value:
            try:
                result = subprocess.run(
                    "tailscale ip -4 2>/dev/null",
                    shell=True,
                    capture_output=True,
                    timeout=2.0,
                ).stdout
            except:
                result = ""
            else:
                result = result.decode().strip()
            self.tailscale_address = result
        else:
            self.tailscale_address = ""
        zt_network = self._d.env_by_tags("zerotierid").value
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
        if self._d.env_by_tags("under_voltage").value and time.time() - self.undervoltage_epoch > 2 * 3600:
            self._d.env_by_tags("under_voltage").value = False

        # now let's check for disk space
        self._d.env_by_tags("low_disk").value = shutil.disk_usage("/").free < 1024 * 1024 * 1024

    @check_restart_lock
    def overview(self):
        enabled_aggregators = {
            k: a
            for k, a in self._all_aggregators().items()
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

        board = self._d.env_by_tags("board_name").value
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

        # refresh docker ps cache so the aggregator status is nicely up to date
        self._executor.submit(self._system.refreshDockerPs)

        board = self._d.env_by_tags("board_name").value
        base = self._d.env_by_tags("image_name").value
        version = self._d.env_by_tags("base_version").value
        containers = [
            self._d.env_by_tags(["container", container]).value
            for container in self._d.tag_for_name.values()
            if self._d.is_enabled(container)
            or container in ["ultrafeeder", "shipfeeder"]]
        available_tags = gitlab.gitlab_repo().get_tags()
        return render_template(
            "overview.html",
            enabled_aggregators=enabled_aggregators,
            local_address=local_address,
            tailscale_address=self.tailscale_address,
            zerotier_address=self.zerotier_address,
            compose_up_failed=compose_up_failed,
            board=board,
            base=base,
            version=version,
            containers=containers,
            sdrs=self._sdrdevices.sdrs,
            tags=available_tags,
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

        site_name = self._d.env_by_tags("site_name").list_get(0)
        now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
        download_name = f"adsb-feeder-config-{site_name}-{now}.txt"
        return send_file(
            pipeOut,
            as_attachment=as_attachment,
            download_name=download_name,
        )

    def info(self):
        board = self._d.env_by_tags("board_name").value
        base = self._d.env_by_tags("image_name").value
        current = self._d.env_by_tags("base_version").value
        ufargs = self._d.env_by_tags("ultrafeeder_extra_args").value
        envvars = self._d.env_by_tags("ultrafeeder_extra_env").value
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

        containers = [
            self._d.env_by_tags(["container", container]).value
            for container in self._d.tag_for_name.values()
            if self._d.is_enabled(container) or container == "ultrafeeder"
        ]
        return render_template(
            "info.html",
            board=board,
            memory=memory,
            top=top,
            storage=storage,
            base=base,
            kernel=kernel,
            journal=journal,
            ipv6=ipv6,
            current=current,
            containers=containers,
            sdrs=sdrs,
            ufargs=ufargs,
            envvars=envvars,
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

    @check_restart_lock
    def feeder_update(self):
        tag = request.form["tag"]
        self._logger.info(f"Starting update to {tag}.")
        # Submit the update script as a transient systemd unit, so the
        # process is independent from us and can shut us down.
        try:
            utils.system.systemctl().run_transient(
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

    def __init__(self):
        self._event_queue = queue.Queue(maxsize=10)
        self._connectivity_monitor = None
        self._connectivity_change_thread = None
        data = utils.data.Data()
        self._hotspot_app = HotspotApp(data, self._on_wifi_credentials)
        self._hotspot = hotspot.make_hotspot(self._on_wifi_test_status)
        self._adsb_im = AdsbIm(data, self._hotspot_app)
        self._hotspot_timer = None
        self._keep_running = True
        self._logger = logging.getLogger(type(self).__name__)
        self._ensure_config_exists()

    def _ensure_config_exists(self):
        if not utils.data.CONFIG_DIR.exists():
            utils.data.CONFIG_DIR.mkdir()

        if not utils.data.ENV_FILE.exists():
            env_file = utils.data.APP_DIR / ".env"
            if not env_file.exists():
                env_file = utils.data.APP_DIR / "docker.image.versions"
            shutil.copyfile(env_file, utils.data.ENV_FILE)


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
    if "--update-config" in sys.argv:
        # Just get AdsbIm to do some housekeeping and exit.
        AdsbIm(utils.data.Data(), None).update_config()
        sys.exit(0)

    shutdown_event = threading.Event()

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, setting shutdown event.")
        shutdown_event.set()
        signal.signal(sig, signal.SIG_DFL)  # Restore default handler

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    with PidFile(), Manager():
        shutdown_event.wait()
    logger.info("Shut down.")


if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    main()
