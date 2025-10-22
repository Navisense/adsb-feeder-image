import collections.abc as cl_abc
import concurrent.futures
import datetime
import filecmp
import functools as ft
import json
import logging
import logging.config
import operator as op
import os
import os.path
import pathlib
import queue
import re
import shlex
import secrets
import select
import signal
import shutil
import string
import subprocess
import tempfile
import threading
import time
from typing import Optional
import uuid
import re
import sys
import zipfile

import bcrypt
import flask
from flask import (
    flash,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    url_for,
)
import flask_login
import werkzeug.serving

import hotspot
import aggregators
import config
import flask_util
import gitlab
import sdr
import stats
import system
import util
import wifi

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
            """Filter GETs for static assets."""
            msg = record.getMessage()
            if "GET /static/" in msg:
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


class SystemOperationError(Exception):
    pass


class PidFile:
    PID_FILE = pathlib.Path("/run/porttracker-sdr-feeder.pid")

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def __enter__(self):
        if self.PID_FILE.exists():
            self._logger.warning(
                f"PID file {self.PID_FILE} already exists. Overwriting it, "
                "since porttracker-sdr-feeder should only run once.")
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


class AdminUser:
    """
    Simple admin user representation.

    We need to provide flask_login with a user object, but we don't have
    multiple users, just one that's logged in or not.
    """
    def __init__(self):
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return "admin"


class AdsbIm:
    RESTORE_STAGING_DIR = pathlib.Path("/run/adsb-restore-stage")
    _embedded_app_specs = [
        {
            "rule": "/ais-catcher",
            "endpoint": "ais-catcher",
            "port_key_path": "ports.aiscatcher",
            "path": "",
            "title": "AIS-catcher",},
        {
            "rule": "/tar1090",
            "endpoint": "tar1090",
            "port_key_path": "ports.tar1090",
            "path": "",
            "title": "Tar1090",},
        {
            "rule": "/tar1090-stats",
            "endpoint": "tar1090-stats",
            "port_key_path": "ports.tar1090",
            "path": "/graphs1090/",
            "title": "Tar1090 Stats",},
        {
            "rule": "/dozzle",
            "endpoint": "dozzle",
            "port_key_path": "ports.dazzle",
            "path": "",
            "title": "Dozzle",},
        {
            "rule": "/flightaware/status",
            "endpoint": "flightaware-status",
            "port_key_path": "ports.piastat",
            "path": "",
            "title": "FlightAware Stats",},
        {
            "rule": "/flightradar/status",
            "endpoint": "flightradar-status",
            "port_key_path": "ports.fr",
            "path": "",
            "title": "Flightradar Stats",},
        {
            "rule": "/planefinder/map",
            "endpoint": "planefinder-map",
            "port_key_path": "ports.pf",
            "path": "",
            "title": "PlaneFinder Map",},
        {
            "rule": "/planefinder/status",
            "endpoint": "planefinder-status",
            "port_key_path": "ports.pf",
            "path": "/stats.html",
            "title": "PlaneFinder Stats",},]
    _redirect_app_specs = [
        {
            "rule": "/flightaware/status.json",
            "endpoint": "flightaware-status-json",
            "port_key_path": "ports.piastat",
            "path": "/status.json",},
        {
            "rule": "/flightradar/monitor.json",
            "endpoint": "flightradar-monitor-json",
            "port_key_path": "ports.fr",
            "path": "/monitor.json",},]

    def __init__(self, conf: config.Config, sys: system.System, hotspot_app):
        self._logger = logging.getLogger(type(self).__name__)
        self._conf = conf
        self._system = sys
        self._hotspot_app = hotspot_app
        self._hotspot_mode = False
        self._server = self._server_thread = None
        self._executor = concurrent.futures.ThreadPoolExecutor()
        self._background_tasks = {}
        self._app = self._make_app()
        self._reception_monitor = stats.ReceptionMonitor(self._conf)
        self._sdrdevices = sdr.SDRDevices()

        self.last_dns_check = 0
        self.undervoltage_epoch = 0
        self.lastSetGainWrite = 0
        self._dmesg_monitor = DmesgMonitor(
            on_usb_change=self._sdrdevices.ensure_populated,
            on_undervoltage=self._set_undervoltage)

        self.exiting = False

        # let's only instantiate the Wifi class if we are on WiFi
        self.wifi = None
        self.wifi_ssid = ""

        # No one should share a CPU serial with AirNav, so always create fake
        # cpuinfo. Also identify if we would use the thermal hack for RB and
        # Ultrafeeder.
        if util.create_fake_cpu_info():
            self._conf.set("rbthermalhack", "/sys/class/thermal")
        else:
            self._conf.set("rbthermalhack", "")

        self.update_meminfo()
        self.update_journal_state()

    def _make_app(self) -> flask_util.App:
        app = flask_util.App(__name__)

        def env_functions():
            return {
                "get_conf": self._conf.get,
                "url_for": url_for_with_empty_parameters,
                "is_reception_enabled": self.is_reception_enabled,}

        def set_no_cache(response: Response):
            response.headers.setdefault("Cache-Control", "no-cache")
            return response

        app.secret_key = config.read_or_create_flask_secret_key()
        # set Cache-Control max-age for static files served
        # cachebust.sh ensures that the browser doesn't get outdated files
        app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 1209600
        app.jinja_env.add_extension("jinja2.ext.loopcontrols")
        app.context_processor(env_functions)
        app.after_request(set_no_cache)

        login_manager = flask_login.LoginManager()
        login_manager.init_app(app)

        def load_user(user_id: str) -> Optional[AdminUser]:
            if user_id == "admin":
                return AdminUser()
            self._logger.error(f"Request to load unknown user {user_id}.")
            return None

        login_manager.user_loader(load_user)

        # Docker container pages embedded in iframes.
        for spec in self._embedded_app_specs:
            port = self._conf.get(spec["port_key_path"])
            app.add_url_rule(
                spec["rule"],
                spec["endpoint"],
                view_func=ft.partial(
                    self.render_other_app_in_iframe, spec["title"], port,
                    spec["path"]),
                view_func_wrappers=[self._decide_route_hotspot_mode],
            )
        # Docker container pages with redirects.
        for spec in self._redirect_app_specs:
            port = self._conf.get(spec["port_key_path"])
            app.add_url_rule(
                spec["rule"],
                spec["endpoint"],
                view_func=ft.partial(
                    self.redirect_to_other_app, port, spec["path"]),
                view_func_wrappers=[self._decide_route_hotspot_mode],
            )

        app.add_url_rule(
            "/healthz",
            "healthz",
            view_func=self.healthz,
            view_func_wrappers=[self._decide_route_hotspot_mode],
            methods=["OPTIONS", "GET"],
        )
        app.add_url_rule(
            "/login",
            "login",
            view_func=self.login,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/logout",
            "logout",
            view_func=self.logout,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting],
            methods=["POST"],
        )
        app.add_url_rule(
            "/restarting",
            "restarting",
            view_func=self.restarting,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/shutdownpage",
            "shutdownpage",
            view_func=self.shutdownpage,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/restart",
            "restart",
            view_func=self.restart,
            view_func_wrappers=[self._decide_route_hotspot_mode],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/waiting",
            "waiting",
            view_func=self.waiting,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/stream-log",
            "stream_log",
            view_func=self.stream_log,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/backup",
            "backup",
            view_func=self.backup,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
        )
        app.add_url_rule(
            "/backup/download",
            "download_backup",
            view_func=self.download_backup,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
        )
        app.add_url_rule(
            "/restore",
            "restore",
            view_func=self.restore,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/sdr_setup",
            "sdr_setup",
            view_func=self.sdr_setup,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET"],
        )
        app.add_url_rule(
            "/visualization",
            "visualization",
            view_func=self.visualization,
            view_func_wrappers=[
                self._decide_route_hotspot_mode,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/expert",
            "expert",
            view_func=self.expert,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/systemmgmt",
            "systemmgmt",
            view_func=self.systemmgmt,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET"],
        )
        app.add_url_rule(
            "/aggregators",
            "aggregators",
            view_func=self.aggregators,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/",
            "index",
            view_func=self.index,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting],
            methods=["GET"],
        )
        app.add_url_rule(
            "/info",
            "info",
            view_func=self.info,
            view_func_wrappers=[
                self._decide_route_hotspot_mode,
                self._redirect_for_incomplete_config],
        )
        app.add_url_rule(
            "/overview",
            "overview",
            view_func=self.overview,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/support",
            "support",
            view_func=self.support,
            view_func_wrappers=[
                self._decide_route_hotspot_mode,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/setup",
            "setup",
            view_func=self.setup,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/sdplay_license",
            "sdrplay_license",
            view_func=self.sdrplay_license,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._redirect_for_incomplete_config, self._require_login],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/api/sdr_info",
            "sdr_info",
            view_func=self.sdr_info,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/api/stats",
            "stats",
            view_func=self.get_stats,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/api/aggregators",
            "aggregator_info",
            view_func=self.aggregator_info,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/api/version-info",
            "version_info",
            view_func=self.version_info,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/api/get_temperatures.json",
            "temperatures",
            view_func=self.temperatures,
            view_func_wrappers=[self._decide_route_hotspot_mode],
        )
        app.add_url_rule(
            "/set-ssh-credentials",
            "set-ssh-credentials",
            view_func=self.set_ssh_credentials,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/create-root-password",
            "create-root-password",
            view_func=self.create_root_password,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/set-admin-password",
            "set-admin-password",
            view_func=self.set_admin_password,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/shutdown-reboot",
            "shutdown-reboot",
            view_func=self.shutdown_reboot,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/toggle-log-persistence",
            "toggle-log-persistence",
            view_func=self.toggle_log_persistence,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/feeder-update",
            "feeder-update",
            view_func=self.feeder_update,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/os-update",
            "os-update",
            view_func=self.os_update,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/restart-containers",
            "restart-containers",
            view_func=self.restart_containers,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/configure-zerotier",
            "configure-zerotier",
            view_func=self.configure_zerotier,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/configure-tailscale",
            "configure-tailscale",
            view_func=self.configure_tailscale,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/configure-wifi",
            "configure-wifi",
            view_func=self.configure_wifi,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/configure-sdr",
            "configure-sdr",
            view_func=self.configure_sdr,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._redirect_if_restarting,
                self._require_login],
            methods=["POST"],
        )
        app.add_url_rule(
            "/get-logs",
            "get-logs",
            view_func=self.get_logs,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
        )
        app.add_url_rule(
            "/view-logs",
            "view-logs",
            view_func=self.view_logs,
            view_func_wrappers=[
                self._decide_route_hotspot_mode, self._require_login],
        )
        # Catch-all rules for the hotspot app.
        app.add_url_rule(
            "/",
            "/",
            view_func=None,
            view_func_wrappers=[self._decide_route_hotspot_mode],
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/<path:path>",
            None,
            view_func=None,
            view_func_wrappers=[self._decide_route_hotspot_mode],
            methods=["GET", "POST"],
        )
        return app

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

    def _redirect_if_restarting(self, view_func):
        """Redirect to the restarting page if necessary."""
        def handle_request(*args, **kwargs):
            if self._system.is_restarting:
                return redirect("/restarting")
            return view_func(*args, **kwargs)

        return handle_request

    def _redirect_for_incomplete_config(self, view_func):
        """
        Redirect if necessary setup is missing.

        Redirects the request to the basic setup page if that's not finished
        yet. If there are any inconsistencies with the configuration of SDR
        devices, redirects to the SDR setup page.
        """
        def handle_request(*args, **kwargs):
            # Check basic setup.
            if (not self._conf.get("mandatory_config_is_complete")
                    and request.endpoint != "setup"):
                self._logger.info(
                    "Mandatory config not complete, redirecting to setup.")
                flash("Please complete the initial setup.")
                return redirect(url_for("setup"))

            # Check if any used SDR devices are missing.
            available_serials = {sdr.serial for sdr in self._sdrdevices.sdrs}
            used_serials = {
                self._conf.get(f"serial_devices.{purpose}")
                for purpose in self._sdrdevices.purposes}
            used_serials = {serial for serial in used_serials if serial}
            missing_serials = used_serials - available_serials
            if missing_serials and request.endpoint != "sdr_setup":
                self._logger.warning(
                    f"Configured devices {missing_serials} appear to not be "
                    "attached, redirecting to SDR setup.")
                flash(
                    f"{len(missing_serials)} device(s) are configured for "
                    "some purpose, but aren't plugged in. Please set up the "
                    "remaining SDR devices.", category="error")
                return redirect(url_for("sdr_setup"))

            # Check for unconfigured SDR devices.
            configured_serials = (
                used_serials | set(self._conf.get("serial_devices.unused")))
            unconfigured_serials = available_serials - configured_serials
            if unconfigured_serials and request.endpoint != "sdr_setup":
                self._logger.info(
                    f"Unconfigured devices: {unconfigured_serials}, "
                    "redirecting to SDR setup.")
                flash(
                    f"Please configure {len(unconfigured_serials)} "
                    "unconfigured device(s).")
                return redirect(url_for("sdr_setup"))

            return view_func(*args, **kwargs)

        return handle_request

    def _require_login(self, view_func):
        """
        Redirect if the user needs to log in.

        Redirects to the login page, and uses login_url() to set a parameter
        containing the next url that should be redirected to.
        """
        def handle_request(*args, **kwargs):
            if (not self._conf.get("admin_login.is_enabled")
                    or flask_login.current_user.is_authenticated):
                return view_func(*args, **kwargs)
            flash("This page requires you to be logged in.", category="info")
            if request.method in ["GET", "OPTIONS"]:
                return redirect(
                    flask_login.login_url("login", next_url=request.url))
            self._logger.warning(
                "Received request with method other than GET or OPTIONS on a "
                "login-protected endpoint while the user wasn't logged in.")
            return redirect(
                flask_login.login_url("login", next_url=url_for("index")))

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
        self._ensure_running_dependencies()
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

        self._server = werkzeug.serving.make_server(
            host="0.0.0.0", port=int(self._conf.get("ports.web")),
            app=self._app, threaded=True)
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

    def _ensure_running_dependencies(self):
        self._maybe_enable_mdns()
        try:
            self._ensure_prometheus_metrics_state()
        except SystemOperationError:
            self._logger.exception(
                "Error enabling/disabling Prometheus metrics.")
        self._ensure_nightly_feeder_update_timer()
        self._ensure_nightly_os_update_timer()
        tailscale_is_running = (
            self._system.get_tailscale_info().status in [
                system.TailscaleStatus.LOGGED_IN,
                system.TailscaleStatus.LOGGED_OUT])
        if self._conf.get("tailscale.is_enabled") and not tailscale_is_running:
            self._logger.warning(
                "Tailscale is supposed to be enabled, but appears to be not "
                "running. Trying to enable it.")
            try:
                self._configure_tailscale(
                    True, self._conf.get("tailscale.extras"))
            except:
                self._logger.exception(
                    "Error enabling Tailscale during startup.")

    def _maybe_enable_mdns(self):
        if not self._conf.get("mdns.is_enabled"):
            return
        args = ["/bin/bash", "/opt/adsb/scripts/mdns-alias-setup.sh"]
        mdns_domains = ["porttracker-sdr-feeder.local"]
        if self.hostname:
            # If we have a hostname, make the mDNS script create an alias for
            # it as well.
            mdns_domains.append(f"{self.hostname}.local")
        self._conf.set("mdns.domains", mdns_domains)
        subprocess.run(args + mdns_domains)

    def update_meminfo(self):
        self._memtotal = 0
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        self._memtotal = util.make_int(line.split()[1])
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
                self._logger.error("We appear to have lost DNS.")

        self.last_dns_check = time.time()
        self._executor.submit(update_dns)

    def set_hostname_and_enable_mdns(self):
        if self.hostname:
            subprocess.run(["/usr/bin/hostnamectl", "hostname", self.hostname])
        self._maybe_enable_mdns()

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
            self._logger.info(f"Calling timedatectl set-timezone {timezone}")
            subprocess.run(["timedatectl", "set-timezone", f"{timezone}"], check=True)
        except subprocess.SubprocessError:
            self._logger.exception(
                f"Failed to set up timezone ({timezone}) using timedatectl, "
                "try dpkg-reconfigure instead")
            try:
                subprocess.run(["test", "-f", f"/usr/share/zoneinfo/{timezone}"], check=True)
            except:
                self._logger.exception(
                    f"Setting timezone: /usr/share/zoneinfo/{timezone} "
                    "doesn't exist")
                return False
            try:
                subprocess.run(["ln", "-sf", f"/usr/share/zoneinfo/{timezone}", "/etc/localtime"])
                subprocess.run("dpkg-reconfigure --frontend noninteractive tzdata", shell=True)
            except:
                pass

        return True

    def render_other_app_in_iframe(self, title, port, path):
        return render_template(
            "iframe.html", title=title, url=self._make_proxy_url(port, path))

    def redirect_to_other_app(self, port, path):
        url = self._make_proxy_url(port, path)
        return redirect(url)

    def _make_proxy_url(self, port, path):
        host_url = request.host_url.rstrip("/ ")
        host_url = re.sub(":\\d+$", "", host_url)
        q = ""
        if request.query_string:
            q = f"?{request.query_string.decode()}"
        return f"{host_url}:{port}{path}{q}"

    def index(self):
        return redirect(url_for("overview"))

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

    def login(self):
        if request.method == "GET":
            return render_template("login.html")
        next_url = self._get_next_url_from_request()
        if not self._conf.get("admin_login.is_enabled"):
            self._logger.error(
                "Received an admin login request, but admin login is "
                "disabled. Redirecting to next page.")
            return redirect(next_url)
        password_bcrypt = self._conf.get("admin_login.password_bcrypt")
        assert isinstance(password_bcrypt, bytes)
        password_plain = request.form["password"]
        if bcrypt.checkpw(password_plain.encode(), password_bcrypt):
            flask_login.login_user(AdminUser())
            return redirect(next_url)
        flash("Incorrect password, try again.", category="error")
        return redirect(flask_login.login_url("login", next_url=next_url))

    def _get_next_url_from_request(self):
        next_url = request.args.get("next")
        if not next_url:
            self._logger.warning(
                "No next URL in request, redirecting to index instead.")
            next_url = url_for("index")
        elif not next_url.startswith("/"):
            self._logger.warning(
                "Next URL is not a relative URL, redirecting to index "
                "instead.")
            next_url = url_for("index")
        return next_url

    def logout(self):
        next_url = self._get_next_url_from_request()
        if not flask_login.current_user.is_authenticated:
            self._logger.warning(
                "Received logout request, but user was not logged in.")
        else:
            flask_login.logout_user()
        return redirect(next_url)

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
        assert request.method == "GET"
        return render_template(
            "backup.html", restore_info=self._make_restore_info(),
            format_binary_prefix=util.format_binary_prefix)

    def _make_restore_info(self):
        if not self.RESTORE_STAGING_DIR.exists():
            return None
        new_files, changed_files, unchanged_files = [], [], []
        config_status = "unchanged"
        for file in self.RESTORE_STAGING_DIR.rglob("*"):
            if not file.is_file():
                # rglob() will also give us directories, we just want regular
                # files.
                continue
            relative_file = file.relative_to(self.RESTORE_STAGING_DIR)
            corresponding_current = config.CONFIG_DIR / relative_file
            file_details = {
                "name": str(relative_file), "size_bytes": file.stat().st_size}
            if not corresponding_current.exists():
                new_files.append(file_details)
            elif filecmp.cmp(file, corresponding_current):
                unchanged_files.append(file_details)
            else:
                if corresponding_current == config.CONFIG_FILE:
                    # In case there's a changed config file, examine it a
                    # little closer to display some extra info.
                    config_status = self._restore_config_status(file)
                    if config_status == "unchanged":
                        unchanged_files.append(file_details)
                        continue
                changed_files.append(file_details)
        for files in [new_files, changed_files, unchanged_files]:
            files.sort(key=op.itemgetter("name"))
        return {
            "new_files": new_files, "changed_files": changed_files,
            "unchanged_files": unchanged_files, "config_status": config_status}

    def _restore_config_status(self, restore_config_file):
        try:
            with restore_config_file.open() as f:
                restore_dict = json.load(f)
        except:
            self._logger.exception("Error loading restore config.")
            return "invalid"
        try:
            with config.CONFIG_FILE.open() as f:
                current_dict = json.load(f)
        except:
            self._logger.exception(
                "Error loading current config (this really shouldn't happen).")
            return "invalid_current"
        if restore_dict == current_dict:
            return "unchanged"
        try:
            restore_version = restore_dict["config_version"]
            if restore_version < config.Config.CONFIG_VERSION:
                return "older_version"
            elif restore_version == config.Config.CONFIG_VERSION:
                return "same_version"
            return "future_version"
        except:
            return "invalid"

    def download_backup(self):
        include_config = util.checkbox_checked(request.args['include-config'])
        include_stats = util.checkbox_checked(request.args['include-stats'])
        include_graphs1090 = util.checkbox_checked(
            request.args['include-graphs1090'])
        include_heatmap = util.checkbox_checked(
            request.args['include-heatmap'])
        if not any([include_config, include_stats, include_graphs1090,
                    include_heatmap]):
            return "No option selected.", 400
        temp_file = tempfile.NamedTemporaryFile()
        self._logger.info(
            f"Created temporary file {temp_file.name} to assemble config "
            "download.")

        def assemble_and_stream_zip() -> cl_abc.Generator[bytes]:
            with temp_file as binary_file:
                with zipfile.ZipFile(binary_file, mode="w") as zip_file:
                    self._add_backup_files_to_zip(
                        zip_file, include_config, include_stats,
                        include_graphs1090, include_heatmap)
                # Seek back to the beginning and yield the bytes of the zip
                # file.
                binary_file.seek(0)
                yield from binary_file
                # The temp file will be deleted when it is closed by the
                # context manager.

        ts = datetime.datetime.now(
            datetime.UTC).isoformat(timespec="seconds").replace(":", "-")
        file_name = (
            f"porttracker-sdr-feeder-config_{self.hostname}_{ts}.backup.zip")
        return flask.Response(
            assemble_and_stream_zip(), headers={
                "Content-Type": "application/zip",
                "Content-Disposition": f'attachment; filename="{file_name}"'})

    def _add_backup_files_to_zip(
            self, zip_file: zipfile.ZipFile, include_config, include_stats,
            include_graphs1090, include_heatmap):
        if include_graphs1090:
            # Start the flush right away in the background, because it may take
            # a few seconds.
            flush_task = self._executor.submit(self._flush_graphs1090_rrd_file)
        ultrafeeder_dir = config.CONFIG_DIR / "ultrafeeder"
        globe_history_dir = ultrafeeder_dir / "globe_history"
        # First the config.json itself.
        if include_config:
            zip_file.write(config.CONFIG_FILE, arcname="config.json")
        # Feeder stats.
        if include_stats:
            try:
                self._reception_monitor.write_stats_file()
            except:
                self._logger.exception(
                    "Error flushing current stats. Some data in backup may be "
                    "missing.", flash_message=True)
            zip_file.write(
                self._reception_monitor.STATS_FILE,
                arcname=self._reception_monitor.STATS_FILE.relative_to(
                    config.CONFIG_DIR))
        # Globe history data.
        if include_heatmap and globe_history_dir.is_dir():
            for subpath in globe_history_dir.iterdir():
                if subpath.name in ["internal_state", "tar1090-update"]:
                    continue
                for globe_history_file in subpath.rglob("*"):
                    zip_file.write(
                        globe_history_file,
                        arcname=globe_history_file.relative_to(
                            config.CONFIG_DIR))
        # Graph data from ultrafeeder.
        if include_graphs1090:
            flush_task.result()  # Wait for the flush to finish.
            rrd_file = (ultrafeeder_dir / "graphs1090/rrd/localhost.tar.gz")
            if rrd_file.exists():
                zip_file.write(
                    rrd_file, arcname=rrd_file.relative_to(config.CONFIG_DIR))
            else:
                self._logger.error(
                    "No graphs1090 rrd file found to back up.",
                    flash_message=True)

    def _flush_graphs1090_rrd_file(self):
        if not any(c.name == "ultrafeeder" for c in self._system.containers):
            self._logger.debug(
                "No need to flush the graphs1090 rrd file since ultrafeeder "
                "is not even running.")
            return
        rrd_file = (
            config.CONFIG_DIR / "ultrafeeder/graphs1090/rrd/localhost.tar.gz")

        def rrd_file_has_recently_been_written():
            if not rrd_file.exists():
                return False
            # Because of the way the file gets updated, it will briefly not
            # exist when the new copy is moved in place, so retry a few times
            # before giving up.
            start_time = time.time()
            while True:
                try:
                    return (time.time() - rrd_file.stat().st_mtime) < 120
                except:
                    if time.time() - start_time > 1:
                        self._logger.exception(
                            "Giving up trying to stat rrd file.")
                        return False
                    time.sleep(0.1)

        if rrd_file_has_recently_been_written():
            self._logger.debug(
                "No need to flush the graphs1090 rrd file since it's recently "
                "been written.")
            return

        # The rrd file will be updated via move after collectd is done writing
        # it out so killing collectd and waiting for the mtime to change is
        # enough.
        self._logger.info(
            f"Killing ultrafeeder's collectd to force an update of the of the "
            "graphs1090 rrd file.")
        try:
            util.shell_with_combined_output(
                "docker exec ultrafeeder pkill collectd", timeout=10,
                check=True)
        except subprocess.CalledProcessError:
            self._logger.exception(
                f"Error killing collectd. Graph data might miss up to 6h.",
                flash_message=True)
            return
        start_time = time.time()
        while True:
            if rrd_file_has_recently_been_written():
                self._logger.debug(
                    f"Graphs1090 rrd file updated successfully.")
                return
            if time.time() - start_time > 30:
                # Give up after 30 seconds.
                break
            time.sleep(0.5)

        self._logger.error(
            "Timeout when waiting for graphs1090 to be written. Graph data "
            "might miss up to 6h", flash_message=True)

    def restore(self):
        assert request.method == "POST"
        if "upload-file" in request.form:
            if ("file" not in request.files
                    or not request.files["file"].filename):
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                self._logger.error(
                    "Backup upload requested, but no file selected.",
                    flash_message=True)
                return redirect(url_for("backup"))
            file = request.files["file"]
            shutil.rmtree(self.RESTORE_STAGING_DIR, ignore_errors=True)
            try:
                with tempfile.TemporaryFile() as temp_file:
                    file.save(temp_file)
                    temp_file.seek(0)
                    with zipfile.ZipFile(temp_file) as zip_file:
                        zip_file.extractall(self.RESTORE_STAGING_DIR)
            except Exception as e:
                self._logger.exception(
                    f"Error extracting backup file: {e}.", flash_message=True)
                shutil.rmtree(self.RESTORE_STAGING_DIR, ignore_errors=True)
                return redirect(url_for("backup"))
            return redirect(url_for("backup"))
        elif "restore-backup" in request.form:
            restore_config_file = self.RESTORE_STAGING_DIR / (
                config.CONFIG_FILE.relative_to(config.CONFIG_DIR))
            if restore_config_file.exists():
                restore_config_status = self._restore_config_status(
                    restore_config_file)
            if restore_config_status in ["invalid", "future_version"]:
                self._logger.error(
                    "Can't apply backup, because the config file contained in "
                    f"it has status {restore_config_status}.")
                return redirect(url_for("backup"))
            self._logger.info("Starting restore service.")
            # Submit the restore script as a transient systemd unit, so the
            # process is independent from us and can shut us down.
            try:
                system.systemctl().run_transient(
                    "adsb-apply-config-restore",
                    ["/opt/adsb/scripts/apply-config-restore.bash"])
            except:
                self._logger.exception(
                    "Error executing restore. Trying to redirect to home.")
                return redirect(url_for("index"))
            # Set the exiting flag, so the /restart endpoint can tell the
            # restarting page that this instance is still going down. Once
            # restarted, it will say that it's complete.
            self.exiting = True
            return render_template("restarting.html")

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

    def aggregator_info(self):
        infos = []
        for agg in aggregators.all_aggregators().values():
            if not agg.enabled():
                continue
            ais_status = adsb_status = None
            if agg.enabled(aggregators.MessageType.AIS) and agg.status.ais:
                ais_status = {"data_status": agg.status.ais.data_status}
            if agg.enabled(aggregators.MessageType.ADSB) and agg.status.adsb:
                adsb_status = {
                    "data_status": agg.status.adsb.data_status,
                    "mlat_status": agg.status.adsb.mlat_status,
                    "mlat_privacy": self._conf.get("mlat_privacy"),}
                # Aggregator-specific extras.
                if agg.agg_key == "alive":
                    link = None
                    if agg.status.adsb:
                        link = agg.status.adsb.alive_map_link
                    adsb_status["alive_map_link"] = link
                elif agg.agg_key == "adsblol":
                    link = None
                    if agg.status.adsb:
                        link = agg.status.adsb.adsblol_link
                    adsb_status["adsblol_link"] = link
                elif agg.agg_key == "adsbx":
                    feeder_id = None
                    if agg.status.adsb:
                        feeder_id = agg.status.adsb.adsbx_feeder_id
                    adsb_status["adsbx_feeder_id"] = feeder_id
            info = {
                "agg_key": agg.agg_key,
                "name": agg.name,
                "map_url": agg.map_url,
                "status_url": agg.status_url,
                "ais": ais_status,
                "adsb": adsb_status,}
            infos.append(info)
        # Sort aggregators to always give the frontend the same order.
        return sorted(infos, key=op.itemgetter("agg_key"))

    def sdr_setup(self):
        return render_template("sdr_setup.html")

    def sdr_info(self):
        # Figure out which device is supposed to handle what. First check the
        # config.
        assignments = {
            serial: None
            for serial in self._conf.get("serial_devices.unused")}
        for purpose in self._sdrdevices.purposes:
            serial = self._conf.get(f"serial_devices.{purpose}")
            if not serial:
                continue
            elif serial in assignments:
                self._logger.error(
                    f"Device with serial {serial} assigned to more than one "
                    "purpose. This is a configuration error.")
                continue
            assignments[serial] = purpose
        # For any serials without a job, make a guess what they could do.
        guessed_assignment = self._sdrdevices.get_best_guess_assignment()
        for purpose, serial in guessed_assignment.items():
            if (serial not in assignments
                    and purpose not in assignments.values()):
                self._logger.info(
                    f"Automatically assigning device {serial} to {purpose}.")
                assignments[serial] = purpose
        sdr_device_dicts = []
        for sdr in self._sdrdevices.sdrs:
            sdr_device_dicts.append({
                "serial": sdr.serial,
                "vendor": sdr.vendor,
                "product": sdr.product,
                "type": sdr.type,
                "assignment": assignments.get(sdr.serial),})
        # Sort devices to always get the same order.
        sdr_device_dicts.sort(key=op.itemgetter("serial", "vendor", "product"))
        return {
            "sdr_devices": sdr_device_dicts,
            "lsusb_output": self._sdrdevices.lsusb_output,}

    def configure_sdr(self):
        # Extra buttons for gain resets.
        if "reset-gain" in request.form:
            self._logger.debug("Gain reset requested.")
            try:
                util.shell_with_combined_output(
                    "docker exec ultrafeeder /usr/local/bin/autogain1090 reset",
                    timeout=5, check=True)
            except:
                self._logger.exception(
                    "Error running Ultrafeeder autogain reset.",
                    flash_message=True)
            return redirect(url_for("sdr_setup"))
        if "reset-uat-gain" in request.form:
            self._logger.debug("UAT gain reset requested.")
            try:
                util.shell_with_combined_output(
                    "docker exec dump978 /usr/local/bin/autogain978 reset",
                    timeout=5, check=True)
            except:
                self._logger.exception(
                    "Error running UAT autogain reset.", flash_message=True)
            return redirect(url_for("sdr_setup"))

        # Regular form data.
        if (uat_gain := request.form["uat-gain"]) in ["", "auto"]:
            uat_gain = "autogain"
        self._conf.set("uatgain", uat_gain)
        if (gain := request.form["gain"]) == "":
            gain = "auto"
        self._conf.set("gain", gain)
        self._conf.set("biast", util.checkbox_checked(request.form["biast"]))
        self._conf.set(
            "uatbiast", util.checkbox_checked(request.form["uat-biast"]))
        self._conf.set("remote_sdr", request.form["remote-sdr"])

        # SDR devices assignments to purposes (AIS, ADS-B etc.).
        assignments = {}
        unused_serials = set()
        for key, value in request.form.items():
            if not key.startswith("purpose-"):
                continue
            _, serial = key.split("-")
            if value == "unused":
                unused_serials.add(serial)
                continue
            if value not in self._sdrdevices.purposes:
                return f"Unknown SDR assignment {value}", 400
            if value in assignments:
                return f"{value} assigned to more than one device.", 400
            assignments[value] = serial
        if len(assignments) != len(set(assignments.values())):
            return (
                f"At least one serial in {list(assignments.values())} "
                "assigned twice.", 400)
        unused_serials |= set(self._conf.get("serial_devices.unused"))
        unused_serials -= set(assignments.values())
        self._conf.set("serial_devices.unused", sorted(unused_serials))
        for purpose in self._sdrdevices.purposes:
            self._conf.set(
                f"serial_devices.{purpose}", assignments.get(purpose))
        self._logger.info(
            f"Configured SDR device assignments {assignments}, with unused "
            f"devices {unused_serials}.")

        # Finally go over some additional devices settings.
        self._configure_sdr_assignment_settings()

        self._system._restart.bg_run(
            cmdline="/opt/adsb/docker-compose-start", silent=False)
        return redirect(url_for("restarting"))

    def _configure_sdr_assignment_settings(self):
        serials_by_type = {}
        for sdr in self._sdrdevices.sdrs:
            serials_by_type.setdefault(sdr.type, set()).add(sdr.serial)
        # Airspy devices.
        self._conf.set("airspy.is_enabled", False)
        for purpose in self._sdrdevices.purposes:
            assigned_serial = self._conf.get(f"serial_devices.{purpose}")
            if assigned_serial not in serials_by_type.get("airspy", []):
                continue
            if purpose == "1090":
                self._conf.set("airspy.is_enabled", True)
            else:
                self._logger.error(
                    "Airspy configured for something other than 1090MHz. This "
                    "won't work.")
        # Stratuxv3 devices.
        self._conf.set("uat_device_type", "rtlsdr")
        for purpose in self._sdrdevices.purposes:
            assigned_serial = self._conf.get(f"serial_devices.{purpose}")
            if assigned_serial not in serials_by_type.get("stratuxv3", []):
                continue
            if purpose == "978":
                self._conf.set("uat_device_type", "stratuxv3")
            else:
                self._logger.error(
                    "Stratuxv3 configured for something other than 978MHz. "
                    "This won't work.")
        # SDRplay devices.
        self._conf.set("sdrplay", False)
        for purpose in self._sdrdevices.purposes:
            assigned_serial = self._conf.get(f"serial_devices.{purpose}")
            if assigned_serial not in serials_by_type.get("sdrplay", []):
                continue
            if purpose == "1090":
                self._conf.set("sdrplay", True)
            else:
                self._logger.error(
                    "Sdrplay configured for something other than 1090MHz. "
                    "This won't work.")
        # Set readsb_device_type to rtlsdr or modesbeast.
        adsb_serial = self._conf.get("serial_devices.1090")
        if adsb_serial in serials_by_type.get("rtlsdr", []):
            self._conf.set("readsb_device_type", "rtlsdr")
            # Set rtlsdr 1090 gain, bit hacky but means we don't have to
            # restart the bulky ultrafeeder for gain changes.
            self.setRtlGain()
        if adsb_serial in serials_by_type.get("modesbeast", []):
            self._conf.set("readsb_device_type", "modesbeast")
        else:
            self._conf.set("readsb_device_type", "")

    def version_info(self):
        stable_versions = [
            str(v) for v in gitlab.gitlab_repo().get_semver_tags()]
        containers = [{
            "image": c.image,
            "name": c.name,
            "state": c.state,
            "status": c.status,} for c in self._system.containers]
        containers.sort(key=op.itemgetter("name"))
        return {
            "version": self._conf.get("base_version"),
            "stable_versions": stable_versions,
            "containers": containers,}

    def visualization(self):
        if request.method == "POST":
            return self.update()
        return render_template("visualization.html")

    def clear_range_outline(self):
        self._logger.info("Resetting range outline for ultrafeeder.")
        setGainPath = pathlib.Path(f"/run/adsb-feeder-ultrafeeder/readsb/setGain")

        self.waitSetGainRace()
        util.string2file(
            path=setGainPath, string="resetRangeOutline", verbose=True)

    def waitSetGainRace(self):
        # readsb checks this the setGain file every 0.2 seconds
        # avoid races by only writing to it every 0.25 seconds
        wait = self.lastSetGainWrite + 0.25 - time.time()

        if wait > 0:
            time.sleep(wait)

        self.lastSetGainWrite = time.time()

    def set_rpw(self):
        issues_encountered = False
        proc = util.shell_with_combined_output(
            f"echo 'root:{self.rpw}' | chpasswd")
        try:
            proc.check_returncode()
        except:
            self._logger.exception("Failed to overwrite root password.")
            issues_encountered = True

        if os.path.exists("/etc/ssh/sshd_config"):
            proc = util.shell_with_combined_output(
                "sed -i '/^PermitRootLogin.*/d' /etc/ssh/sshd_config &&"
                + "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && "
                + "systemctl restart sshd", timeout=5)
            try:
                proc.check_returncode()
            except:
                self._logger.exception("Failed to allow root ssh login.")
                issues_encountered = True

        proc = util.shell_with_combined_output(
            "systemctl is-enabled ssh || systemctl is-enabled dropbear || "
            + "systemctl enable --now ssh || systemctl enable --now dropbear",
            timeout=60)
        try:
            proc.check_returncode()
        except:
            self._logger.exception("Failed to enable ssh.")
            issues_encountered = True

        if issues_encountered:
            self._logger.error(
                "Failure while setting root password, check logs for details",
                flash_message=True)

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
            util.string2file(path=(gaindir / "gain"), string=f"{gain}\n")

            # this adjusts the gain while readsb is running
            self.waitSetGainRace()
            util.string2file(path=setGainPath, string=f"{gain}\n")

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

        # finally, check if this has given us enough configuration info to
        # start the containers
        if self._conf.get("mandatory_config_is_complete"):
            if not self._conf.get("journal_configured"):
                try:
                    subprocess.run(
                        "/opt/adsb/scripts/journal-set-volatile.sh",
                        shell=True, timeout=5.0)
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
            with open("/etc/docker/daemon.json", "w") as f:
                json.dump(new_daemon_json, f, indent=2)
            # reload docker config (this is sufficient for the max-concurrent-downloads setting)
            proc = util.shell_with_combined_output(
                "bash -c 'kill -s SIGHUP $(pidof dockerd)'", timeout=5)
            try:
                proc.check_returncode()
            except:
                self._logger.exception("Failed to reload docker config.")

    def update(self, *, needs_docker_restart=False):
        """
        Update a bunch of stuff from various requests.

        This big mess of a function processes POSTed forms from various pages
        and takes actions based on form keys and values.
        """
        self._logger.debug(
            f"Updating with input from {request.headers.get('referer')}.")
        # By default, redirect to the same page again. We can override this
        # below.
        next_url = request.url
        for key, value in request.form.items():
            self._logger.debug(
                f"Update: handling {key} -> {value if value else '\"\"'}")
            # The following are keys of submit buttons, so we don't need to
            # check the value.
            if key == "sdrplay_license_accept":
                self._logger.debug("sdrplay license accepted.")
                needs_docker_restart, next_url = True, None
                self._conf.set("sdrplay_license_accepted", True)
            elif key == "sdrplay_license_reject":
                self._logger.debug("sdrplay license rejected.")
                needs_docker_restart, next_url = True, None
                self._conf.set("sdrplay_license_accepted", False)
            elif key == "aggregators":
                self._logger.debug(
                    "User has chosen aggregators on the aggregators page.")
                needs_docker_restart, next_url = True, None
                self._conf.set("aggregators_chosen", True)
                # Set aggregator_choice to individual so even users that have
                # set "all" before can still deselect individual aggregators.
                self._conf.set("aggregator_choice", "individual")
            elif key == "no_config_link":
                self._logger.debug("Disabled the tar1090 config link.")
                needs_docker_restart, next_url = True, None
                self._conf.set("tar1090_image_config_link", "")
            elif key == "allow_config_link":
                self._logger.debug("Enabled the tar1090 config link.")
                needs_docker_restart, next_url = True, None
                self._conf.set(
                    "tar1090_image_config_link",
                    "WILL_BE_SET_IN_IMPLIED_SETTINGS")
            elif key == "turn_on_gpsd":
                self._logger.debug("Enabled gpsd.")
                needs_docker_restart, next_url = True, None
                self._conf.set("use_gpsd", True)
                # Updates lat/lon/alt, in case there is a GPS fix.
                self.get_lat_lon_alt()
            elif key == "turn_off_gpsd":
                self._logger.debug("Disabled gpsd.")
                needs_docker_restart, next_url = True, None
                self._conf.set("use_gpsd", False)
            elif key == "enable_parallel_docker":
                self._logger.debug("Enabled parallel docker.")
                needs_docker_restart, next_url = True, None
                self.set_docker_concurrent(True)
            elif key == "disable_parallel_docker":
                self._logger.debug("Disabled parallel docker.")
                needs_docker_restart, next_url = True, None
                self.set_docker_concurrent(False)
            # That's submit buttons done. Next are checkboxes where we check
            # key and value. A lot of them just cause a one-time effect, where
            # you check the box, submit the form, and something happens once.
            # Pretty weird.
            if key == "clear_range" and util.checkbox_checked(value):
                self._logger.debug("Clear range requested.")
                self.clear_range_outline()
            # Next up are text fields.
            if key == "tz":
                self._logger.debug(f"Time zone changed to {value}.")
                self.set_tz(value)
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
                if key_path == "site_name":
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
                self._conf.set(key_path, value)

        # Done handling form data. See if the new config implies any other
        # settings.
        self.handle_implied_settings()

        if needs_docker_restart:
            self._system._restart.bg_run(
                cmdline="/opt/adsb/docker-compose-start", silent=False)

        if next_url:
            return redirect(next_url)
        if self._conf.get("mandatory_config_is_complete"):
            self._logger.debug("Base config is complete.")
            if (self._conf.get("sdrplay")
                    and not self._conf.get("sdrplay_license_accepted")):
                return redirect(url_for("sdrplay_license"))
            return render_template("/restarting.html")
        self._logger.debug("Base config not complete.")
        return redirect(url_for("index"))


    def _ensure_prometheus_metrics_state(self):
        currently_enabled = system.systemctl().unit_is_active(
            "adsb-push-prometheus-metrics.timer")
        should_be_enabled = self._conf.get(
            "aggregators.porttracker.prometheus.is_enabled")
        if currently_enabled != should_be_enabled:
            self._logger.info(
                f"Toggling Prometheus metrics state from {currently_enabled} "
                f"to {should_be_enabled}.")
        command = "disable"
        if should_be_enabled:
            command = "enable"
            # The service pushing the metrics uses the env file for
            # configuration. Let's make sure we have the current data in it.
            self._conf.write_env_file()
        proc, = system.systemctl().run([f"{command} --now"],
                                       ["adsb-push-prometheus-metrics.timer"])
        if proc.returncode != 0:
            raise SystemOperationError(f"systemctl call failed: {proc.stdout}")

    def expert(self):
        if request.method == "POST":
            return self.update()
        return render_template("expert.html")

    def systemmgmt(self):
        tailscale_info = self._system.get_tailscale_info()
        if tailscale_info.status in [system.TailscaleStatus.ERROR,
                                     system.TailscaleStatus.NOT_INSTALLED,
                                     system.TailscaleStatus.DISABLED]:
            # Reset the login link in the config if Tailscale is not running.
            self._conf.set("tailscale.login_link", None)
        zerotier_running = False
        proc = util.shell_with_combined_output("ps -e", timeout=2)
        zerotier_running = "zerotier-one" in proc.stdout
        # create a potential new root password in case the user wants to change it
        alphabet = string.ascii_letters + string.digits
        self.rpw = "".join(secrets.choice(alphabet) for i in range(12))
        stable_versions = gitlab.gitlab_repo().get_semver_tags()
        return render_template(
            "systemmgmt.html",
            tailscale_info=tailscale_info,
            zerotier_running=zerotier_running,
            rpw=self.rpw,
            stable_versions=stable_versions,
            containers=self._system.containers,
            persistent_journal=self._persistent_journal,
            wifi=self.wifi_ssid,
            Semver=util.Semver,
        )

    def sdrplay_license(self):
        if request.method == "POST":
            return self.update()
        return render_template("sdrplay_license.html")

    def aggregators(self):
        if request.method == "POST":
            self._configure_aggregators(request.form)
            # The Porttracker aggregator has the option of enabling Prometheus
            # metrics being sent to Porttracker. Enable/disable the systemd
            # unit here if necessary.
            try:
                self._ensure_prometheus_metrics_state()
            except SystemOperationError as e:
                self._logger.exception(
                    f"Error enabling/disabling Prometheus metrics: {e}",
                    flash_message=True)
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
            kwargs["prometheus_enabled"] = (
                util.checkbox_checked(
                    request.form.get(
                        "porttracker-enable-prometheus-metrics", "0")))
        elif agg_key == "aiscatcher":
            kwargs["feeder_key"] = (
                request.form.get("aiscatcher-feeder-key") or None)
        elif agg_key == "aishub":
            kwargs["udp_port"] = request.form.get("aishub-udp-port") or None
        return kwargs

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
                self.wifi = wifi.make_wifi()
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

    def overview(self):
        for aggregator in aggregators.all_aggregators().values():
            if aggregator.enabled():
                # Refresh the status cache to get a fast response when the
                # frontend requests it.
                self._executor.submit(aggregator.refresh_status_cache)
        # if we get to show the feeder homepage, the user should have everything figured out
        # and we can remove the pre-installed ssh-keys and password
        if os.path.exists("/opt/adsb/adsb.im.passwd.and.keys"):
            self._logger.info(
                "Removing pre-installed ssh keys, overwriting root password.")
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
        compose_up_failed = config.DOCKER_COMPOSE_UP_FAILED_FILE.exists()

        ipv6_broken = False
        if compose_up_failed:
            ipv6_broken = self._system.is_ipv6_broken()
            if ipv6_broken:
                self._logger.error("Broken IPv6 state detected.")

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
        aggregators_chosen = (
            any(
                agg.enabled()
                for agg in aggregators.all_aggregators().values())
            or self._conf.get("aggregators_chosen"))
        return render_template(
            "overview.html",
            local_address=local_address,
            zerotier_address=self.zerotier_address,
            compose_up_failed=compose_up_failed,
            system_info=self._system.system_info,
            device_hosts=device_hosts,
            str=str,
            aggregators_chosen=aggregators_chosen,
        )

    def setup(self):
        if request.method == "POST":
            return self.update()
        # make sure DNS works
        self.update_dns_state()
        return render_template("setup.html")

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
        self._logger.info(f"Support request {request.form}")
        if request.method != "POST":
            return render_template("support.html", url="")

        url = "Internal Error uploading logs"

        target = request.form.get("upload")
        if not target:
            self._logger.error("Support POST request without target.")
            return render_template("support.html", url="Error, unspecified upload target!")
        self._logger.info(f'Trying to upload the logs with target: "{target}"')
        if target == "0x0.st":
            proc = util.shell_with_combined_output(
                "bash /opt/adsb/log-sanitizer.sh 2>&1 | curl -F'expires=168' -F'file=@-'  https://0x0.st",
                timeout=60)
            try:
                proc.check_returncode()
                self._logger.info(f"Uploaded logs to {proc.stdout.strip()}")
            except:
                self._logger.exception(
                    "Failed to upload logs.", flash_message=True)
            return render_template("support.html", url=url)

        if target == "termbin.com":
            proc = util.shell_with_combined_output(
                "bash /opt/adsb/log-sanitizer.sh 2>&1 | nc termbin.com 9999",
                timeout=60)
            try:
                proc.check_returncode()
                self._logger.info(
                    f"Uploaded logs to {proc.stdout.strip('\0\n').strip()}")
            except:
                self._logger.exception(
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

        now = datetime.datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
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
        logfile = "/run/porttracker-sdr-feeder.log"

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
        ssh_dir = pathlib.Path("/root/.ssh")
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        with open(ssh_dir / "authorized_keys", "a+") as authorized_keys:
            authorized_keys.write(f"{request.form['ssh-public-key']}\n")
        self._conf.set("ssh_configured", True)
        proc = util.shell_with_combined_output(
            "systemctl is-enabled ssh || systemctl is-enabled dropbear || "
            + "systemctl enable --now ssh || systemctl enable --now dropbear",
            timeout=60)
        try:
            proc.check_returncode()
        except:
            self._logger.exception(
                f"Failed to enable ssh: {proc.stdout}",
                flash_message="Failed to enable ssh - check the logs "
                "for details.")
        return redirect(url_for("systemmgmt"))

    def create_root_password(self):
        self._logger.info("Updating the root password.")
        self.set_rpw()
        return redirect(url_for("systemmgmt"))

    def set_admin_password(self):
        password_plain = request.form["password"]
        if password_plain != request.form["password-repeated"]:
            flash(
                "The repeated password does not match. Password was not "
                "updated. Please try again.", category="error")
            return redirect(url_for("systemmgmt"))
        if password_plain:
            password_bcrypt = bcrypt.hashpw(
                password_plain.encode(), bcrypt.gensalt())
            self._conf.set("admin_login.password_bcrypt", password_bcrypt)
            flash("Admin password updated.", category="success")
        else:
            self._conf.set("admin_login.password_bcrypt", None)
            flask_login.logout_user()
            flash("Admin password removed.", category="success")
        return redirect(url_for("systemmgmt"))

    def shutdown_reboot(self):
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

    def feeder_update(self):
        if "do-feeder-update-now" in request.form:
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
        elif "configure-feeder-update" in request.form:
            should_be_enabled = util.checkbox_checked(
                request.form["nightly-feeder-update-enabled"])
            self._conf.set("nightly_feeder_update", should_be_enabled)
            self._ensure_nightly_feeder_update_timer()
            return redirect(url_for("systemmgmt"))
        else:
            return "Invalid form, missing submit button", 400

    def _ensure_nightly_feeder_update_timer(self):
        if self._conf.get("nightly_feeder_update"):
            command = "start"
        else:
            command = "stop"
        system.systemctl().run([command], ["adsb-update-feeder.timer"])

    def os_update(self):
        if "do-system-update-now" in request.form:
            self._logger.debug("OS update requested.")
            self._system._restart.bg_run(func=self._system.os_update)
            return render_template("/restarting.html")
        elif "configure-system-update" in request.form:
            should_be_enabled = util.checkbox_checked(
                request.form["nightly-system-update-enabled"])
            self._conf.set("nightly_base_update", should_be_enabled)
            self._ensure_nightly_os_update_timer()
            return redirect(url_for("systemmgmt"))
        else:
            return "Invalid form, missing submit button", 400

    def _ensure_nightly_os_update_timer(self):
        command = "start" if self._conf.get("nightly_base_update") else "stop"
        system.systemctl().run([command], ["adsb-update-os.timer"])

    def restart_containers(self):
        containers_to_restart = []
        for container in self._system.containers:
            # Only restart the ones that have been checked.
            if util.checkbox_checked(request.form[container.name]):
                containers_to_restart.append(container.name)
        if "recreate" in request.form:
            self._system.recreate_containers(containers_to_restart)
        else:
            self._system.restart_containers(containers_to_restart)
        return render_template("/restarting.html")

    def configure_zerotier(self):
        if (not util.checkbox_checked(request.form["enabled"])
                or "zerotierid" not in request.form):
            self._conf.set("zerotierid", "")
            system.systemctl().run(["disable --now", "mask"], ["zerotier-one"])
            return redirect(url_for("systemmgmt"))
        zerotier_id = request.form["zerotierid"]
        try:
            system.systemctl().run(["unmask", "enable --now"],
                                    ["zerotier-one"])
            # Wait for the service to get ready...
            time.sleep(5.0)
            subprocess.call([
                "/usr/sbin/zerotier-cli", "join", zerotier_id])
        except:
            self._logger.exception(
                "Exception trying to set up zerotier - giving up",
                flash_message=True)
        return redirect(url_for("systemmgmt"))

    def configure_tailscale(self):
        try:
            self._configure_tailscale(
                util.checkbox_checked(request.form["enabled"]),
                request.form.get("tailscale-extras", ""))
        except ValueError as e:
            flash(f"Error setting up Tailscale: {e}.", category="error")
        return redirect(url_for("systemmgmt"))

    def _configure_tailscale(self, enabled: bool, extra_args: Optional[str]):
        if self._system.get_tailscale_info().status in [
                system.TailscaleStatus.NOT_INSTALLED,
                system.TailscaleStatus.ERROR]:
            self._conf.set("tailscale.is_enabled", False)
            raise ValueError("Tailscale is not installed (properly)")
        if not enabled:
            system.systemctl().run(["disable --now", "mask"],
                                   ["tailscaled.service"])
            self._conf.set("tailscale.is_enabled", False)
            self._logger.info("Disabled Tailscale.")
            return
        try:
            system.systemctl().run(["unmask", "enable --now"],
                                   ["tailscaled.service"])
        except:
            self._logger.exception("Error starting Tailscale daemon.")
            raise ValueError("error starting the Tailscale daemon")
        login_server_url = None
        if extra_args:
            # right now we really only want to allow the login server arg
            try:
                ts_cli_switch, login_server_url = extra_args.split("=")
            except:
                ts_cli_switch = None
            if ts_cli_switch != "--login-server":
                raise ValueError(
                    f"invalid Tailscale args {extra_args} (at this point, we "
                    "only allow the --login-server=<server> argument)")
            match = re.match(
                r"^https?://[-a-zA-Z0-9._\+~=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?::[0-9]{1,5})?(?:[-a-zA-Z0-9()_\+.~/=]*)$",
                login_server_url,
            )
            if not match:
                raise ValueError(
                    f"invalid login server URL {login_server_url}")
        self._logger.info(f"Starting Tailscale with args {extra_args}")
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
            if login_server_url:
                cmd += [f"--login-server={shlex.quote(login_server_url)}"]
            proc = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                text=True,
            )
            os.set_blocking(proc.stderr.fileno(), False)
        except:
            self._logger.exception(
                "Exception trying to set up tailscale - giving up")
            raise ValueError("error setting up Tailscale")
        self._conf.set("tailscale.is_enabled", True)
        self._conf.set("tailscale.extras", extra_args)

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
            # Tailscale up will return immediately with successful return if
            # it's already logged in.
            info = self._system.get_tailscale_info()
            if info.status == system.TailscaleStatus.LOGGED_IN:
                self._logger.info("Started Tailscale (was already logged in).")
        else:
            raise ValueError("unable to get a login link")

    def configure_wifi(self):
        ssid = request.form.get("wifi_ssid")
        password = request.form.get("wifi_password")

        def connect_wifi():
            if self.wifi is None:
                self.wifi = wifi.make_wifi()
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
