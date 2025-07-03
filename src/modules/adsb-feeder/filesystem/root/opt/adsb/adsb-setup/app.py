import concurrent.futures
import copy
import filecmp
import gzip
import json
import logging
import logging.config
import math
import multiprocessing
import os
import os.path
import pathlib
import pickle
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
import threading
import time
import tempfile
import traceback
from uuid import uuid4
import sys
import zipfile
from base64 import b64encode
from datetime import datetime, timezone
from os import urandom
from time import sleep
from typing import Dict, List
from zlib import compress
from copy import deepcopy

from utils.config import (
    config_lock,
    log_consistency_warning,
    read_values_from_config_json,
    read_values_from_env_file,
    write_values_to_config_json,
    write_values_to_env_file,
)
import utils.util
from utils.util import create_fake_info, make_int, print_err, report_issue, mf_get_ip_and_triplet, string2file
from utils.wifi import make_wifi

# nofmt: on
# isort: off
import flask
from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    url_for,
)

import hotspot
from utils.data import Data
from utils.environment import Env
from utils.flask import RouteManager, check_restart_lock
from utils.netconfig import NetConfig, UltrafeederConfig
from utils.other_aggregators import (
    ADSBHub,
    FlightAware,
    FlightRadar24,
    OpenSky,
    PlaneFinder,
    PlaneWatch,
    RadarBox,
    RadarVirtuel,
    Uk1090,
    Sdrmap,
    Porttracker,
)
from utils.sdr import SDR, SDRDevices
from utils.agg_status import AggStatus, ImStatus
from utils.system import System
from utils.util import (
    cleanup_str,
    generic_get_json,
    is_true,
    print_err,
    stack_info,
    verbose,
    make_int,
    run_shell_captured,
)
from utils.background import Background

# nofmt: off
# isort: on

import werkzeug.serving
from werkzeug.utils import secure_filename

from flask.logging import logging as flask_logging


ADSB_DIR = pathlib.Path("/opt/adsb")
CONFIG_DIR = pathlib.Path("/opt/adsb/config")

logger = None


def setup_logging():
    fmt = '%(asctime)s|||%(module)s|||%(name)s|||%(levelname)s|||%(message)s'
    logging.config.dictConfig({
        'version': 1,
        'formatters': {'simple': {'format': fmt}},
        'handlers': {
            'stream_handler': {
                'class': 'logging.StreamHandler', 'formatter': 'simple'}},
        'root': {'level': 'DEBUG', 'handlers': ['stream_handler']},})


# don't log static assets
class NoStatic(flask_logging.Filter):
    def filter(record):
        msg = record.getMessage()
        if "GET /static/" in msg:
            return False
        if not (verbose & 8) and "GET /api/" in msg:
            return False

        return True


flask_logging.getLogger("werkzeug").addFilter(NoStatic)


def only_alphanum_dash(name):
    new_name = "".join(c for c in name if c.isalnum() or c == "-")
    new_name = new_name.strip("-")[:63]
    return new_name


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
    def __init__(self, data: Data, on_wifi_credentials):
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
            "hotspot.html", version=self._d.read_version(),
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
    def __init__(self, data: Data, hotspot_app):
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
                "list_value_by_tags": lambda tag, idx: list_value_by_tags(tag, idx),
                "env_values": self._d.env_values,
            }

        self._routemanager = RouteManager(self.app)
        self._system = System(data=self._d)
        # let's only instantiate the Wifi class if we are on WiFi
        self.wifi = None
        self.wifi_ssid = ""

        # prepare for app use (vs ADS-B Feeder Image use)
        # newer images will include a flag file that indicates that this is indeed
        # a full image - but in case of upgrades from older version, this heuristic
        # should be sufficient to guess if this is an image or an app
        os_flag_file = self._d.data_path / "os.adsb.feeder.image"
        if not os_flag_file.exists():
            # so this could be a pre-0.15 image, or it could indeed be the app
            app_flag_file = ADSB_DIR / "app.adsb.feeder.image"
            if not app_flag_file.exists():
                # there should be no app without the app flag file, so assume that
                # this is an older image that was upgraded and hence didn't get the
                # os flag file at install time
                open(os_flag_file, "w").close()

        if not os_flag_file.exists():
            # we are running as an app under DietPi or some other OS
            self._d.is_feeder_image = False
            with open(self._d.data_path / "adsb-setup/templates/systemmgmt.html", "r+") as systemmgmt_file:
                systemmgmt_html = systemmgmt_file.read()
                systemmgmt_file.seek(0)
                systemmgmt_file.write(
                    re.sub(
                        "FULL_IMAGE_ONLY_START.*? FULL_IMAGE_ONLY_END",
                        "",
                        systemmgmt_html,
                        flags=re.DOTALL,
                    )
                )
                systemmgmt_file.truncate()
            # v1.3.4 ended up not installing the correct port definitions - if that's
            # the case, then insert them into the settings
            self.setup_app_ports()

        self._sdrdevices = SDRDevices()
        for i in [0] + self.micro_indices():
            self._d.ultrafeeder.append(UltrafeederConfig(data=self._d, micro=i))

        self.last_dns_check = 0
        self.undervoltage_epoch = 0

        self._dmesg_monitor = DmesgMonitor(
            on_usb_change=self._sdrdevices._ensure_populated,
            on_undervoltage=self._set_undervoltage)

        self._current_site_name = None
        self._agg_status_instances = dict()
        self._im_status = ImStatus(self._d)
        self._next_url_from_director = ""
        self._last_stage2_contact = ""
        self._last_stage2_contact_time = 0

        self._last_base_info = dict()

        self.lastSetGainWrite = 0

        # no one should share a CPU serial with AirNav, so always create fake cpuinfo;
        # also identify if we would use the thermal hack for RB and Ultrafeeder
        if create_fake_info([0] + self.micro_indices()):
            self._d.env_by_tags("rbthermalhack").value = "/sys/class/thermal"
        else:
            self._d.env_by_tags("rbthermalhack").value = ""

        # Ensure secure_image is set the new way if before the update it was set only as env variable
        if self._d.is_enabled("secure_image"):
            self.set_secure_image()
        self._d.env_by_tags("pack")._value_call = self.pack_im
        self._other_aggregators = {
            "adsbhub--submit": ADSBHub(self._system),
            "flightaware--submit": FlightAware(self._system),
            "flightradar--submit": FlightRadar24(self._system),
            "opensky--submit": OpenSky(self._system),
            "planefinder--submit": PlaneFinder(self._system),
            "planewatch--submit": PlaneWatch(self._system),
            "radarbox--submit": RadarBox(self._system),
            "radarvirtuel--submit": RadarVirtuel(self._system),
            "1090uk--submit": Uk1090(self._system),
            "sdrmap--submit": Sdrmap(self._system),
            "porttracker": Porttracker(self._system),
        }
        # fmt: off
        self.all_aggregators = [
            # tag, name, map link, status link, table number
            ["adsblol", "adsb.lol", "https://adsb.lol/", ["https://api.adsb.lol/0/me"], 0],
            ["flyitaly", "Fly Italy ADSB", "https://mappa.flyitalyadsb.com/", ["https://my.flyitalyadsb.com/am_i_feeding"], 0],
            ["avdelphi", "AVDelphi", "https://www.avdelphi.com/coverage.html", [""], 0],
            ["planespotters", "Planespotters", "https://radar.planespotters.net/", ["https://www.planespotters.net/feed/status"], 0],
            ["tat", "TheAirTraffic", "https://globe.theairtraffic.com/", ["https://theairtraffic.com/feed/myip/"], 0],
            ["adsbfi", "adsb.fi", "https://globe.adsb.fi/", ["https://api.adsb.fi/v1/myip"], 0],
            ["adsbx", "ADSBExchange", "https://globe.adsbexchange.com/", ["https://www.adsbexchange.com/myip/"], 0],
            ["hpradar", "HPRadar", "https://skylink.hpradar.com/", [""], 0],
            ["alive", "airplanes.live", "https://globe.airplanes.live/", ["https://airplanes.live/myfeed/"], 0],
            ["flightradar", "flightradar24", "https://www.flightradar24.com/", ["/fr24STG2IDX/"], 1],
            ["planewatch", "Plane.watch", "https:/plane.watch/desktop.html", [""], 1],
            ["flightaware", "FlightAware", "https://www.flightaware.com/live/map", ["/fa-statusSTG2IDX/"], 1],
            ["radarbox", "AirNav Radar", "https://www.airnavradar.com/coverage-map", ["https://www.airnavradar.com/stations/<FEEDER_RADARBOX_SN>"], 1],
            ["planefinder", "PlaneFinder", "https://planefinder.net/", ["/planefinder-statSTG2IDX/"], 1],
            ["adsbhub", "ADSBHub", "https://www.adsbhub.org/coverage.php", [""], 1],
            ["opensky", "OpenSky", "https://opensky-network.org/network/explorer", ["https://opensky-network.org/receiver-profile?s=<FEEDER_OPENSKY_SERIAL>"], 1],
            ["radarvirtuel", "RadarVirtuel", "https://www.radarvirtuel.com/", [""], 1],
            ["1090uk", "1090MHz UK", "https://1090mhz.uk", ["https://www.1090mhz.uk/mystatus.php?key=<FEEDER_1090UK_API_KEY>"], 1],
            ["sdrmap", "sdrmap", "https://sdrmap.org/", [""], 1],
            ["porttracker", "Porttracker", "https://porttracker.co/", [""], 1],
        ]
        self.agg_matrix = None
        self.agg_structure = None
        self.last_cache_agg_status = 0
        self.cache_agg_status_lock = threading.Lock()
        self.last_aggregator_debug_print = None
        self.microfeeder_setting_tags = (
            "site_name", "lat", "lon", "alt", "tz", "mf_version", "max_range",
            "adsblol_uuid", "adsblol_link", "ultrafeeder_uuid", "mlat_privacy", "route_api",
            "uat978", "heywhatsthat", "heywhatsthat_id",
            "flightradar--key", "flightradar_uat--key", "flightradar--is_enabled",
            "planewatch--key", "planewatch--is_enabled",
            "flightaware--key", "flightaware--is_enabled",
            "radarbox--key", "radarbox--snkey", "radarbox--is_enabled",
            "planefinder--key", "planefinder--is_enabled",
            "adsbhub--key", "adsbhub--is_enabled",
            "opensky--user", "opensky--key", "opensky--is_enabled",
            "radarvirtuel--key", "radarvirtuel--is_enabled",
            "planewatch--key", "planewatch--is_enabled",
            "1090uk--key", "1090uk--is_enabled",
            "adsblol--is_enabled",
            "flyitaly--is_enabled",
            "adsbx--is_enabled", "adsbxfeederid",
            "tat--is_enabled",
            "planespotters--is_enabled",
            "adsbfi--is_enabled",
            "avdelphi--is_enabled",
            "hpradar--is_enabled",
            "alive--is_enabled",
            "uat978--is_enabled",
            "sdrmap--is_enabled", "sdrmap--user", "sdrmap--key",
        )
        # fmt: on

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
            "/running",
            "running",
            self._decide_route_hotspot_mode(self.running),
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
            "/index",
            "index",
            self._decide_route_hotspot_mode(self.index),
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
            "/stage2",
            "stage2",
            self._decide_route_hotspot_mode(self.stage2),
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/update",
            "update",
            self._decide_route_hotspot_mode(self.update),
            methods=["POST"],
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
            "/api/base_info",
            "base_info",
            self._decide_route_hotspot_mode(self.base_info),
        )
        self.app.add_url_rule(
            "/api/stage2_info",
            "stage2_info",
            self._decide_route_hotspot_mode(self.stage2_info),
        )
        self.app.add_url_rule(
            "/api/stage2_stats",
            "stage2_stats",
            self._decide_route_hotspot_mode(self.stage2_stats),
        )
        self.app.add_url_rule(
            "/api/stats",
            "stats",
            self._decide_route_hotspot_mode(self.stats),
        )
        self.app.add_url_rule(
            "/api/micro_settings",
            "micro_settings",
            self._decide_route_hotspot_mode(self.micro_settings),
        )
        self.app.add_url_rule(
            "/api/check_remote_feeder/<ip>",
            "check_remote_feeder",
            self._decide_route_hotspot_mode(self.check_remote_feeder),
        )
        self.app.add_url_rule(
            f"/api/status/<agg>",
            "beast",
            self._decide_route_hotspot_mode(self.agg_status),
        )
        self.app.add_url_rule(
            "/api/stage2_connection",
            "stage2_connection",
            self._decide_route_hotspot_mode(self.stage2_connection),
        )
        self.app.add_url_rule(
            "/api/get_temperatures.json",
            "temperatures",
            self._decide_route_hotspot_mode(self.temperatures),
        )
        self.app.add_url_rule(
            f"/feeder-update-<channel>",
            "feeder-update",
            self._decide_route_hotspot_mode(self.feeder_update),
        )
        self.app.add_url_rule(
            f"/get-logs",
            "get-logs",
            self._decide_route_hotspot_mode(self.get_logs),
        )
        self.app.add_url_rule(
            f"/view-logs",
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

        self._d.previous_version = self.get_previous_version()

        self.load_planes_seen_per_day()

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

    def start(self):
        if self._server:
            raise RuntimeError("already started")
        assert self._server_thread is None
        self.update_config()

        # if using gpsd, try to update the location
        if self._d.is_enabled("use_gpsd"):
            self.get_lat_lon_alt()

        self._background_tasks["every_minute"] = (
            Background(60, self.every_minute))
        # every_minute stuff is required to initialize some values, run it synchronously
        self.every_minute()

        if self._d.is_enabled("stage2"):
            # let's make sure we tell the micro feeders every ten minutes that
            # the stage2 is around, looking at them
            self._executor.submit(self.stage2_checks)
            self._background_tasks["stage2_checks"] = (
                Background(600, self.stage2_checks))

        # reset undervoltage indicator
        self._d.env_by_tags("under_voltage").value = False

        self._dmesg_monitor.start()

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
        self.exiting = True
        self._dmesg_monitor.stop()
        self.write_planes_seen_per_day()
        for task in self._background_tasks.values():
            task.stop_and_wait()
        self._executor.shutdown()
        self._server.shutdown()
        self._server_thread.join()
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
        conf_version = self._d.env_by_tags("base_version").value
        if pathlib.Path(self._d.version_file).exists():
            with open(self._d.version_file, "r") as f:
                file_version = f.read().strip()
        else:
            file_version = ""
        if file_version:
            if file_version != conf_version:
                print_err(
                    f"found version '{conf_version}' in memory, but '{file_version}' on disk, updating to {file_version}"
                )
                self._d.env_by_tags("base_version").value = file_version
        else:
            if conf_version:
                print_err(f"no version found on disk, using {conf_version}")
                with open(self._d.version_file, "w") as f:
                    f.write(conf_version)
            else:
                print_err("no version found on disk or in memory, using v0.0.0")
                self._d.env_by_tags("base_version").value = "v0.0.0"

    def get_previous_version(self):
        previous_version = ""
        pv_file = "/opt/adsb/adsb.im.previous-version"

        if pathlib.Path(pv_file).exists():
            with open(pv_file, "r") as f:
                previous_version = f.read().strip()

        return previous_version

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

    def pack_im(self) -> str:
        image = {
            "in": self._d.env_by_tags("image_name").value,
            "bn": self._d.env_by_tags("board_name").value,
            "bv": self._d.env_by_tags("base_version").value,
            "pv": self._d.previous_version,
            "cv": self.agg_matrix,
        }
        if self._d.env_by_tags("initial_version").value == "":
            self._d.env_by_tags("initial_version").value == self._d.env_by_tags("base_version").value
        return b64encode(compress(pickle.dumps(image))).decode("utf-8")

    def check_secure_image(self):
        return self._d.secure_image_path.exists()

    def set_secure_image(self):
        # set legacy env variable as well for webinterface
        self._d.env_by_tags("secure_image").value = True
        if not self.check_secure_image():
            self._d.secure_image_path.touch(exist_ok=True)
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

    def setup_ultrafeeder_args(self):
        # set all of the ultrafeeder config data up
        for i in [0] + self.micro_indices():
            print_err(f"ultrafeeder_config {i}", level=2)
            if i >= len(self._d.ultrafeeder):
                self._d.ultrafeeder.append(UltrafeederConfig(data=self._d, micro=i))
            self._d.env_by_tags("ultrafeeder_config").list_set(i, self._d.ultrafeeder[i].generate())

    def setup_app_ports(self):
        if not self._d.is_enabled("app_init_done"):
            # ok, we don't have them explicitly set, so let's set them up
            # with the app defaults
            for tag, default in [
                ("webport", 1099),
                ("tar1090port", 1090),
                ("uatport", 1091),
                ("piamapport", 1092),
                ("piastatport", 1093),
                ("dazzleport", 1094),
                ("dazzleport", 1094),]:
                if self._d.env_by_tags(tag).value is None:
                    # TODO and this is completely wrong anyway+++++++++
                    self._d.env_by_tags("app_init_done").value = default

    def set_hostname_and_enable_mdns(self, site_name: str):
        self._current_site_name = site_name
        should_set_hostname = self._d.is_feeder_image and self.hostname
        if should_set_hostname:
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
            report_issue(f"timezone {timezone} probably invalid, defaulting to UTC")
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

    def push_multi_outline(self) -> None:
        if not self._d.is_enabled("stage2"):
            return

        def push_mo():
            subprocess.run(
                ["bash", "/opt/adsb/push_multioutline.sh", f"{self._d.env_by_tags('num_micro_sites').value}"]
            )
        self._executor.submit(push_mo)

    def stage2_checks(self):
        for i in self.micro_indices():
            if self._d.env_by_tags("mf_version").list_get(i) != "not an adsb.im feeder":
                self.get_base_info(i)

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

    def running(self):
        return "OK"

    def backup(self):
        return render_template("/backup.html")

    def backup_execute_config(self):
        return self.create_backup_zip()

    def backup_execute_graphs(self):
        return self.create_backup_zip(include_graphs=True)

    def backup_execute_full(self):
        return self.create_backup_zip(include_graphs=True, include_heatmap=True)

    def create_backup_zip(self, include_graphs=False, include_heatmap=False):
        adsb_path = self._d.config_path

        def graphs1090_writeback(uf_path, microIndex):
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

            context = f"graphs1090 writeback {microIndex}"

            t = timeSinceWrite(rrd_file)
            if t < 120:
                print_err(f"{context}: not needed, timeSinceWrite: {round(t)}s")
                return

            print_err(f"{context}: requesting")
            try:
                if microIndex == 0:
                    uf_container = "ultrafeeder"
                else:
                    uf_container = f"uf_{microIndex}"
                subprocess.run(
                    f"docker exec {uf_container} pkill collectd",
                    timeout=10.0,
                    shell=True,
                    check=True,
                )
            except:
                report_issue(f"{context}: docker exec failed - backed up graph data might miss up to 6h")
                pass
            else:
                count = 0
                increment = 0.1
                # give up after 30 seconds
                while count < 30:
                    count += increment
                    sleep(increment)
                    if timeSinceWrite(rrd_file) < 120:
                        print_err(f"{context}: success")
                        return

                report_issue(f"{context}: writeback timed out - backed up graph data might miss up to 6h")

        fdOut, fdIn = os.pipe()
        pipeOut = os.fdopen(fdOut, "rb")
        pipeIn = os.fdopen(fdIn, "wb")

        def zip2fobj(fobj, include_graphs, include_heatmap):
            try:
                with fobj as file, zipfile.ZipFile(file, mode="w") as backup_zip:
                    backup_zip.write(adsb_path / "config.json", arcname="config.json")

                    for microIndex in [0] + self.micro_indices():
                        if microIndex == 0:
                            uf_path = adsb_path / "ultrafeeder"
                        else:
                            uf_path = adsb_path / "ultrafeeder" / self._d.env_by_tags("mf_ip").list_get(microIndex)

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
                                    backup_zip.write(f, arcname=f.relative_to(adsb_path))

                        # do graphs after heatmap data as this can pause a couple seconds in graphs1090_writeback
                        # due to buffers, the download won't be recognized by the browsers until some data is added to the zipfile
                        if include_graphs:
                            graphs1090_writeback(uf_path, microIndex)
                            graphs_path = uf_path / "graphs1090/rrd/localhost.tar.gz"
                            if graphs_path.exists():
                                backup_zip.write(graphs_path, arcname=graphs_path.relative_to(adsb_path))
                            else:
                                report_issue(f"graphs1090 backup failed, file not found: {graphs_path}")

            except BrokenPipeError:
                report_issue(f"warning: backup download aborted mid-stream")

        self._executor.submit(
            zip2fobj,
            fobj=pipeIn,
            include_graphs=include_graphs,
            include_heatmap=include_heatmap,
        )

        site_name = self._d.env_by_tags("site_name_sanitized").list_get(0)
        if self._d.is_enabled("stage2"):
            site_name = f"stage2-{site_name}"
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
                restore_path = pathlib.Path("/opt/adsb/config/restore")
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
        adsb_path = pathlib.Path("/opt/adsb/config")
        restore_path = adsb_path / "restore"
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
            elif os.path.isfile(adsb_path / name):
                if filecmp.cmp(adsb_path / name, restore_path / name):
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
        adsb_path = pathlib.Path("/opt/adsb/config")
        (adsb_path / "ultrafeeder").mkdir(mode=0o755, exist_ok=True)
        restore_path = adsb_path / "restore"
        restore_path.mkdir(mode=0o755, exist_ok=True)
        try:
            subprocess.call("/opt/adsb/docker-compose-adsb down -t 20", timeout=40.0, shell=True)
        except subprocess.TimeoutExpired:
            print_err("timeout expired stopping docker... trying to continue...")
        for name, value in form.items():
            if value == "1":
                print_err(f"restoring {name}")
                dest = adsb_path / name
                if dest.is_file():
                    shutil.move(dest, adsb_path / (name + ".dist"))
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
        restore_path = pathlib.Path("/opt/adsb/config/restore")
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
                report_issue("timeout expired joining Zerotier network... trying to continue...")

        self.handle_implied_settings()
        self.write_envfile()

        try:
            subprocess.call("/opt/adsb/docker-compose-start", timeout=180.0, shell=True)
        except subprocess.TimeoutExpired:
            report_issue("timeout expired re-starting docker... trying to continue...")

    def base_is_configured(self):
        base_config: set[Env] = {env for env in self._d._env if env.is_mandatory}
        for env in base_config:
            if env._value == None or (type(env._value) == list and not env.list_get(0)):
                print_err(f"base_is_configured: {env} isn't set up yet")
                return False
        return True

    def at_least_one_aggregator(self) -> bool:
        # this only checks for a micro feeder or integrated feeder, not for stage2
        if self._d.ultrafeeder[0].enabled_aggregators:
            return True

        # of course, maybe they picked just one or more proprietary aggregators and that's all they want...
        for submit_key in self._other_aggregators.keys():
            key = submit_key.replace("--submit", "")
            if self._d.list_is_enabled(key, idx=0):
                print_err(f"no semi-anonymous aggregator, but enabled {key}")
                return True

        return False

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

    def stage2_info(self):
        if not self._d.is_enabled("stage2"):
            print_err("/api/stage2_info called but stage2 is not enabled")
            return self.base_info()
        # for a stage2 we return the base info for each of the micro feeders
        info_array = []
        for i in self.micro_indices():
            uat_capable = False
            if self._d.env_by_tags("mf_version").list_get(i) != "not an adsb.im feeder":
                self.get_base_info(i)
                uat_capable = self._d.env_by_tags("978url").list_get(i) != ""

            info_array.append(
                {
                    "mf_ip": self._d.env_by_tags("mf_ip").list_get(i),
                    "mf_version": self._d.env_by_tags("mf_version").list_get(i),
                    "lat": self._d.env_by_tags("lat").list_get(i),
                    "lon": self._d.env_by_tags("lon").list_get(i),
                    "alt": self._d.env_by_tags("alt").list_get(i),
                    "uat_capable": uat_capable,
                    "brofm_capable": (
                        self._d.list_is_enabled("mf_brofm_capable", idx=i)
                        or self._d.list_is_enabled("mf_brofm", idx=i)
                    ),
                    "brofm_enabled": self._d.list_is_enabled("mf_brofm", idx=i),
                }
            )
        return Response(json.dumps(info_array), mimetype="application/json")

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

    def base_info(self):
        listener = request.remote_addr
        tm = int(time.time())
        print_err(f"access to base_info from {listener}", level=8)
        self._last_stage2_contact = listener
        self._last_stage2_contact_time = tm
        lat, lon, alt = self.get_lat_lon_alt()
        rtlsdr_at_port = 0
        if self._d.env_by_tags("readsb_device_type").value == "rtlsdr":
            if self._d.is_enabled("stage2_nano"):
                rtlsdr_at_port = self._d.env_by_tags("nanotar1090portadjusted").value
            else:
                rtlsdr_at_port = self._d.env_by_tags("tar1090port").value
        response = make_response(
            json.dumps(
                {
                    "name": self._d.env_by_tags("site_name").list_get(0),
                    "lat": lat,
                    "lng": lon,  # include both spellings for backwards compatibility
                    "lon": lon,
                    "alt": alt,
                    "tz": self._d.env_by_tags("tz").list_get(0),
                    "version": self._d.env_by_tags("base_version").value,
                    "airspy_at_port": (self._d.env_by_tags("airspyport").value if self._d.is_enabled("airspy") else 0),
                    "rtlsdr_at_port": rtlsdr_at_port,
                    "dump978_at_port": (
                        self._d.env_by_tags("uatport").value if self._d.list_is_enabled(["uat978"], 0) else 0
                    ),
                    "brofm_capable": (self._d.env_by_tags("aggregator_choice").value in ["micro", "nano"]),
                }
            )
        )
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    def uf_suffix(self, i):
        suffix = f"uf_{i}" if i != 0 else "ultrafeeder"
        if self._d.env_by_tags("aggregator_choice").value == "nano":
            suffix = "nanofeeder"
        return suffix

    def stats(self):
        # collect the stats for each microfeeder and ensure that they are all the same
        # length by padding with zeros (that means the value for days for which we have
        # no data is 0)
        plane_stats = []
        l = 0
        for i in [0] + self.micro_indices():
            plane_stats.append([len(self.planes_seen_per_day[i])] + self.plane_stats[i])
            l = max(l, len(plane_stats[-1]))
        for i in range(len(plane_stats)):
            plane_stats[i] = plane_stats[i] + [0] * (l - len(plane_stats[i]))
        return Response(json.dumps(plane_stats), mimetype="application/json")

    def stage2_stats(self):
        ret = []
        if True:
            for i in [0] + self.micro_indices():
                tplanes = len(self.planes_seen_per_day[i])
                ip = self._d.env_by_tags("mf_ip").list_get(i)
                ip, triplet = mf_get_ip_and_triplet(ip)
                suffix = self.uf_suffix(i)
                try:
                    with open(f"/run/adsb-feeder-{suffix}/readsb/stats.prom") as f:
                        uptime = 0
                        found = 0
                        for line in f:
                            if "position_count_total" in line:
                                pps = int(line.split()[1]) / 60
                                # show precise position rate if less than 1
                                pps = round(pps, 1) if pps < 1 else round(pps)
                                found |= 1
                            if "readsb_messages_valid" in line:
                                mps = round(int(line.split()[1]) / 60)
                                found |= 4
                            if "readsb_aircraft_with_position" in line:
                                planes = int(line.split()[1])
                                found |= 8
                            if i != 0 and f'readsb_net_connector_status{{host="{ip}"' in line:
                                uptime = int(line.split()[1])
                                found |= 2
                            if i == 0 and "readsb_uptime" in line:
                                uptime = int(int(line.split()[1]) / 1000)
                                found |= 2
                            if found == 15:
                                break
                        ret.append(
                            {
                                "pps": pps,
                                "mps": mps,
                                "uptime": uptime,
                                "planes": planes,
                                "tplanes": tplanes,
                            }
                        )
                except FileNotFoundError:
                    ret.append({"pps": 0, "mps": 0, "uptime": 0, "planes": 0, "tplanes": tplanes})
                except:
                    print_err(traceback.format_exc())
                    ret.append({"pps": 0, "mps": 0, "uptime": 0, "planes": 0, "tplanes": tplanes})
        return Response(json.dumps(ret), mimetype="application/json")

    def stage2_connection(self):
        if not self._d.env_by_tags("aggregator_choice").value in ["micro", "nano"] or self._last_stage2_contact == "":
            return Response(json.dumps({"stage2_connected": "never"}), mimetype="application/json")
        now = int(time.time())
        last = self._last_stage2_contact_time
        since = now - last
        hrs, min = divmod(since // 60, 60)
        if hrs > 0:
            time_since = "more than an hour"
        elif min > 15:
            time_since = f"{min} minutes"
        else:
            time_since = "recent"
        return Response(
            json.dumps(
                {
                    "stage2_connected": time_since,
                    "address": self._last_stage2_contact,
                }
            ),
            mimetype="application/json",
        )

    def micro_settings(self):
        microsettings = {}
        for e in self._d._env:
            for t in self.microfeeder_setting_tags:
                tags = t.split("--")
                if all(t in e.tags for t in tags):
                    if type(e._value) == list:
                        microsettings[t] = e.list_get(0)
                    else:
                        microsettings[t] = e._value
        # fix up the version
        microsettings["mf_version"] = self._d.env_by_tags("base_version").value
        # ensure forward/backward compatibility with lng/lon change
        microsettings["lng"] = microsettings["lon"]
        response = make_response(json.dumps(microsettings))
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    def generate_agg_structure(self):
        aggregators = copy.deepcopy(self.all_aggregators)
        n = len(self.micro_indices()) + 1
        matrix = [0] * n
        active_aggregators = []
        for idx in range(len(aggregators)):
            agg = aggregators[idx][0]
            status_link_list = aggregators[idx][3]
            template_link = status_link_list[0]
            final_link = template_link
            agg_enabled = False
            for i in range(n):
                agg_enabled |= self._d.list_is_enabled(agg, i)
                matrix[i] |= 1 << idx if self._d.list_is_enabled(agg, i) else 0
                if template_link.startswith("/"):
                    final_link = template_link.replace("STG2IDX", "" if i == 0 else f"_{i}")
                else:
                    match = re.search("<([^>]*)>", template_link)
                    if match:
                        final_link = template_link.replace(match.group(0), self._d.env(match.group(1)).list_get(i))
                if i == 0:
                    status_link_list[0] = final_link
                else:
                    status_link_list.append(final_link)

            if agg_enabled:
                active_aggregators.append(aggregators[idx])

        agg_debug_print = f"final aggregator structure: {active_aggregators}"
        if agg_debug_print != self.last_aggregator_debug_print:
            self.last_aggregator_debug_print = agg_debug_print
            print_err(agg_debug_print)

        self.agg_matrix = matrix
        self.agg_structure = active_aggregators

    def cache_agg_status(self):
        with self.cache_agg_status_lock:
            now = time.time()
            if now < self.last_cache_agg_status + 5:
                return
            self.last_cache_agg_status = now

        # print_err("caching agg status")

        # launch all the status checks there are in separate threads
        # they will be requested by the index page soon
        for entry in self.agg_structure:
            agg = entry[0]
            for idx in [0] + self.micro_indices():
                if self._d.list_is_enabled(agg, idx):
                    self._executor.submit(self.get_agg_status, agg, idx)

    def get_agg_status(self, agg, idx):

        status = self._agg_status_instances.get(f"{agg}-{idx}")
        if status is None:
            status = self._agg_status_instances[f"{agg}-{idx}"] = AggStatus(
                agg,
                idx,
                self._d,
                f"http://127.0.0.1:{self._d.env_by_tags('webport').value}",
                self._system,
            )

        res = {
            "beast": status.beast,
            "mlat": status.mlat,
        }

        if agg == "adsbx":
            res["adsbxfeederid"] = self._d.env_by_tags("adsbxfeederid").list_get(idx)
        elif agg == "adsblol":
            res["adsblollink"] = (self._d.env_by_tags("adsblol_link").list_get(idx),)
        elif agg == "alive":
            res["alivemaplink"] = (self._d.env_by_tags("alivemaplink").list_get(idx),)

        return res

    def agg_status(self, agg):
        # print_err(f'agg_status(agg={agg})')
        if agg == "im":
            return json.dumps(self._im_status.check())

        self.cache_agg_status()

        res = dict()

        # collect the data retrieved in the threads, this works due do each agg status object having a lock
        for idx in [0] + self.micro_indices():
            if self._d.list_is_enabled(agg, idx):
                res[idx] = self.get_agg_status(agg, idx)

        return json.dumps(res)

    @check_restart_lock
    def sdr_setup(self):
        if request.method == "POST":
            return self.update()
        return render_template("sdr_setup.html")

    def visualization(self):
        if request.method == "POST":
            return self.update()

        # is this a stage2 site and you are looking at an individual micro feeder,
        # or is this a regular feeder?
        # m=0 indicates we are looking at an integrated/micro feeder or at the stage 2 local aggregator
        # m>0 indicates we are looking at a micro-proxy
        if self._d.is_enabled("stage2"):
            if request.args.get("m"):
                m = make_int(request.args.get("m"))
            else:
                m = 0
            site = self._d.env_by_tags("site_name").list_get(m)
            print_err("setting up visualization on a stage 2 system for site {site} (m={m})")
        else:
            site = ""
            m = 0
        return render_template("visualization.html", site=site, m=m)

    def set_channel(self, channel: str):
        with open(self._d.data_path / "update-channel", "w") as update_channel:
            print(channel, file=update_channel)

    def extract_channel(self) -> str:
        channel = self._d.env_by_tags("base_version").value
        if channel:
            match = re.search(r"\((.*?)\)", channel)
            if match:
                channel = match.group(1)
        branch = channel
        if channel in ["stable", "beta", "main"]:
            channel = ""
        if channel and not channel.startswith("origin/"):
            channel = f"origin/{channel}"
        return channel, branch

    def clear_range_outline(self, idx=0):
        suffix = self.uf_suffix(idx)
        print_err(f"resetting range outline for {suffix}")
        setGainPath = pathlib.Path(f"/run/adsb-feeder-{suffix}/readsb/setGain")

        self.waitSetGainRace()
        string2file(path=setGainPath, string=f"resetRangeOutline", verbose=True)

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
            report_issue("failure while setting root password, check logs for details")

    def unique_site_name(self, name, idx=-1):
        # make sure that a site name is unique - if the idx is given that's
        # the current value and excluded from the check
        existing_names = self._d.env_by_tags("site_name")
        names = [existing_names.list_get(n) for n in range(0, len(existing_names.value)) if n != idx]
        while name in names:
            name += "_"
        return name

    def get_base_info(self, n, do_import=False):
        ip = self._d.env_by_tags("mf_ip").list_get(n)
        port = self._d.env_by_tags("mf_port").list_get(n)
        if not port:
            port = "80"
        ip, triplet = mf_get_ip_and_triplet(ip)

        print_err(f"getting info from {ip}:{port} with do_import={do_import}", level=8)
        timeout = 2.0
        # try:
        if do_import:
            micro_settings, status = generic_get_json(f"http://{ip}:{port}/api/micro_settings", timeout=timeout)
            print_err(f"micro_settings API on {ip}:{port}: {status}, {micro_settings}")
            if status != 200 or micro_settings == None:
                # maybe we're running on 1099?
                port = "1099"
                micro_settings, status = generic_get_json(f"http://{ip}:{port}/api/micro_settings", timeout=timeout)
                print_err(f"micro_settings API on {ip}:{port}: {status}, {micro_settings}")

            if status == 200 and micro_settings != None:
                for key, value in micro_settings.items():
                    # when getting values from a microfeeder older than v2.1.3
                    if key == "lng":
                        key = "lon"
                    if key not in self.microfeeder_setting_tags:
                        continue
                    tags = key.split("--")
                    e = self._d.env_by_tags(tags)
                    if e:
                        e.list_set(n, value)
        base_info, status = generic_get_json(f"http://{ip}:{port}/api/base_info", timeout=timeout)
        if (status != 200 or base_info == None) and port == "80":
            # maybe we're running on 1099?
            port = "1099"
            base_info, status = generic_get_json(f"http://{ip}:{port}/api/base_info", timeout=timeout)
        if status == 200 and base_info != None:

            base_info_string = json.dumps(base_info)

            if self._last_base_info.get(ip) != base_info_string:
                self._last_base_info[ip] = base_info_string
                print_err(f"got {base_info} for {ip}")

            if do_import or not self._d.env_by_tags("site_name").list_get(n):
                # only accept the remote name if this is our initial import
                # after that the user may have overwritten it
                self._d.env_by_tags("site_name").list_set(n, self.unique_site_name(base_info["name"], n))
            self._d.env_by_tags("lat").list_set(n, base_info["lat"])
            # deal with backwards compatibility
            lon = base_info.get("lon", None)
            if lon is None:
                lon = base_info.get("lng", "")
            self._d.env_by_tags("lon").list_set(n, lon)
            self._d.env_by_tags("alt").list_set(n, base_info["alt"])
            self._d.env_by_tags("tz").list_set(n, base_info["tz"])
            self._d.env_by_tags("mf_version").list_set(n, base_info["version"])
            self._d.env_by_tags("mf_port").list_set(n, port)

            aap = base_info.get("airspy_at_port")
            rap = base_info.get("rtlsdr_at_port")
            dap = base_info.get("dump978_at_port")
            airspyurl = ""
            rtlsdrurl = ""
            dump978url = ""

            if aap and aap != 0:
                airspyurl = f"http://{ip}:{aap}"
            if rap and rap != 0:
                rtlsdrurl = f"http://{ip}:{rap}"
            if dap and dap != 0:
                dump978url = f"http://{ip}:{dap}/skyaware978"

            self._d.env_by_tags("airspyurl").list_set(n, airspyurl)
            self._d.env_by_tags("rtlsdrurl").list_set(n, rtlsdrurl)
            self._d.env_by_tags("978url").list_set(n, dump978url)

            self._d.env_by_tags("mf_brofm_capable").list_set(n, bool(base_info.get("brofm_capable")))

            return True
        #    except:
        #        pass
        print_err(f"failed to get base_info from micro feeder {n}")
        return False

    def check_remote_feeder(self, ip):
        print_err(f"check_remote_feeder({ip})")
        ip, triplet = mf_get_ip_and_triplet(ip)
        json_dict = {}
        for port in ["80", "1099"]:
            url = f"http://{ip}:{port}/api/base_info"
            print_err(f"checking remote feeder {url}")
            try:
                response = requests.get(url, timeout=5.0)
                print_err(f"response code: {response.status_code}")
                json_dict = response.json()
                print_err(f"json_dict: {type(json_dict)} {json_dict}")
            except:
                print_err(f"failed to check base_info from remote feeder {ip}:{port}")
            else:
                if response.status_code == 200:
                    # yay, this is an adsb.im feeder
                    # is it new enough to have the setting transfer?
                    url = f"http://{ip}:{port}/api/micro_settings"
                    print_err(f"checking remote feeder {url}")
                    try:
                        response = requests.get(url, timeout=5.0)
                    except:
                        print_err(f"failed to check micro_settings from remote feeder {ip}")
                        json_dict["micro_settings"] = False
                    else:
                        if response.status_code == 200:
                            # ok, we have a recent adsb.im version
                            json_dict["micro_settings"] = True
                        else:
                            json_dict["micro_settings"] = False
                    # does it support beast reduce optimized for mlat (brofm)?
                    json_dict["brofm_capable"] = bool(json_dict.get("brofm_capable"))

                # now return the json_dict which will give the caller all the relevant data
                # including whether this is a v2 or not
                return make_response(json.dumps(json_dict), 200)

        # ok, it's not a recent adsb.im version, it could still be a feeder
        uf = self._d.env_by_tags(["ultrafeeder", "container"]).value
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/usr/local/bin/readsb",
            f"{uf}",
            "--net",
            "--net-connector",
            f"{triplet}",
            "--quiet",
            "--auto-exit=2",
        ]
        print_err(f"running: {cmd}")
        try:
            response = subprocess.run(
                cmd,
                timeout=30.0,
                capture_output=True,
            )
            output = response.stderr.decode("utf-8")
        except:
            print_err("failed to use readsb in ultrafeeder container to check on remote feeder status")
            return make_response(json.dumps({"status": "fail"}), 200)
        if not re.search("input: Connection established", output):
            print_err(f"can't connect to beast_output on remote feeder: {output}")
            return make_response(json.dumps({"status": "fail"}), 200)
        return make_response(json.dumps({"status": "ok"}), 200)

    def import_graphs_and_history_from_remote(self, ip, port):
        print_err(f"importing graphs and history from {ip}")
        # first make sure that there isn't any old data that needs to be moved
        # out of the way
        if pathlib.Path(self._d.config_path / "ultrafeeder" / ip).exists():
            now = datetime.now().replace(microsecond=0).isoformat().replace(":", "-")
            shutil.move(
                self._d.config_path / "ultrafeeder" / ip,
                self._d.config_path / "ultrafeeder" / f"{ip}-{now}",
            )

        url = f"http://{ip}:{port}/backupexecutefull"
        # make tmpfile
        os.makedirs(self._d.config_path / "ultrafeeder", exist_ok=True)
        fd, tmpfile = tempfile.mkstemp(dir=self._d.config_path / "ultrafeeder")
        os.close(fd)

        # stream writing to a file with requests library is a pain so just use curl
        try:
            subprocess.run(
                ["curl", "-o", f"{tmpfile}", f"{url}"],
                check=True,
            )

            with zipfile.ZipFile(tmpfile) as zf:
                zf.extractall(path=self._d.config_path / "ultrafeeder" / ip)
            # deal with the duplicate "ultrafeeder in the path"
            shutil.move(
                self._d.config_path / "ultrafeeder" / ip / "ultrafeeder" / "globe_history",
                self._d.config_path / "ultrafeeder" / ip / "globe_history",
            )
            shutil.move(
                self._d.config_path / "ultrafeeder" / ip / "ultrafeeder" / "graphs1090",
                self._d.config_path / "ultrafeeder" / ip / "graphs1090",
            )

            print_err(f"done importing graphs and history from {ip}")
        except:
            report_issue(f"ERROR when importing graphs and history from {ip}")
        finally:
            os.remove(tmpfile)

    def setup_new_micro_site(
        self,
        key,
        uat,
        is_adsbim,
        brofm,
        do_import=False,
        do_restore=False,
        micro_data={},
    ):
        # the key here can be a readsb net connector triplet in the form ip,port,protocol
        # usually it's just the ip
        if key in {self._d.env_by_tags("mf_ip").list_get(i) for i in self.micro_indices()}:
            print_err(f"IP address {key} already listed as a micro site")
            return (False, f"IP address {key} already listed as a micro site")
        print_err(f"setting up a new micro site at {key} do_import={do_import} do_restore={do_restore}")
        n = self._d.env_by_tags("num_micro_sites").value

        # store the IP address so that get_base_info works
        # and assume port is 80 (get_base_info will fix that if it's wrong)
        self._d.env_by_tags("mf_ip").list_set(n + 1, key)
        self._d.env_by_tags("mf_port").list_set(n + 1, "80")
        self._d.env_by_tags("mf_brofm").list_set(n + 1, brofm)

        if not is_adsbim:
            # well that's unfortunate
            # we might get asked to create a UI for this at some point. Not today, though
            print_err(f"Micro feeder at {key} is not an adsb.im feeder")
            n += 1
            self._d.env_by_tags("num_micro_sites").value = n
            self._d.env_by_tags("site_name").list_set(n, self.unique_site_name(micro_data.get("micro_site_name", "")))
            self._d.env_by_tags("lat").list_set(n, micro_data.get("micro_lat", ""))
            self._d.env_by_tags("lon").list_set(n, micro_data.get("micro_lon", ""))
            self._d.env_by_tags("alt").list_set(n, micro_data.get("micro_alt", ""))
            self._d.env_by_tags("tz").list_set(n, "UTC")
            self._d.env_by_tags("mf_version").list_set(n, "not an adsb.im feeder")
            self._d.env_by_tags(["uat978", "is_enabled"]).list_set(n, uat)
            # accessing the microfeeder envs will create them
            for e in self._d.stage2_envs:
                e.list_get(n)
            # create fake cpu info for airnav
            create_fake_info([0] + self.micro_indices())
            self.plane_stats.append([])
            self.planes_seen_per_day.append(set())
            return (True, "")

        # now let's see if we can get the data from the micro feeder
        if self.get_base_info(n + 1, do_import=do_import):
            print_err(f"added new micro site {self._d.env_by_tags('site_name').list_get(n + 1)} at {key}")
            n += 1
            self._d.env_by_tags("num_micro_sites").value = n
            if do_restore:
                port = self._d.env_by_tags("mf_port").list_get(n)
                print_err(f"attempting to restore graphs and history from {key}:{port}")
                self.import_graphs_and_history_from_remote(key, port)
        else:
            # oh well, remove the IP address
            self._d.env_by_tags("mf_ip").list_remove()
            return (False, "unable to get base info from micro feeder")

        self._d.env_by_tags(["uat978", "is_enabled"]).list_set(n, uat)
        # accessing the microfeeder envs will create them
        for e in self._d.stage2_envs:
            e.list_get(n)
        # create fake cpu info for airnav
        create_fake_info([0] + self.micro_indices())
        self.plane_stats.append([])
        self.planes_seen_per_day.append(set())

        return (True, "")

    def remove_micro_site(self, num):
        # carefully shift everything down
        print_err(f"removing micro site {num}")

        # deal with plane stats
        for i in range(num, self._d.env_by_tags("num_micro_sites").value):
            self.plane_stats[i] = self.plane_stats[i + 1]
            self.planes_seen_per_day[i] = self.planes_seen_per_day[i + 1]

        self.plane_stats.pop()
        self.planes_seen_per_day.pop()

        # deal with env vars
        log_consistency_warning(False)
        for e in self._d.stage2_envs:
            print_err(f"shifting {e.name} down and deleting last element {e._value}")
            for i in range(num, self._d.env_by_tags("num_micro_sites").value):
                e.list_set(i, e.list_get(i + 1))
            while len(e._value) > self._d.env_by_tags("num_micro_sites").value:
                e.list_remove()
        self._d.env_by_tags("num_micro_sites").value -= 1
        log_consistency_warning(True)
        # now read them in to get a consistency warning if needed
        read_values_from_config_json(check_integrity=True)

    def edit_micro_site(self, num: int, site_name, ip, uat, brofm, new_idx: int):
        print_err(
            f"editing micro site {num} from {self._d.env_by_tags('site_name').list_get(num)} at "
            + f"{self._d.env_by_tags('mf_ip').list_get(num)} to {site_name} at {ip}"
            + (f" (new index {new_idx})" if new_idx != num else "")
        )
        if new_idx < 0 or new_idx > self._d.env_by_tags("num_micro_sites").value:
            print_err(f"invalid new index {new_idx}, ignoring")
            new_idx = num
        old_ip = self._d.env_by_tags("mf_ip").list_get(num)
        if old_ip != ip:
            if any([s in ip for s in ["/", "\\", ":", "*", "?", '"', "<", ">", "|", "..", "$"]]):
                print_err(f"found suspicious characters in IP address {ip} - let's not use this in a command")
                return (False, f"found suspicious characters in IP address {ip} - rejected")
            else:
                data_dir = pathlib.Path("/opt/adsb/config/ultrafeeder")
                if (data_dir / f"{old_ip}").exists() and (data_dir / f"{old_ip}").is_dir():
                    # ok, as one would hope, there's an Ultrafeeder directory for the old IP
                    if (data_dir / f"{ip}").exists():
                        print_err(f"can't move micro feeder data directory to {data_dir/ip} - it's already in use")
                        return (
                            False,
                            f"can't move micro feeder data directory to {data_dir/ip} - it's already in use",
                        )
                    try:
                        subprocess.run(
                            f"/opt/adsb/docker-compose-adsb rm --force --stop uf_{num} -t 20",
                            shell=True,
                        )
                    except:
                        print_err(f"failed to stop micro feeder {num}")
                        return (False, f"failed to stop micro feeder {num}")
                    print_err(f"moving micro feeder data directory from {data_dir/old_ip} to {data_dir/ip}")
                    try:
                        os.rename(data_dir / f"{old_ip}", data_dir / f"{ip}")
                    except:
                        print_err(
                            f"failed to move micro feeder data directory from {data_dir/old_ip} to {data_dir/ip}"
                        )
                        return (
                            False,
                            f"failed to move micro feeder data directory from {data_dir/old_ip} to {data_dir/ip}",
                        )
                # ok, this seems to have worked, let's update the environment variable IP
                self._d.env_by_tags("mf_ip").list_set(num, ip)

        if site_name != self._d.env_by_tags("site_name").list_get(num):
            print_err(f"update site name from {self._d.env_by_tags('site_name').list_get(num)} to {site_name}")
            self._d.env_by_tags("site_name").list_set(num, self.unique_site_name(site_name))
        if uat != self._d.env_by_tags("uat978").list_get(num):
            print_err(f"update uat978 from {self._d.env_by_tags('uat978').list_get(num)} to {uat}")
            self._d.env_by_tags("uat978").list_set(num, uat)
            self.setup_or_disable_uat(num)

        self._d.env_by_tags("mf_brofm").list_set(num, brofm)

        # now that all the editing has been done, move things around if needed
        if new_idx != num:
            print_err(f"moving micro site {num} to {new_idx}")

            for e in self._d.stage2_envs:
                e.list_move(num, new_idx)
            self.plane_stats.insert(new_idx, self.plane_stats.pop(num))
            self.planes_seen_per_day.insert(new_idx, self.planes_seen_per_day.pop(num))

        return (True, "")

    def setRtlGain(self):
        if self._d.is_enabled("stage2_nano") or self._d.env_by_tags("aggregator_choice").value == "nano":
            gaindir = pathlib.Path("/opt/adsb/config/nanofeeder/globe_history/autogain")
            setGainPath = pathlib.Path("/run/adsb-feeder-nanofeeder/readsb/setGain")
        else:
            gaindir = pathlib.Path("/opt/adsb/config/ultrafeeder/globe_history/autogain")
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
        if self._d.env_by_tags("aggregator_choice").value in ["micro", "nano"]:
            ac_db = False
            self._d.env_by_tags(["mlathub_disable"]).value = True
        else:
            ac_db = True
            self._d.env_by_tags(["mlathub_disable"]).value = False

        if self._memtotal < 900000:
            ac_db = False
            # save 100 MB of memory for low memory setups

        self._d.env_by_tags(["tar1090_ac_db"]).value = ac_db

        # make sure the avahi alias service runs on an adsb.im image
        self.set_hostname_and_enable_mdns(self._d.env_by_tags("site_name").list_get(0))

        stage2_nano = False

        if self._d.is_enabled("stage2") and (
            self._d.env_by_tags("1090serial").value or self._d.env_by_tags("978serial").value
            or self._d.env_by_tags("aisserial").value
        ):
            # this is special - the user has declared this a stage2 feeder, yet
            # appears to be setting up an SDR - let's force this to be treated as
            # nanofeeder

            self._d.env_by_tags("stage2_nano").value = True
            self._d.env_by_tags("nano_beast_port").value = "30035"
            self._d.env_by_tags("nano_beastreduce_port").value = "30036"
        else:
            self._d.env_by_tags("stage2_nano").value = False
            self._d.env_by_tags("nano_beast_port").value = "30005"
            self._d.env_by_tags("nano_beastreduce_port").value = "30006"

        for sitenum in [0] + self.micro_indices():
            site_name = self._d.env_by_tags("site_name").list_get(sitenum)
            sanitized = "".join(c if c.isalnum() or c in "-_." else "_" for c in site_name)
            self._d.env_by_tags("site_name_sanitized").list_set(sitenum, sanitized)

            # fixup altitude mishaps by stripping the value
            # strip meter units and whitespace for good measure
            alt = self._d.env_by_tags("alt").list_get(sitenum)
            alt_m = alt.strip().strip("m").strip()
            self._d.env_by_tags("alt").list_set(sitenum, alt_m)

            # make sure use_route_api is populated with the default:
            self._d.env_by_tags("route_api").list_get(sitenum)

            # make sure the uuids are populated:
            if not self._d.env_by_tags("adsblol_uuid").list_get(sitenum):
                self._d.env_by_tags("adsblol_uuid").list_set(sitenum, str(uuid4()))
            if not self._d.env_by_tags("ultrafeeder_uuid").list_get(sitenum):
                self._d.env_by_tags("ultrafeeder_uuid").list_set(sitenum, str(uuid4()))

            for agg in [submit_key.replace("--submit", "") for submit_key in self._other_aggregators.keys()]:
                if self._d.env_by_tags([agg, "is_enabled"]).list_get(sitenum):
                    # disable other aggregators for the combined data of stage2
                    if sitenum == 0 and self._d.is_enabled("stage2"):
                        self._d.env_by_tags([agg, "is_enabled"]).list_set(sitenum, False)
                    # disable other aggregators if their key isn't set
                    if self._d.env_by_tags([agg, "key"]).list_get(sitenum) == "":
                        print_err(f"empty key, disabling: agg: {agg}, sitenum: {sitenum}")
                        self._d.env_by_tags([agg, "is_enabled"]).list_set(sitenum, False)

        # explicitely enable mlathub unless disabled
        self._d.env_by_tags(["mlathub_enable"]).value = not self._d.env_by_tags(["mlathub_disable"]).value

        if self._d.env_by_tags("aggregator_choice").value in ["micro", "nano"]:
            self._d.env_by_tags("beast-reduce-optimize-for-mlat").value = True
        else:
            self._d.env_by_tags("beast-reduce-optimize-for-mlat").value = False

        if self._d.env_by_tags("tar1090_image_config_link").value != "":
            self._d.env_by_tags("tar1090_image_config_link").value = (
                f"http://HOSTNAME:{self._d.env_by_tags('webport').value}/"
            )

        if self._d.is_enabled("stage2"):
            # for stage2 tar1090port is used for the webproxy
            # move the exposed port for the combined ultrafeeder to 8078 to avoid a port conflict
            self._d.env_by_tags("tar1090portadjusted").value = 8078
            # similarly, move the exposed port for a local nanofeeder to 8076 to avoid another port conflict
            self._d.env_by_tags("nanotar1090portadjusted").value = 8076

            # set unlimited range for the stage2 tar1090
            self._d.env_by_tags("max_range").list_set(0, 0)

            for sitenum in [0] + self.micro_indices():
                self.setup_or_disable_uat(sitenum)

        else:
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

        # make all the smart choices for plugged in SDRs - unless we are a stage2 that hasn't explicitly requested SDR support
        # only run this for initial setup or when the SDR setup is requested via the interface
        if (not self._d.is_enabled("stage2") or self._d.is_enabled("stage2_nano")) and not self._d.env_by_tags(
            "sdrs_locked"
        ).value:
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

        if self._d.env_by_tags("stage2_nano").value:
            do978 = bool(self._d.env_by_tags("978serial").value)

            # this code is here and not further up so get_base_info knows
            # about the various URLs for 978 / airspy / 1090
            log_consistency_warning(False)
            self.setup_new_micro_site(
                "local",
                uat=do978,
                is_adsbim=True,
                brofm=False,
                do_import=True,
                do_restore=False,
            )
            # adjust 978
            for i in self.micro_indices():
                if self._d.env_by_tags("mf_ip").list_get(i) == "local":
                    self._d.env_by_tags(["uat978", "is_enabled"]).list_set(i, do978)
            log_consistency_warning(True)
            read_values_from_config_json(check_integrity=True)

        # set all of the ultrafeeder config data up
        self.setup_ultrafeeder_args()

        # finally, check if this has given us enough configuration info to
        # start the containers
        if self.base_is_configured() or self._d.is_enabled("stage2"):
            self._d.env_by_tags(["base_config", "is_enabled"]).value = True
            if self.at_least_one_aggregator():
                self._d.env_by_tags("aggregators_chosen").value = True

            if self._d.is_feeder_image and not self._d.env_by_tags("journal_configured").value:
                try:
                    cmd = "/opt/adsb/scripts/journal-set-volatile.sh"
                    print_err(cmd)
                    subprocess.run(cmd, shell=True, timeout=5.0)
                    self.update_journal_state()
                    self._d.env_by_tags("journal_configured").value = True
                except:
                    pass

        for i in self.micro_indices():
            create_stage2_yml_files(i, self._d.env_by_tags("mf_ip").list_get(i))

        # check if we need the stage2 multiOutline job
        if self._d.is_enabled("stage2"):
            if "multi_outline" not in self._background_tasks:
                self.push_multi_outline()
                self._background_tasks["multi_outline"] = (
                    Background(60, self.push_multi_outline))
        else:
            self._background_tasks.pop("multi_outline", None)

        self.generate_agg_structure()

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
    def update(self):
        description = """
            This is the one endpoint that handles all the updates coming in from the UI.
            It walks through the form data and figures out what to do about the information provided.
        """
        # let's try and figure out where we came from - for reasons I don't understand
        # the regexp didn't capture the site number, so let's do this the hard way
        extra_args = ""
        referer = request.headers.get("referer")
        m_arg = referer.rfind("?m=")
        if m_arg > 0:
            arg = make_int(referer[m_arg + 3 :])
        else:
            arg = 0
        if arg in self.micro_indices():
            sitenum = arg
            site = self._d.env_by_tags("site_name").list_get(sitenum)
            extra_args = f"?m={sitenum}"
        else:
            site = ""
            sitenum = 0
        allow_insecure = not self.check_secure_image()
        print_err(f"handling input from {referer} and site # {sitenum} / {site} (allow insecure is {allow_insecure})")
        # in the HTML, every input field needs to have a name that is concatenated by "--"
        # and that matches the tags of one Env
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
                if key == "add_micro" or key == "add_other" or key.startswith("import_micro"):
                    # user has clicked Add micro feeder on Stage 2 page
                    # grab the IP that we know the user has provided
                    ip = form.get("add_micro_feeder_ip")
                    uat = form.get("micro_uat")
                    brofm = is_true(form.get("micro_reduce")) and key != "add_other"
                    is_adsbim = key != "add_other"
                    micro_data = {}
                    if not is_adsbim:
                        for mk in [
                            "micro_site_name",
                            "micro_lat",
                            "micro_lon",
                            "micro_alt",
                        ]:
                            micro_data[mk] = form.get(mk)
                    do_import = key.startswith("import_micro")
                    do_restore = key == "import_micro_full"
                    log_consistency_warning(False)
                    status, message = self.setup_new_micro_site(
                        ip,
                        uat=is_true(uat),
                        is_adsbim=is_adsbim,
                        brofm=brofm,
                        do_import=do_import,
                        do_restore=do_restore,
                        micro_data=micro_data,
                    )
                    log_consistency_warning(True)
                    read_values_from_config_json(check_integrity=True)
                    if status:
                        print_err("successfully added new micro site")
                        self._next_url_from_director = url_for("stage2")
                    else:
                        print_err(f"failed to add new micro site: {message}")
                        flash(f"failed to add new micro site: {message}", "danger")
                        next_url = url_for("stage2")
                    continue
                if key.startswith("remove_micro_"):
                    # user has clicked Remove micro feeder on Stage 2 page
                    # grab the micro feeder number that we know the user has provided
                    num = int(key[len("remove_micro_") :])
                    name = self._d.env_by_tags("site_name").list_get(num)
                    self.remove_micro_site(num)
                    flash(f"Removed micro site {name}", "success")
                    self._next_url_from_director = url_for("stage2")
                    continue
                if key.startswith("edit_micro_"):
                    # user has clicked Edit micro feeder on Stage 2 page
                    # grab the micro feeder number that we know the user has provided
                    num = int(key[len("edit_micro_") :])
                    return render_template("stage2.html", edit_index=num)
                if key.startswith("cancel_edit_micro_"):
                    # discard changes
                    flash(f"Cancelled changes", "success")
                    return redirect(url_for("stage2"))
                if key.startswith("save_edit_micro_"):
                    # save changes
                    num = int(key[len("save_edit_micro_") :])
                    success, message = self.edit_micro_site(
                        num,
                        form.get(f"site_name_{num}"),
                        form.get(f"mf_ip_{num}"),
                        form.get(f"mf_uat_{num}"),
                        form.get(f"mf_brofm_{num}"),
                        make_int(form.get(f"site_order_{num}")),
                    )
                    if success:
                        self._next_url_from_director = url_for("stage2")
                    else:
                        flash(message, "error")
                        next_url = url_for("stage2")
                    continue
                if key == "set_stage2_data":
                    # just grab the new data and go back
                    next_url = url_for("stage2")
                if key == "turn_off_stage2":
                    # let's just switch back
                    self._d.env_by_tags("stage2").value = False
                    try:
                        task = self._background_tasks.pop("multi_outline")
                        task.cancel()
                    except KeyError:
                        pass
                    self._d.env_by_tags("aggregators_chosen").value = False
                    self._d.env_by_tags("aggregator_choice").value = ""

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
                if key.startswith("update_feeder_aps"):
                    channel = key.rsplit("_", 1)[-1]
                    if channel == "branch":
                        channel, _ = self.extract_channel()
                    return self.do_feeder_update(channel)
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
                            report_issue(
                                "at this point we only allow the --login-server=<server> argument; "
                                "please let us know at the Zulip support link why you need "
                                f"this to support {ts_cli_switch}"
                            )
                            continue
                        print_err(f"login server arg is {ts_cli_value}")
                        match = re.match(
                            r"^https?://[-a-zA-Z0-9._\+~=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?::[0-9]{1,5})?(?:[-a-zA-Z0-9()_\+.~/=]*)$",
                            ts_cli_value,
                        )
                        if not match:
                            report_issue(f"the login server URL didn't make sense {ts_cli_value}")
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
                        report_issue("exception trying to set up tailscale - giving up")
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
                        report_issue(f"ERROR: tailscale didn't provide a login link within 30 seconds")
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
                if key in self._other_aggregators:
                    l_sitenum = 0
                    if value.startswith("stay-"):
                        l_sitenum = make_int(value[5:])
                        l_site = self._d.env_by_tags("site_name").list_get(l_sitenum)
                        if not l_site:
                            print_err(f"can't find a site for sitenum {l_sitenum}")
                            l_sitenum = 0
                        else:
                            print_err(f"found other aggregator {key} for site {l_site} sitenum {l_sitenum}")
                    is_successful = False
                    base = key.replace("--submit", "")
                    aggregator_arguments = [form.get(f"{base}--key", None)]
                    if base == "flightradar":
                        uat_arg = form.get(f"{base}_uat--key", None)
                        aggregator_arguments[0] += f"::{uat_arg}"
                    if base == "opensky":
                        user = form.get(f"{base}--user", None)
                        aggregator_arguments[0] += f"::{user}"
                    if base == "sdrmap":
                        user = form.get(f"{base}--user", None)
                        aggregator_arguments[0] += f"::{user}"
                    aggregator_object = self._other_aggregators[key]
                    print_err(f"got aggregator object {aggregator_object} -- activating for sitenum {l_sitenum}")
                    try:
                        is_successful = aggregator_object._activate(*aggregator_arguments, l_sitenum)
                    except Exception as e:
                        print_err(f"error activating {key}: {e}")
                    if not is_successful:
                        report_issue(f"did not successfully enable {base}")

                    # immediately start the containers in case the user doesn't click "apply settings" after requesting a key
                    seen_go = True
                    # go back to the page we were on after applying settings
                    self._next_url_from_director = request.url

                continue
            # now handle other form input
            if key == "clear_range" and value == "1":
                self.clear_range_outline(sitenum)
                continue
            if key == "resetgain" and value == "1":
                # tell the ultrafeeder container to restart the autogain processing
                if self._d.is_enabled("stage2_nano"):
                    cmdline = "docker exec nanofeeder /usr/local/bin/autogain1090 reset"
                else:
                    cmdline = "docker exec ultrafeeder /usr/local/bin/autogain1090 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    report_issue("Error running Ultrafeeder autogain reset")
                continue
            if key == "resetuatgain" and value == "1":
                # tell the dump978 container to restart the autogain processing
                cmdline = "docker exec dump978 /usr/local/bin/autogain978 reset"
                try:
                    subprocess.run(cmdline, timeout=5.0, shell=True)
                except:
                    report_issue("Error running UAT autogain reset")
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
                    report_issue(f"failed to enable ssh - check the logs for details")
                    print_err(f"failed to enable ssh: {output}")
                continue
            e = self._d.env_by_tags(key.split("--"))
            if e:
                if allow_insecure and key == "zerotierid":
                    try:
                        subprocess.call("/usr/bin/systemctl unmask zerotier-one", shell=True)
                        subprocess.call("/usr/bin/systemctl enable --now zerotier-one", shell=True)
                        sleep(5.0)  # this gives the service enough time to get ready
                        subprocess.call(
                            ["/usr/sbin/zerotier-cli", "join", f"{value}"],
                        )
                    except:
                        report_issue("exception trying to set up zerorier - giving up")
                if key in {"lat", "lon"}:
                    # remove letters, spaces, degree symbols
                    value = str(float(re.sub("[a-zA-Z° ]", "", value)))
                if key == "tz":
                    self.set_tz(value)
                    continue
                if key == "uatgain":
                    if value == "" or value == "auto":
                        value = "autogain"
                if key == "gain":
                    if value == "":
                        value = "auto"
                # deal with the micro feeder and stage2 initial setup
                if key == "aggregator_choice" and value in ["micro", "nano"]:
                    self._d.env_by_tags("aggregators_chosen").value = True
                    # disable all the aggregators in micro mode
                    for ev in self._d._env:
                        if "is_enabled" in ev.tags:
                            if "other_aggregator" in ev.tags or "ultrafeeder" in ev.tags:
                                ev.list_set(0, False)
                    if value == "nano" and self._d.is_feeder_image:
                        # make sure we don't log to disk at all
                        try:
                            subprocess.call("bash /opt/adsb/scripts/journal-set-volatile.sh", shell=True, timeout=5)
                            print_err("switched to volatile journal")
                        except:
                            print_err("exception trying to switch to volatile journal - ignoring")
                if key == "aggregator_choice" and value == "stage2":
                    next_url = url_for("stage2")
                    self._d.env_by_tags("stage2").value = True
                    if "multi_outline" not in self._background_tasks:
                        self.push_multi_outline()
                        self._background_tasks["multi_outline"] = (
                            Background(60, self.push_multi_outline))
                    unique_name = self.unique_site_name(form.get("site_name"), 0)
                    self._d.env_by_tags("site_name").list_set(0, unique_name)
                # if this is a regular feeder and the user is changing to 'individual' selection
                # (either in initial setup or when coming back to that setting later), show them
                # the aggregator selection page next
                if (
                    key == "aggregator_choice"
                    and not self._d.is_enabled("stage2")
                    and value == "individual"
                    and self._d.env_by_tags("aggregator_choice").value != "individual"
                ):
                    # show the aggregator selection
                    next_url = url_for("aggregators")
                # finally, painfully ensure that we remove explicitly asigned SDRs from other asignments
                # this relies on the web page to ensure that each SDR is only asigned on purpose
                # the key in quesiton will be explicitely set and does not need clearing
                # empty string means no SDRs assigned to that purpose
                purposes = self._sdrdevices.purposes()
                if key in purposes and value != "":
                    for clear_key in purposes:
                        if clear_key != key and value == self._d.env_by_tags(clear_key).value:
                            print_err(f"clearing: {str(clear_key)} old value: {value}")
                            self._d.env_by_tags(clear_key).value = ""
                # when dealing with micro feeder aggregators, we need to keep the site number
                # in mind
                tags = key.split("--")
                if sitenum > 0 and "is_enabled" in tags:
                    print_err(f"setting up stage2 micro site number {sitenum}: {key}")
                    self._d.env_by_tags("aggregators_chosen").value = True
                    self._d.env_by_tags(tags).list_set(sitenum, is_true(value))
                else:
                    if type(e._value) == list:
                        e.list_set(sitenum, value)
                    else:
                        e.value = value
                if key == "site_name":
                    unique_name = self.unique_site_name(value, sitenum)
                    self._d.env_by_tags("site_name").list_set(sitenum, unique_name)
        # done handling the input data
        # what implied settings do we have (and could we simplify them?)

        self.handle_implied_settings()

        # write all this out to the .env file so that a docker-compose run will find it
        self.write_envfile()

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

            self._system._restart.bg_run(cmdline="/opt/adsb/docker-compose-start", silent=False)
            return render_template("/restarting.html", extra_args=extra_args)
        print_err("base config not completed", level=2)
        return redirect(url_for("director"))

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
        if self._d.is_feeder_image:
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
        # if we are on a branch that's neither stable nor beta, pass the value to the template
        # so that a third update button will be shown - separately, pass along unconditional
        # information on the current branch the user is on so we can show that in the explanatory text.
        channel, current_branch = self.extract_channel()
        return render_template(
            "systemmgmt.html",
            tailscale_running=tailscale_running,
            zerotier_running=zerotier_running,
            rpw=self.rpw,
            channel=channel,
            current_branch=current_branch,
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
            self._parse_porttracker_form_data()
            return self.update()

        def uf_enabled(tag, m=0):
            # stack_info(f"tags are {type(tag)} {tag}")
            if type(tag) == str:
                tag = [tag]
            if type(tag) != list:
                print_err(f"PROBLEM::: tag is {type(tag)}")
            return "checked" if self._d.list_is_enabled(["ultrafeeder"] + tag, idx=m) else ""

        def others_enabled(tag, m=0):
            # stack_info(f"tags are {type(tag)} {tag}")
            if type(tag) == str:
                tag = [tag]
            if type(tag) != list:
                print_err(f"PROBLEM::: tag is {type(tag)}")
            return "checked" if self._d.list_is_enabled(["other_aggregator"] + tag, idx=m) else ""

        # is this a stage2 site and you are looking at an individual micro feeder,
        # or is this a regular feeder? If we have a query argument m that is a non-negative
        # number, then yes it is
        if self._d.is_enabled("stage2"):
            print_err("setting up aggregators on a stage 2 system")
            try:
                m = int(request.args.get("m"))
            except:
                m = 0
            if m == 0:  # do not set up aggregators for the aggregated feed
                if self._d.env_by_tags("num_micro_sites").value == "0":
                    # things aren't set up yet, bail out to the stage 2 setup
                    return redirect(url_for("stage2"))
                else:
                    # data sharing for the combined data is impossible,
                    # redirect instead of showing the data sharing page
                    return redirect(url_for("director"))
            site = self._d.env_by_tags("site_name").list_get(m)
            print_err(f"setting up aggregators for site {site} (m={m})")
        else:
            site = ""
            m = 0
        return render_template(
            "aggregators.html",
            uf_enabled=uf_enabled,
            others_enabled=others_enabled,
            site=site,
            m=str(m),
            piastatport=str(m * 1000 + make_int(self._d.env_by_tags("piastatport").value)),
        )

    def _parse_porttracker_form_data(self):
        site_num = request.form["site_num"]
        porttracker = self._other_aggregators["porttracker"]
        if request.form["porttracker-is-enabled"] == "0":
            porttracker._deactivate(site_num)
            print_err(f"Deactivated {porttracker}.")
            return
        try:
            station_id = request.form["porttracker-station-id"]
            data_sharing_key = request.form["porttracker-data-sharing-key"]
            mqtt_protocol = request.form["porttracker-mqtt-protocol"]
            mqtt_host = request.form["porttracker-mqtt-host"]
            mqtt_port = request.form["porttracker-mqtt-port"]
            mqtt_username = request.form["porttracker-mqtt-username"]
            mqtt_password = request.form["porttracker-mqtt-password"]
            mqtt_topic = request.form["porttracker-mqtt-topic"]
        except KeyError as e:
            report_issue(
                f"Can't activate Porttracker: missing key {e}.", level=0)
            return
        try:
            porttracker._activate(
                station_id, data_sharing_key, mqtt_protocol, mqtt_host,
                mqtt_port, mqtt_username, mqtt_password, mqtt_topic, site_num)
            print_err(f"Activated {porttracker} for site_num {site_num}.")
        except:
            report_issue(f"Error activating Porttracker.", level=1)

    @check_restart_lock
    def director(self):
        # figure out where to go:
        if request.method == "POST":
            return self.update()
        if not self._d.is_enabled("base_config"):
            print_err(f"director redirecting to setup, base_config not completed")
            return self.setup()
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
            return self.sdr_setup()

        used_serials = [self._d.env_by_tags(purpose).value for purpose in ["978serial","1090serial","aisserial"]]
        used_serials = [serial for serial in used_serials if serial != ""]
        if any([serial not in available_serials for serial in used_serials]):
            print_err(f"used serials: {used_serials}")
            print_err(f"available serials: {available_serials}")
            print_err("director redirecting to sdr_setup: at least one used device is not present")
            return self.sdr_setup()

        # if the user chose to individually pick aggregators but hasn't done so,
        # they need to go to the aggregator page
        if self.at_least_one_aggregator() or self._d.env_by_tags("aggregators_chosen"):
            return self.index()
        print_err("director redirecting to aggregators: to be configured")
        return self.aggregators()

    def reset_planes_seen_per_day(self):
        self.planes_seen_per_day = [set() for i in [0] + self.micro_indices()]

    def load_planes_seen_per_day(self):
        # set limit on how many days of statistics to keep
        self.plane_stats_limit = 14
        # we base this on UTC time so it's comparable across time zones
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        self.reset_planes_seen_per_day()
        self.plane_stats_day = start_of_day.timestamp()
        self.plane_stats = [[] for i in [0] + self.micro_indices()]
        try:
            with gzip.open("/opt/adsb/adsb_planes_seen_per_day.json.gz", "r") as f:
                planes = json.load(f)
                ts = planes.get("timestamp", 0)
                if ts >= start_of_day.timestamp():
                    # ok, this dump is from today
                    planelists = planes.get("planes")
                    for i in [0] + self.micro_indices():
                        # json can't store sets, so we use list on disk, but sets in memory
                        self.planes_seen_per_day[i] = set(planelists[i])

                planestats = planes.get("stats")
                for i in [0] + self.micro_indices():
                    self.plane_stats[i] = planestats[i]

                diff = start_of_day.timestamp() - ts
                if diff > 0:
                    print_err(f"loading planes_seen_per_day: file not from this utc day")
                    days = math.ceil(diff / (24 * 60 * 60))
                    if days > 0:
                        days -= 1
                        planelists = planes.get("planes")
                        for i in [0] + self.micro_indices():
                            self.plane_stats[i].insert(0, len(planelists[i]))
                    if days > 0:
                        print_err(f"loading planes_seen_per_day: padding with {days} zeroes")
                    while days > 0:
                        days -= 1
                        for i in [0] + self.micro_indices():
                            self.plane_stats[i].insert(0, 0)

                for i in [0] + self.micro_indices():
                    while len(self.plane_stats[i]) > self.plane_stats_limit:
                        self.plane_stats[i].pop()

        except:
            print_err(f"error loading planes_seen_per_day:\n{traceback.format_exc()}")
            pass

    def write_planes_seen_per_day(self):
        # we want to make absolutely sure we don't throw any errors here as this is
        # called during termination
        try:
            # json can't store sets, so we use list on disk, but sets in memory
            planelists = [list(self.planes_seen_per_day[i]) for i in [0] + self.micro_indices()]
            planes = {"timestamp": int(time.time()), "planes": planelists, "stats": self.plane_stats}
            planes_json = json.dumps(planes, indent=2)

            path = "/opt/adsb/adsb_planes_seen_per_day.json.gz"
            tmp = path + ".tmp"
            with gzip.open(tmp, "w") as f:
                f.write(planes_json.encode("utf-8"))
            os.rename(tmp, path)
            print_err("wrote planes_seen_per_day")
        except Exception as e:
            print_err(f"error writing planes_seen_per_day:\n{traceback.format_exc()}")
            pass

    def get_current_planes(self, idx):
        planes = set()
        path = "/run/adsb-feeder-" + self.uf_suffix(idx) + "/readsb/aircraft.json"
        try:
            with open(path) as f:
                aircraftdict = json.load(f)
                aircraft = aircraftdict.get("aircraft", [])
                planes = set([plane["hex"] for plane in aircraft if not plane["hex"].startswith("~")])
        except:
            pass
        return planes

    def track_planes_seen_per_day(self):
        # we base this on UTC time so it's comparable across time zones
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        ultrafeeders = [0] + self.micro_indices()
        if self.plane_stats_day != start_of_day.timestamp():
            self.plane_stats_day = start_of_day.timestamp()
            print_err("planes_seen_per_day: new day!")
            # it's a new day, store and then reset the data
            for i in ultrafeeders:
                self.plane_stats[i].insert(0, len(self.planes_seen_per_day[i]))
                if len(self.plane_stats[i]) > self.plane_stats_limit:
                    self.plane_stats[i].pop()
            self.reset_planes_seen_per_day()
            pv = self._d.previous_version
            self._d.previous_version = "check-in"
            self._im_status.check(True)
            self._d.previous_version = pv
        if now.minute == 0:
            # this function is called once every minute - so this triggers once an hour
            # write the data to disk every hour
            self.write_planes_seen_per_day()
        for i in ultrafeeders:
            # using sets it's really easy to keep track of what we've seen
            self.planes_seen_per_day[i] |= self.get_current_planes(i)

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
        # track the number of planes seen per day - that's a fun statistic to have and
        # readsb makes it a bit annoying to get that
        self.track_planes_seen_per_day()

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

        if self._d.previous_version:
            print_err(f"sending previous version: {self._d.previous_version}")
            self._im_status.check()

    @check_restart_lock
    def index(self):
        # if we get to show the feeder homepage, the user should have everything figured out
        # and we can remove the pre-installed ssh-keys and password
        if os.path.exists("/opt/adsb/adsb.im.passwd.and.keys"):
            print_err("removing pre-installed ssh-keys, overwriting root password")
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
        # there are many other boards I should list here - but Pi 3 and Pi Zero are probably the most common
        stage2_suggestion = board.startswith("Raspberry") and not (
            board.startswith("Raspberry Pi 4") or board.startswith("Raspberry Pi 5")
        )
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

        self.cache_agg_status()

        channel, current_branch = self.extract_channel()
        return render_template(
            "index.html",
            aggregators=self.agg_structure,
            agg_tables=list({entry[4] for entry in self.agg_structure}),
            local_address=local_address,
            tailscale_address=self.tailscale_address,
            zerotier_address=self.zerotier_address,
            stage2_suggestion=stage2_suggestion,
            matrix=self.agg_matrix,
            compose_up_failed=compose_up_failed,
            channel=channel,
        )

    @check_restart_lock
    def setup(self):
        if request.method == "POST" and (
            request.form.get("submit") == "go" or request.form.get("set_stage2_data") == "go"
        ):
            return self.update()
        # is this a stage2 feeder?
        if self._d.is_enabled("stage2"):
            return render_template("stage2.html")
        # make sure DNS works
        self.update_dns_state()
        return render_template("setup.html", mem=self._memtotal)

    def micro_indices(self):
        if self._d.is_enabled("stage2"):
            # micro proxies start at 1
            return list(range(1, self._d.env_by_tags("num_micro_sites").value + 1))
        else:
            return []

    @check_restart_lock
    def stage2(self):
        if request.method == "POST":
            return self.update()
        return render_template("stage2.html")

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
                report_issue(f"failed to upload logs")
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
                report_issue(f"failed to upload logs")
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

    def overview(self):
        board = self._d.env_by_tags("board_name").value
        base = self._d.env_by_tags("image_name").value
        version = self._d.env_by_tags("base_version").value
        containers = [
            self._d.env_by_tags(["container", container]).value
            for container in self._d.tag_for_name.values()
            if self._d.is_enabled(container)
            or container in ["ultrafeeder", "shipfeeder"]]
        return render_template(
            "overview.html",
            board=board,
            base=base,
            version=version,
            containers=containers,
            sdrs=self._sdrdevices.sdrs,
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
    def feeder_update(self, channel):
        if channel not in ["stable", "beta"]:
            return "This update functionality is only available for stable and beta"
        return self.do_feeder_update(channel)

    # internal helper function to start the feeder update
    def do_feeder_update(self, channel):
        self.set_channel(channel)
        print_err(f"updating feeder to {channel} channel")
        # the webinterface needs to stay in the waiting state until the feeder-update stops it
        # because this is not guaranteed otherwise, add a sleep to the command running in the
        # background
        self._system._restart.bg_run(cmdline="systemctl start adsb-feeder-update.service; sleep 30")
        self.exiting = True
        return render_template("/restarting.html")


def create_stage2_yml_from_template(stage2_yml_name, n, ip, template_file):
    if n:
        with open(template_file, "r") as stage2_yml_template:
            with open(stage2_yml_name, "w") as stage2_yml:
                stage2_yml.write(stage2_yml_template.read().replace("STAGE2NUM", f"{n}").replace("STAGE2IP", ip))
    else:
        print_err(f"could not find micro feedernumber in {stage2_yml_name}")


def create_stage2_yml_files(n, ip):
    if not n:
        return
    print_err(f"create_stage2_yml_files(n={n}, ip={ip})")
    for yml_file, template in [
        [f"stage2_micro_site_{n}.yml", "stage2.yml"],
        [f"1090uk_{n}.yml", "1090uk_stage2_template.yml"],
        [f"ah_{n}.yml", "ah_stage2_template.yml"],
        [f"fa_{n}.yml", "fa_stage2_template.yml"],
        [f"fr24_{n}.yml", "fr24_stage2_template.yml"],
        [f"os_{n}.yml", "os_stage2_template.yml"],
        [f"pf_{n}.yml", "pf_stage2_template.yml"],
        [f"pw_{n}.yml", "pw_stage2_template.yml"],
        [f"rb_{n}.yml", "rb_stage2_template.yml"],
        [f"rv_{n}.yml", "rv_stage2_template.yml"],
        [f"sdrmap_{n}.yml", "sdrmap_stage2_template.yml"],
    ]:
        create_stage2_yml_from_template(f"/opt/adsb/config/{yml_file}", n, ip, f"/opt/adsb/config/{template}")


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
        data = Data()
        self._hotspot_app = HotspotApp(data, self._on_wifi_credentials)
        self._hotspot = hotspot.make_hotspot(self._on_wifi_test_status)
        self._adsb_im = AdsbIm(data, self._hotspot_app)
        self._hotspot_timer = None
        self._keep_running = True
        self._logger = logging.getLogger(type(self).__name__)
        self._ensure_config_exists()

    def _ensure_config_exists(self):
        # setup the config folder if that hasn't happened yet
        # this is designed for two scenarios:
        # (a) /opt/adsb/config is a subdirectory of /opt/adsb (that gets created if necessary)
        #     and the config files are moved to reside there
        # (b) prior to starting this app, /opt/adsb/config is created as a symlink to the
        #     OS designated config dir (e.g., /mnt/dietpi_userdata/adsb-feeder) and the config
        #     files are moved to that place instead
        if not CONFIG_DIR.exists():
            CONFIG_DIR.mkdir()
            env_file = ADSB_DIR / ".env"
            if env_file.exists():
                shutil.move(env_file, CONFIG_DIR / ".env")

        moved = False
        for config_file in ADSB_DIR.glob("*.yml"):
            if config_file.exists():
                moved = True
                new_file = CONFIG_DIR / config_file.name
                shutil.move(config_file, new_file)
        if moved:
            self._logger.info(f"moved yml files to {CONFIG_DIR}")

        if not pathlib.Path(CONFIG_DIR / ".env").exists():
            # I don't understand how that could happen
            shutil.copyfile(
                ADSB_DIR / "docker.image.versions", CONFIG_DIR / ".env")

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
        AdsbIm(Data(), None).update_config()
        sys.exit(0)

    shutdown_event = threading.Event()

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down.")
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
