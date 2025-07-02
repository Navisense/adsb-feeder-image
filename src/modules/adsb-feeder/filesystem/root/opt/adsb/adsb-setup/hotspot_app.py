import abc
import collections
import functools as ft
import http.client
import json
import logging
import pathlib
import queue
import re
import signal
import socket
import threading
import time

import flask
from flask import request

import fakedns
import utils.data
import utils.util
import utils.wifi


def make_hotspot(wlan):
    baseos = utils.util.get_baseos()
    if baseos == "dietpi":
        return NetworkingHotspot(wlan)
    elif baseos in ["raspbian", "postmarketos"]:
        return NetworkManagerHotspot(wlan)
    else:
        raise ValueError(f"unknown OS {baseos}")


class ConnectivityMonitor:
    """
    Monitor that regularly checks whether we have internet access.

    If the state changes, puts an item into its event queue.
    """
    NETWORK_TIMEOUT = 2

    def __init__(self, event_queue, *, check_interval):
        self._event_queue = event_queue
        self.check_interval = check_interval
        self._keep_running = None
        self._check_timer = None
        self._check_timer_lock = threading.Lock()
        self._checks = {
            "google_quad8_https_head": ft.partial(
                self._check_https_head, "8.8.8.8"),
            "cloudflare_quad1_https_head": ft.partial(
                self._check_https_head, "1.1.1.1"),}
        self._status_history = collections.deque(maxlen=2)
        self._logger = logging.getLogger(type(self).__name__)

    @property
    def current_status(self):
        try:
            return any(self._status_history[-1].values())
        except IndexError:
            return None

    @property
    def previous_status(self):
        try:
            return any(self._status_history[-2].values())
        except IndexError:
            return None

    def start(self):
        assert self._check_timer is None
        self._keep_running = True
        # This will also start a timer for the next check.
        self._do_check()

    def stop(self):
        assert self._check_timer is not None
        self._keep_running = False
        with self._check_timer_lock:
            self._check_timer.cancel()
            self._check_timer.join(timeout=self.NETWORK_TIMEOUT + 0.5)
            if self._check_timer.is_alive():
                self._logger.warning(
                    "Network check thread won't terminate cleanly.")
        self._check_timer = None

    def _do_check(self):
        new_stati = {}
        for check_name, check_function in self._checks.items():
            if not self._keep_running:
                return
            new_stati[check_name] = check_function()
        self._status_history.append(new_stati)
        if len(set(new_stati.values())) != 1:
            self._logger.warning(
                "Inconsistent results for internet connectivity checks: some "
                f"succeeded, some failed: {new_stati}.")
        if self.current_status != self.previous_status:
            self._logger.info(
                "Internet connectivity has changed: was "
                f"{self.previous_status}, is now {self.current_status}.")
            self._publish_new_status()
        with self._check_timer_lock:
            if not self._keep_running:
                return
            self._check_timer = threading.Timer(
                self.check_interval, self._do_check)
            self._check_timer.start()

    def _publish_new_status(self):
        while self._keep_running:
            event = ("connectivity_change", self.current_status)
            try:
                self._event_queue.put(event, timeout=0.5)
                return
            except queue.Full:
                self._logger.warning(
                    "Tried to publish a new connectivity status, but the "
                    "event queue was full.")

    def _check_https_head(self, host):
        conn = http.client.HTTPSConnection(host, timeout=self.NETWORK_TIMEOUT)
        try:
            conn.request("HEAD", "/")
            return True
        except:
            return False
        finally:
            conn.close()

    def _check_dns_resolve(self, host):
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False


class Hotspot(abc.ABC):
    HOSTAPD_SRC_PATH = pathlib.Path("/opt/adsb/accesspoint/hostapd.conf")
    HOSTAPD_DEST_PATH = pathlib.Path("/etc/hostapd/hostapd.conf")
    KEA_SRC_PATH = pathlib.Path("/opt/adsb/accesspoint/kea-dhcp4.conf")
    KEA_DEST_PATH = pathlib.Path("/etc/kea/kea-dhcp4.conf")
    AVAHI_UNIT_PATH = pathlib.Path(
        "/usr/lib/systemd/system/adsb-avahi-alias@.service")

    def __init__(self, wlan):
        self.wlan = wlan
        self._hotspot_lock = threading.Lock()
        self._hotspot_is_running = False
        self._wifi_test_thread = None
        self.comment = ""
        self.restart_state = "done"
        self.ssid = ""
        self.passwd = ""
        self._dns_server = fakedns.Server()
        self._d = utils.data.Data()
        self._logger = logging.getLogger(type(self).__name__)
        self.wifi = utils.wifi.make_wifi(self.wlan)
        self.version = self._d.read_version()
        self._setup_config_files()
        self._app = self._setup_flask()
        self._scan_for_ssids()

    @abc.abstractmethod
    def _restart_wifi_client(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _stop_wifi_client(self):
        raise NotImplementedError

    def _setup_config_files(self):
        # Set the correct wlan device in config files.
        has_replaced = False
        with self.HOSTAPD_SRC_PATH.open("r") as hostapd_in:
            hostapd_config = []
            for line in hostapd_in:
                if line.startswith("interface="):
                    line = f"interface={self.wlan}\n"
                    has_replaced = True
                hostapd_config.append(line)
        if not has_replaced:
            self._logger.warning("Interface not replaced in hostapd config.")
        with self.HOSTAPD_DEST_PATH.open("w") as hostapd_out:
            hostapd_out.writelines(hostapd_config)
        with self.KEA_SRC_PATH.open("r") as kea_in:
            kea_config = json.load(kea_in)
            kea_config["Dhcp4"]["interfaces-config"]["interfaces"] = [
                self.wlan]
        with self.KEA_DEST_PATH.open("w") as kea_out:
            json.dump(kea_config, kea_out, indent=4)
        has_replaced = False
        with self.AVAHI_UNIT_PATH.open("r+") as avahi_file:
            avahi_config = []
            for line in avahi_file:
                line, subs = re.subn(r"dev \S*", f"dev {self.wlan}", line)
                has_replaced |= bool(subs)
                avahi_config.append(line)
            avahi_file.seek(0)
            avahi_file.writelines(avahi_config)
            avahi_file.truncate()
        if not has_replaced:
            self._logger.warning(
                "Interface not replaced in avahi unit config.")

    def _scan_for_ssids(self):
        self._logger.info("Scanning for SSIDs.")
        start_time = time.time()
        while time.time() - start_time < 20:
            self.wifi.scan_ssids()
            if len(self.wifi.ssids) > 0:
                return
            time.sleep(0.5)

    def _setup_flask(self):
        app = flask.Flask(__name__)
        app.add_url_rule(
            "/healthz", view_func=self.healthz, methods=["OPTIONS", "GET"])
        app.add_url_rule("/hotspot", view_func=self.hotspot, methods=["GET"])
        app.add_url_rule("/restarting", view_func=self.restarting)
        app.add_url_rule(
            "/restart", view_func=self.restart, methods=["POST", "GET"])
        app.add_url_rule(
            "/",
            "/",
            view_func=self.catch_all,
            defaults={"path": ""},
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/<path:path>", view_func=self.catch_all, methods=["GET", "POST"])
        return app

    def run(self):
        with self._hotspot_lock:
            self._setup_hotspot_locked()
        signal.signal(signal.SIGTERM, self._shutdown)
        self._app.run(host="0.0.0.0", port=80)

    def _shutdown(self, sig, frame):
        self._logger.info("Shutting down.")
        if self._wifi_test_thread:
            # Wait for the test thread to finish.
            self._wifi_test_thread.join(15)
            if self._wifi_test_thread.is_alive():
                self._logger.warning(
                    "Wifi test thread failed to finish within timeout.")
        with self._hotspot_lock:
            if self._hotspot_is_running:
                self._teardown_hotspot_locked()
            # Restore default handler and raise again for Flask.
            signal.signal(sig, signal.SIG_DFL)
            signal.raise_signal(signal.SIGTERM)

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
        return self.restart_state

    def hotspot(self):
        return flask.render_template(
            "hotspot.html", version=self.version, comment=self.comment,
            ssids=self.wifi.ssids, mdns_enabled=self._d.is_enabled("mdns"))

    def catch_all(self, path):
        # Catch all requests not explicitly handled. Since our fake DNS server
        # resolves all names to us, this may literally be any request the
        # client tries to make to anyone. If it looks like they're sending us
        # wifi credentials, try those and restart. In all other cases, render
        # the /hotspot page.
        if self.restart_state == "restarting":
            return flask.redirect("/restarting")

        if self._request_looks_like_wifi_credentials():
            if self._wifi_test_thread is not None:
                self._logger.warning(
                    "Received wifi credentials while a wifi test thread is "
                    "already running. Returning the main page again.")
                return self.hotspot()
            self.restart_state = "restarting"

            self.ssid = request.form.get("ssid")
            self.passwd = request.form.get("passwd")

            self._wifi_test_thread = threading.Thread(target=self.test_wifi)
            self._wifi_test_thread.start()

            return flask.redirect("/restarting")

        return self.hotspot()

    def _request_looks_like_wifi_credentials(self):
        return (
            request.method == "POST" and "ssid" in request.form
            and "passwd" in request.form)

    def restarting(self):
        return flask.render_template("hotspot-restarting.html")

    def _setup_hotspot_locked(self):
        # We need to stop any existing wifi service in case there's already an
        # incorrect password configured so it doesn't disrupt hostapd, and to
        # get rid of any DNS proxy that may block port 53.
        self._stop_wifi_client()
        utils.util.shell_with_combined_output(
            f"ip li set {self.wlan} up && "
            "ip ad add 192.168.199.1/24 broadcast 192.168.199.255 "
            f"dev {self.wlan}")
        self._systemctl(["unmask", "start"], "hostapd.service")
        time.sleep(2)
        self._systemctl(
            ["unmask", "start"], "isc-kea-dhcp4-server.service")
        if self._d.is_enabled("mdns"):
            self._systemctl(
                ["restart"], "adsb-avahi-alias@adsb-feeder.local.service")
        self._logger.info("Starting DNS server.")
        try:
            self._dns_server.start()
        except:
            self._logger.exception("Error starting DNS server.")
        self._logger.info("Started hotspot.")
        self._hotspot_is_running = True

    def _teardown_hotspot_locked(self):
        self._logger.info("Stopping DNS server.")
        try:
            self._dns_server.stop()
        except:
            self._logger.exception("Error stopping DNS server.")
        if self._d.is_enabled("mdns"):
            self._systemctl(
                ["stop"], "adsb-avahi-alias@adsb-feeder.local.service")
        self._systemctl(
            ["stop", "disable", "mask"],
            "isc-kea-dhcp4-server.service hostapd.service")
        utils.util.shell_with_combined_output(
            f"ip ad del 192.168.199.1/24 dev {self.wlan}; "
            f"ip addr flush {self.wlan}; ip link set dev {self.wlan} down")
        self._restart_wifi_client()
        # used to wait here, just spin around the wifi instead
        self._logger.info("Stopped hotspot.")
        self._hotspot_is_running = False

    def _systemctl(self, commands, services, *, ignore_errors=False):
        procs = []
        for command in commands:
            proc = utils.util.shell_with_combined_output(
                f"systemctl {command} {services}")
            if proc.returncode and not ignore_errors:
                self._logger.error(f"systemctl failed: {proc.stdout}")
            procs.append(proc)
        return procs

    def test_wifi(self):
        self._logger.info("Starting wifi test.")
        # the parent process needs to return from the call to POST
        time.sleep(1.0)
        with self._hotspot_lock:
            self._teardown_hotspot_locked()

            self._logger.info(f"Testing the '{self.ssid}' network.")

            success = self.wifi.wifi_connect(self.ssid, self.passwd)
            self.restart_state = "done"
            if not success:
                self._logger.info(f"Failed to connect to '{self.ssid}'.")
                self.comment = "Failed to connect, wrong SSID or password, please try again."
                # now we bring back up the hotspot in order to deliver the result to the user
                # and have them try again
                self._setup_hotspot_locked()
                self._wifi_test_thread = None
                return

            self._logger.info(f"Successfully connected to '{self.ssid}'.")
            # Exit the hotspot. Afterwards, the connectivity monitor should
            # pick up that we have internet access. Otherwise, the manager will
            # have to restart the hotspot.
            self._wifi_test_thread = None
        signal.raise_signal(signal.SIGTERM)


class NetworkingHotspot(Hotspot):
    """Hotspot using networking.service."""
    def _stop_wifi_client(self):
        self._systemctl(["stop"],  "networking.service")

    def _restart_wifi_client(self):
        self._systemctl(["restart --no-block"], "networking.service")


class NetworkManagerHotspot(Hotspot):
    """Hotspot using NetworkManager."""
    def _stop_wifi_client(self):
        self._systemctl(["stop"], "NetworkManager wpa_supplicant")
        utils.util.shell_with_combined_output("iw reg set 00")
        # In some configurations, NetworkManager starts a dnsmasq as a DNS
        # proxy that can hang around even after we've stopped NetworkManager.
        # We need to stop it so we get port 53 back for our stub DNS server.
        for i in range(10):
            if not self._dnsmasq_is_running():
                break
            if i > 0:
                self._logger.warning(
                    "Tried to stop dnsmasq, but it's still running.")
                time.sleep(0.5)
            self._kill_dnsmasq()
        else:
            self._logger.error("Giving up trying to stop dnsmasq.")

    def _dnsmasq_is_running(self):
        proc = utils.util.shell_with_combined_output("ps -e | grep dnsmasq")
        return proc.returncode == 0

    def _kill_dnsmasq(self):
        # This may not exist, we'll get it with killall. Ignore errors.
        proc, = self._systemctl(["stop"], "dnsmasq", ignore_errors=True)
        if proc.returncode == 0:
            return
        utils.util.shell_with_combined_output("killall dnsmasq")

    def _restart_wifi_client(self):
        utils.util.shell_with_combined_output("iw reg set 00")
        self._systemctl(["restart"], "wpa_supplicant NetworkManager")
