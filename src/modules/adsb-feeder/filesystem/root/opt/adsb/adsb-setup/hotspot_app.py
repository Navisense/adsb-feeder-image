import abc
import collections
import functools as ft
import http.client
import logging
import math
import pathlib
import queue
import signal
import socket
import subprocess
import sys
import threading
import time

from flask import (
    Flask,
    make_response,
    redirect,
    render_template,
    request,
)

import fakedns
import utils.data
import utils.util
from utils.wifi import make_wifi


def print_err(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".{0:03.0f}Z".format(
        math.modf(time.time())[0] * 1000
    )
    print(*((timestamp,) + args), file=sys.stderr, **kwargs)


class ConnectivityMonitor:
    """
    Monitor that regularly checks whether we have internet access.

    If the state changes, puts the new value into its change_queue.
    """
    NETWORK_TIMEOUT = 2
    CHECK_INTERVAL = 60

    def __init__(self):
        self.change_queue = queue.Queue(maxsize=1)
        self._keep_running = None
        self._check_timer = None
        self._check_timer_lock = threading.Lock()
        self._checks = {
            "google_quad8_https_head": ft.partial(
                self._check_https_head, "8.8.8.8"),
            "quad9_https_head": ft.partial(self._check_https_head, "9.9.9.9"),
            "google.com_dns_resolve": ft.partial(
                self._check_dns_resolve, "google.com"),
            "navisense.de_dns_resolve": ft.partial(
                self._check_dns_resolve, "navisense.de"),}
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
                self.CHECK_INTERVAL, self._do_check)
            self._check_timer.start()

    def _publish_new_status(self):
        while self._keep_running:
            try:
                self.change_queue.put(self.current_status, timeout=0.5)
                return
            except queue.Full:
                self._logger.warning(
                    "Tried to publish a new connectivity status, but no one "
                    "has picked up the previous one yet.")

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
    def __init__(self, wlan):
        self._d = utils.data.Data()
        self.app = Flask(__name__)
        self.wlan = wlan
        self.wifi = make_wifi(wlan)
        if pathlib.Path("/opt/adsb/adsb.im.version").exists():
            with open("/opt/adsb/adsb.im.version", "r") as f:
                self.version = f.read().strip()
        else:
            self.version = "unknown"
        self.comment = ""
        self.restart_state = "done"
        self.ssid = ""
        self.passwd = ""
        self._dns_server = fakedns.Server()
        print_err("trying to scan for SSIDs")
        self.wifi.ssids = []
        startTime = time.time()
        while time.time() - startTime < 20:
            self.wifi.scan_ssids()
            if len(self.wifi.ssids) > 0:
                break

        self.app.add_url_rule(
            "/healthz", view_func=self.healthz, methods=["OPTIONS", "GET"])
        self.app.add_url_rule("/hotspot", view_func=self.hotspot, methods=["GET"])
        self.app.add_url_rule("/restarting", view_func=self.restarting)

        self.app.add_url_rule("/restart", view_func=self.restart, methods=["POST", "GET"])
        self.app.add_url_rule(
            "/",
            "/",
            view_func=self.catch_all,
            defaults={"path": ""},
            methods=["GET", "POST"],
        )
        self.app.add_url_rule("/<path:path>", view_func=self.catch_all, methods=["GET", "POST"])

    @abc.abstractmethod
    def _restart_wifi_client(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _stop_wifi_client(self):
        raise NotImplementedError

    def healthz(self):
        if request.method == "OPTIONS":
            response = make_response()
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "*")
            response.headers.add("Access-Control-Allow-Methods", "*")
        else:
            response = make_response("ok")
            response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    def restart(self):
        return self.restart_state

    def hotspot(self):
        return render_template(
            "hotspot.html", version=self.version, comment=self.comment,
            ssids=self.wifi.ssids, mdns_enabled=self._d.is_enabled("mdns"))

    def catch_all(self, path):
        # Catch all requests not explicitly handled. Since our fake DNS server
        # resolves all names to us, this may literally be any request the
        # client tries to make to anyone. If it looks like they're sending us
        # wifi credentials, try those and restart. In all other cases, render
        # the /hotspot page.
        if self.restart_state == "restarting":
            return redirect("/restarting")

        if self._request_looks_like_wifi_credentials():
            self.lastUserInput = time.monotonic()
            self.restart_state = "restarting"

            self.ssid = request.form.get("ssid")
            self.passwd = request.form.get("passwd")

            threading.Thread(target=self.test_wifi).start()
            print_err("started wifi test thread")

            return redirect("/restarting")

        return self.hotspot()

    def _request_looks_like_wifi_credentials(self):
        return (
            request.method == "POST" and "ssid" in request.form
            and "passwd" in request.form)

    def restarting(self):
        return render_template("hotspot-restarting.html")

    def run(self):
        self.setup_hotspot()

        self.lastUserInput = time.monotonic()

        def idle_exit():
            while True:
                idleTime = time.monotonic() - self.lastUserInput
                if idleTime > 300:
                    break

                time.sleep(300 - idleTime)

            # 5 minutes without user interaction: quit the app and have the shell script check if networking is working now
            self.restart_state = "restarting"
            self.teardown_hotspot()
            print_err("exiting the hotspot app after 5 minutes idle")
            signal.raise_signal(signal.SIGTERM)

        threading.Thread(target=idle_exit).start()

        self.app.run(host="0.0.0.0", port=80)

    def setup_hotspot(self):
        # We need to stop any existing wifi service in case there's already an
        # incorrect password configured so it doesn't disrupt hostapd, and to
        # get rid of any DNS proxy that may block port 53.
        self._stop_wifi_client()

        subprocess.run(
            f"ip li set {self.wlan} up && ip ad add 192.168.199.1/24 broadcast 192.168.199.255 dev {self.wlan} && systemctl start hostapd.service",
            shell=True,
        )
        time.sleep(2)
        subprocess.run(
            f"systemctl start isc-kea-dhcp4-server.service",
            shell=True,
        )
        if self._d.is_enabled("mdns"):
            subprocess.run(
                f"systemctl start adsb-avahi-alias@adsb-feeder.local.service",
                shell=True,
            )
        print_err("Starting DNS server.")
        try:
            self._dns_server.start()
        except Exception as e:
            print_err(f"Error starting DNS server: {e}.")
        print_err("started hotspot")

    def teardown_hotspot(self):
        print_err("Stopping DNS server.")
        try:
            self._dns_server.stop()
        except Exception as e:
            print_err(f"Error stopping DNS server: {e}.")
        if self._d.is_enabled("mdns"):
            subprocess.run(
                f"systemctl stop adsb-avahi-alias@adsb-feeder.local.service",
                shell=True,
            )
        subprocess.run(
            f"systemctl stop isc-kea-dhcp4-server.service; systemctl stop hostapd.service; ip ad del 192.168.199.1/24 dev {self.wlan}; ip addr flush {self.wlan}; ip link set dev {self.wlan} down",
            shell=True,
        )
        self._restart_wifi_client()
        # used to wait here, just spin around the wifi instead
        print_err("turned off hotspot")

    def test_wifi(self):
        # the parent process needs to return from the call to POST
        time.sleep(1.0)
        self.teardown_hotspot()

        print_err(f"testing the '{self.ssid}' network")

        success = self.wifi.wifi_connect(self.ssid, self.passwd)
        self.restart_state = "done"
        if not success:
            print_err(f"test_wifi failed to connect to '{self.ssid}'")

            self.comment = "Failed to connect, wrong SSID or password, please try again."
            # now we bring back up the hotspot in order to deliver the result to the user
            # and have them try again
            self.setup_hotspot()
            return

        print_err(f"successfully connected to '{self.ssid}'")
        # the shell script that launched this app will do a final connectivity check
        # if there is no connectivity despite being able to join the wifi, it will re-launch this app (unlikely)
        print_err("exiting the hotspot app")
        signal.raise_signal(signal.SIGTERM)


class NetworkingHotspot(Hotspot):
    """Hotspot using networking.service."""
    def _stop_wifi_client(self):
        utils.util.shell_with_combined_output(
            "systemctl stop networking.service")

    def _restart_wifi_client(self):
        proc = utils.util.shell_with_combined_output(
            "systemctl restart --no-block networking.service")
        print_err(
            f"restarted networking.service: {proc.returncode}\n{proc.stdout}")


class NetworkManagerHotspot(Hotspot):
    """Hotspot using NetworkManager."""
    def _stop_wifi_client(self):
        utils.util.shell_with_combined_output(
            "systemctl stop NetworkManager wpa_supplicant; iw reg set 00")
        # In some configurations, NetworkManager starts a dnsmasq as a DNS
        # proxy that can hang around even after we've stopped NetworkManager.
        # We need to stop it so we get port 53 back for our stub DNS server.
        for i in range(10):
            if not self._dnsmasq_is_running():
                break
            if i > 0:
                print_err("Tried to stop dnsmasq, but it's still running.")
                time.sleep(0.5)
            self._kill_dnsmasq()
        else:
            print_err("Giving up trying to stop dnsmasq.")

    def _dnsmasq_is_running(self):
        proc = utils.util.shell_with_combined_output("ps -e | grep dnsmasq")
        return proc.returncode == 0

    def _kill_dnsmasq(self):
        proc = utils.util.shell_with_combined_output("systemctl stop dnsmasq")
        if proc.returncode == 0:
            return
        utils.util.shell_with_combined_output("killall dnsmasq")

    def _restart_wifi_client(self):
        utils.util.shell_with_combined_output(
            "iw reg set 00; systemctl restart wpa_supplicant NetworkManager")


if __name__ == "__main__":
    wlan = "wlan0"
    if len(sys.argv) == 2:
        wlan = sys.argv[1]
    baseos = utils.util.get_baseos()
    if baseos == "dietpi":
        hotspot = NetworkingHotspot(wlan)
    elif baseos in ["raspbian", "postmarketos"]:
        hotspot = NetworkManagerHotspot(wlan)
    else:
        print_err(f"Unknown OS {baseos} - giving up.")
        sys.exit(1)
    print_err(f"Starting hotspot for {wlan}.")

    hotspot.run()
