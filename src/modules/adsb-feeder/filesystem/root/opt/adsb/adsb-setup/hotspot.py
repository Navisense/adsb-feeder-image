import abc
import collections
import functools as ft
import http.client
import json
import logging
import pathlib
import queue
import re
import socket
import threading
import time

import fakedns
import utils.data
import utils.system
import utils.util
import utils.wifi

logger = logging.getLogger(__name__)


def make_hotspot(on_wifi_test_status):
    wlan = _find_wlan_device()
    if not wlan:
        return None
    baseos = utils.util.get_baseos()
    if baseos == "dietpi":
        return NetworkingHotspot(wlan, on_wifi_test_status)
    elif baseos in ["raspbian", "postmarketos"]:
        return NetworkManagerHotspot(wlan, on_wifi_test_status)
    else:
        raise ValueError(f"unknown OS {baseos}")


def _find_wlan_device():
    raw_output = utils.util.shell_with_combined_output(
        "iw dev | grep Interface | cut -d' ' -f2")
    wlans = [wlan for wlan in raw_output.stdout.split("\n") if wlan]
    if not wlans:
        logger.warning(
            f"No wlan device found in {raw_output}. Unable to start "
            "hotspot.")
        return None
    if len(wlans) > 1:
        logger.info(
            f"Found more than one wlan device: {wlans}. Using {wlans[0]}")
    return wlans[0]


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
    HOTSPOT_IP = "192.168.199.1"
    HOTSPOT_BROADCAST = "192.168.199.255"
    HOSTAPD_SRC_PATH = pathlib.Path("/opt/adsb/accesspoint/hostapd.conf")
    HOSTAPD_DEST_PATH = pathlib.Path("/etc/hostapd/hostapd.conf")
    KEA_SRC_PATH = pathlib.Path("/opt/adsb/accesspoint/kea-dhcp4.conf")
    KEA_DEST_PATH = pathlib.Path("/etc/kea/kea-dhcp4.conf")
    AVAHI_UNIT_PATH = pathlib.Path(
        "/usr/lib/systemd/system/adsb-avahi-alias@.service")

    def __init__(self, wlan, on_wifi_test_status):
        self.wlan = wlan
        self._on_wifi_test_status = on_wifi_test_status
        self._hotspot_lock = threading.Lock()
        self._hotspot_is_running = False
        self._wifi_test_thread = None
        # Don't answer DNS queries for names under .local or
        # local.porttracker-feeder.de (where porttracker-feeder.de is the DNS
        # suffix advertised via DHCP). Those are mDNS names that should be
        # answered by the avahi service.
        self._dns_server = fakedns.Server(
            response_ip=self.HOTSPOT_IP,
            non_response_domains={"local", "local.porttracker-feeder.de"})
        self._d = utils.data.Data()
        self._logger = logging.getLogger(type(self).__name__)
        self.wifi = utils.wifi.make_wifi(self.wlan)
        self.version = self._d.read_version()
        self._setup_config_files()

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
                break
            time.sleep(0.5)
        return self.wifi.ssids

    @property
    def active(self):
        return self._hotspot_is_running

    def start(self):
        ssids = self._scan_for_ssids()
        with self._hotspot_lock:
            if self._hotspot_is_running:
                self._logger.error(
                    "start() was called, but the hotspot was already running. "
                    "Unable to scan for SSIDs now.")
                return []
            self._setup_hotspot_locked()
        return ssids

    def stop(self):
        if (self._wifi_test_thread
                and self._wifi_test_thread is not threading.current_thread()):
            # Wait for the test thread to finish.
            self._wifi_test_thread.join(15)
            if self._wifi_test_thread.is_alive():
                self._logger.warning(
                    "Wifi test thread failed to finish within timeout.")
        with self._hotspot_lock:
            if not self._hotspot_is_running:
                return
            self._teardown_hotspot_locked()

    def _setup_hotspot_locked(self):
        # We need to stop any existing wifi service in case there's already an
        # incorrect password configured so it doesn't disrupt hostapd, and to
        # get rid of any DNS proxy that may block port 53.
        self._stop_wifi_client()
        utils.util.shell_with_combined_output(
            f"ip li set {self.wlan} up && "
            f"ip ad add {self.HOTSPOT_IP}/24 "
            f"broadcast {self.HOTSPOT_BROADCAST} dev {self.wlan}")
        # Sleep for a bit to get hostapd and kea to start up properly.
        time.sleep(2)
        utils.system.systemctl().run(["unmask", "start"], ["hostapd.service"])
        utils.system.systemctl().run(["unmask", "start"],
                                     ["isc-kea-dhcp4-server.service"])
        if self._d.is_enabled("mdns"):
            utils.system.systemctl().run(
                ["restart"],
                ["adsb-avahi-alias@porttracker-feeder.local.service"])
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
            utils.system.systemctl().run(
                ["stop"],
                ["adsb-avahi-alias@porttracker-feeder.local.service"])
        utils.system.systemctl().run(
            ["stop", "disable", "mask"],
            ["isc-kea-dhcp4-server.service", "hostapd.service"])
        utils.util.shell_with_combined_output(
            f"ip ad del {self.HOTSPOT_IP}/24 dev {self.wlan}; "
            f"ip addr flush {self.wlan}; ip link set dev {self.wlan} down")
        self._restart_wifi_client()
        # used to wait here, just spin around the wifi instead
        self._logger.info("Stopped hotspot.")
        self._hotspot_is_running = False

    def start_wifi_test(self, ssid, password):
        if self._wifi_test_thread:
            raise ValueError("a wifi test is already running.")
        self._wifi_test_thread = threading.Thread(
            target=self._test_wifi, args=(ssid, password), daemon=True)
        self._wifi_test_thread.start()

    def _test_wifi(self, ssid, password):
        self._logger.info(f"Setting up to test the '{ssid}' network.")
        with self._hotspot_lock:
            if self.active:
                self._teardown_hotspot_locked()
            else:
                self._logger.warning(
                    "Got request to test wifi credentials, but the hotspot "
                    "wasn't active.")
            success = self.wifi.wifi_connect(ssid, password)
            self.restart_state = "done"
            if not success:
                self._logger.info(f"Failed to connect to '{ssid}'.")
                self._setup_hotspot_locked()
            else:
                # Leave the hotspot disabled.
                self._logger.info(f"Successfully connected to '{ssid}'.")
        self._on_wifi_test_status(success)
        self._wifi_test_thread = None


class NetworkingHotspot(Hotspot):
    """Hotspot using networking.service."""
    def _stop_wifi_client(self):
        utils.system.systemctl().run(["stop"], ["networking.service"])

    def _restart_wifi_client(self):
        utils.system.systemctl().run(["restart --no-block"],
                                     ["networking.service"])


class NetworkManagerHotspot(Hotspot):
    """Hotspot using NetworkManager."""
    def _stop_wifi_client(self):
        utils.system.systemctl().run(["stop"],
                                     ["NetworkManager", "wpa_supplicant"])
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
        proc, = utils.system.systemctl().run(["stop"], ["dnsmasq"],
                                             log_errors=False)
        if proc.returncode == 0:
            return
        utils.util.shell_with_combined_output("killall dnsmasq")

    def _restart_wifi_client(self):
        utils.util.shell_with_combined_output("iw reg set 00")
        utils.system.systemctl().run(["restart"],
                                     ["wpa_supplicant", "NetworkManager"])
