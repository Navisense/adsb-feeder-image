import dataclasses as dc
import logging
import os
import subprocess
import time

import util


@dc.dataclass(eq=True, frozen=True)
class WifiNetworkInfo:
    ssid: str
    signal_strength: float


def make_wifi(device_name="wlan0"):
    baseos = util.get_baseos()
    if baseos in ["raspbian", "postmarketos"]:
        return NetworkManagerWifi(device_name)
    logging.getLogger(__name__).warning(
        f"Unknown OS {baseos} - wifi will be unable to scan and connect.")
    return GenericWifi(device_name)


class GenericWifi:
    """Generic wifi that can't scan or connect."""
    def __init__(self, device_name):
        self._logger = logging.getLogger(type(self).__name__)
        self._device_name = device_name
        self.networks: dict[str, WifiNetworkInfo] = {}

    def get_ssid(self):
        try:
            # if you aren't on wifi, this will return an empty string
            ssid = subprocess.run(
                f"iw dev {self._device_name} link | awk '/SSID/{{print $2}}'",
                shell=True,
                capture_output=True,
                timeout=2.0,
            ).stdout.decode("utf-8")
        except:
            ssid = ""

        return ssid.strip()

    def wifi_connect(self, ssid, passwd, country_code="00"):
        return False

    def scan_ssids(self):
        pass


class NetworkManagerWifi(GenericWifi):
    """Wifi using NetworkManager, e.g. for Raspbian."""
    def wifi_connect(self, ssid, passwd, country_code="00"):
        # Try for a while because it takes a bit for NetworkManager to come
        # back up.
        startTime = time.time()
        while time.time() - startTime < 20:
            # Do a wifi scan to ensure the following connect works. This is
            # apparently necessary for NetworkManager.
            self.scan_ssids()
            # Before connecting, delete the connection if it exists.
            # Apparently, not doing this can cause problems with
            # NetworkManager. This will return an error if the connection
            # doesn't exist, which we can ignore.
            util.shell_with_combined_output(f"nmcli connection delete {ssid}")
            try:
                proc = util.shell_with_combined_output(
                    f"nmcli dev wifi connect {ssid} password {passwd} "
                    f"ifname {self._device_name}", timeout=20.0)
            except subprocess.TimeoutExpired:
                self._logger.exception(
                    "Timeout in process connecting to wifi.")
                continue

            if "successfully activated" in proc.stdout:
                return True
            self._logger.error(f"Failed to connect to '{ssid}': {proc.stdout}")
            # Just to safeguard against super fast spin, sleep a bit.
            time.sleep(2)

        return False

    def scan_ssids(self):
        try:
            try:
                proc = util.shell_with_separate_output(
                    "nmcli --terse --fields SSID,SIGNAL dev wifi", check=True)
            except subprocess.CalledProcessError:
                self._logger.exception("Error scanning for SSIDs.")
                return

            networks = {}
            for line in proc.stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    ssid, signal_strength_str = line.rsplit(":", maxsplit=1)
                    signal_strength = float(signal_strength_str)
                except:
                    self._logger.exception(
                        f"Error parsing nmcli output line {line}")
                    continue
                network_info = WifiNetworkInfo(
                    ssid=ssid, signal_strength=signal_strength)
                if (ssid not in networks
                        or networks[ssid].signal_strength < signal_strength):
                    networks[ssid] = network_info

            if len(networks) > 0:
                self._logger.info(f"Found wifi networks {networks}.")
                self.networks = networks
            else:
                self._logger.info("No wifi networks found.")

        except Exception:
            self._logger.exception("Error scanning for SSIDs.")
