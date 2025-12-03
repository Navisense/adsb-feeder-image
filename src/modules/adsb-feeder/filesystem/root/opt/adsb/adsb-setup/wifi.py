import dataclasses as dc
import logging
import subprocess
import threading
import time
from typing import Optional

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
    def __init__(self, device_name: str):
        self._logger = logging.getLogger(type(self).__name__)
        self._device_name = device_name
        self._ssid = None
        self.networks: dict[str, WifiNetworkInfo] = {}

    @property
    def device_name(self) -> str:
        return self._device_name

    @property
    def ssid(self) -> Optional[str]:
        """The SSID this wifi is connected to."""
        return self._ssid

    def refresh_ssid(self):
        old_ssid = self._ssid
        try:
            proc = util.shell_with_combined_output(
                f"iw dev {self._device_name} link | awk '/SSID/{{print $2}}'",
                check=True)
            ssid = proc.stdout.strip()
        except:
            self._logger.exception("Error refreshing SSID.")
            ssid = None
        self._ssid = ssid or None
        if old_ssid != self._ssid:
            self._logger.info(
                f"The SSID we're connected to changed from {old_ssid} to "
                f"{self._ssid}.")

    def connect(self, ssid, passwd):
        pass

    def scan_ssids(self):
        pass


class NetworkManagerWifi(GenericWifi):
    """Wifi using NetworkManager, e.g. for Raspbian."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._device_lock = threading.Lock()

    def connect(self, ssid, passwd):
        with self._device_lock:
            self._connect_locked(ssid, passwd)

    def _connect_locked(self, ssid, passwd):
        # Try for a while because it takes a bit for NetworkManager to come
        # back up.
        try_until = time.monotonic() + 20
        while time.monotonic() < try_until:
            # Do a wifi scan to ensure the following connect works. This is
            # apparently necessary for NetworkManager.
            self._scan_ssids_locked()
            # Before connecting, delete the connection if it exists.
            # Apparently, not doing this can cause problems with
            # NetworkManager. This will return an error if the connection
            # doesn't exist, which we can ignore.
            util.shell_with_combined_output(
                f'nmcli connection delete "{ssid}"')
            try:
                proc = util.shell_with_combined_output(
                    f'nmcli dev wifi connect "{ssid}" password "{passwd}" '
                    f'ifname "{self._device_name}"', timeout=20.0)
            except subprocess.TimeoutExpired:
                self._logger.exception(
                    "Timeout in process connecting to wifi.")
                continue

            if "successfully activated" in proc.stdout:
                self.refresh_ssid()
                return
            self._logger.error(f"Failed to connect to '{ssid}': {proc.stdout}")
            # Just to safeguard against super fast spin, sleep a bit.
            time.sleep(2)

        raise Exception(f"Failed to connect to '{ssid}' after timeout.")

    def scan_ssids(self):
        with self._device_lock:
            self._scan_ssids_locked()

    def _scan_ssids_locked(self):
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

            if networks:
                self._logger.debug(f"Found wifi networks {networks}.")
                self.networks = networks
            else:
                self._logger.debug("No wifi networks found.")

        except Exception:
            self._logger.exception("Error scanning for SSIDs.")
