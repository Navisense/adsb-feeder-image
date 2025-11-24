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


def make_wifi(wlan="wlan0"):
    baseos = util.get_baseos()
    if baseos == "dietpi":
        return WpaSupplicantWifi(wlan)
    elif baseos in ["raspbian", "postmarketos"]:
        return NetworkManagerWifi(wlan)
    logging.getLogger(__name__).warning(
        f"Unknown OS {baseos} - wifi will be unable to scan and connect.")
    return GenericWifi(wlan)


class GenericWifi:
    """Generic wifi that can't scan or connect."""
    def __init__(self, wlan):
        self._logger = logging.getLogger(type(self).__name__)
        self.wlan = wlan
        self.networks: dict[str, WifiNetworkInfo] = {}

    def get_ssid(self):
        try:
            # if you aren't on wifi, this will return an empty string
            ssid = subprocess.run(
                f"iw dev {self.wlan} link | awk '/SSID/{{print $2}}'",
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


class WpaSupplicantWifi(GenericWifi):
    """Wifi using wpa_supplicant, for the DietPi."""
    def _wait_wpa_supplicant(self):
        # Wait for wpa_supplicant to be running.
        startTime = time.time()
        success = False
        while time.time() - startTime < 45:
            proc = util.shell_with_combined_output(
                "pgrep wpa_supplicant", timeout=1)
            try:
                proc.check_returncode()
                break
            except:
                pass
        else:
            self._logger.error(
                "Timeout while waiting for wpa_supplicant to start.")
        return success

    def _wpa_cli_reconfigure(self):
        connected = False
        output = ""
        try:
            proc = subprocess.Popen(
                ["wpa_cli", f"-i{self.wlan}"],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
            )
            os.set_blocking(proc.stdout.fileno(), False)

            startTime = time.time()
            reconfigureSent = False
            reconfigured = False
            while time.time() - startTime < 20:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue

                output += line
                if not reconfigureSent and line.startswith(">"):
                    proc.stdin.write("reconfigure\n")
                    proc.stdin.flush()
                    reconfigureSent = True
                if "reconfigure" in line:
                    reconfigured = True
                if reconfigured and "CTRL-EVENT-CONNECTED" in line:
                    connected = True
                    break
        except:
            self._logger.exception("Error running wpa_cli.")
        finally:
            if proc:
                proc.terminate()

        if not connected:
            self._logger.error(
                f"Couldn't connect after wpa_cli reconfigure: {output}")

        return connected

    def _wpa_cli_scan(self):
        ssids = []
        try:
            proc = subprocess.Popen(
                ["wpa_cli", f"-i{self.wlan}"],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
            )
            os.set_blocking(proc.stdout.fileno(), False)

            start_time = time.time()
            while time.time() - start_time < 15:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue

                if line.count("Interactive mode"):
                    proc.stdin.write("scan\n")
                    proc.stdin.flush()
                if line.count("CTRL-EVENT-SCAN-RESULTS"):
                    proc.stdin.write("scan_results\n")
                    proc.stdin.flush()
                    break

            start_time = time.time()
            while time.time() - start_time < 1:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue

                if line.count("\t"):
                    fields = line.rstrip("\n").split("\t")
                    if len(fields) == 5:
                        ssids.append(fields[4])

        except:
            self._logger.exception(f"Error in _wpa_cli_scan().")
        finally:
            if proc:
                proc.terminate()

        return ssids

    def _write_wpa_conf(
            self, ssid=None, passwd=None, path=None, country_code="00"):
        netblocks = {}
        try:
            # extract the existing network blocks from the config file
            with open(path, "r") as conf:
                lines = conf.readlines()
                inBlock = False
                for line in lines:
                    if line.strip().startswith("network="):
                        if inBlock:
                            raise SyntaxError("nested network block")
                        netblock = ""
                        exist_ssid = None
                        inBlock = True
                    if inBlock:
                        if "ssid" in line:
                            exist_ssid = line.split('"')[1]
                        if "priority" in line:
                            p1, p2 = line.split("=")
                            # lower priority of all existing networks by 1
                            # negative priorities are allowed so this is fine
                            line = p1 + f"={int(p2) - 1}"
                        netblock += line.rstrip() + "\n"
                    if "}" in line:
                        if not inBlock or not exist_ssid:
                            raise SyntaxError(
                                "unexpected close of network block")
                        inBlock = False
                        netblocks[exist_ssid] = netblock
        except:
            self._logger.exception(
                "ERROR when parsing existing wpa supplicant config, will "
                "DISCARD OLD CONFIG")
            netblocks = {}

        try:
            output = subprocess.run(
                ["wpa_passphrase", f"{ssid}", f"{passwd}"],
                capture_output=True,
                check=True,
            ).stdout.decode()
            netblocks[ssid] = output.replace("}", "\tpriority=1000\n}")

            with open(path, "w") as conf:
                conf.write(
                    f"""
# WiFi country code, set here in case the access point does not send one
country={country_code}
# Grant all members of group "netdev" permissions to configure WiFi, e.g. via wpa_cli or wpa_gui
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
# Allow wpa_cli/wpa_gui to overwrite this config file
update_config=1
# disable p2p as it can cause errors
p2p_disabled=1
""")
                for k in netblocks.keys():
                    conf.write(netblocks[k])
        except:
            self._logger.exception(
                f"Error when writing wpa supplicant config to {path}.")
            raise
        self._logger.info(f"wpa supplicant config written to {path}.")

    def _restart_networking_noblock(self):
        util.shell_with_combined_output(
            "systemctl restart --no-block networking.service", timeout=5)

    def _add_wifi_hotplug(self):
        # enable dietpi wifi in case it is disabled
        changedInterfaces = False
        with open("/etc/network/interfaces",
                  "r") as current, open("/etc/network/interfaces.new",
                                        "w") as update:
            lines = current.readlines()
            for line in lines:
                if line.startswith(
                        "#") and "allow-hotplug" in line and self.wlan in line:
                    changedInterfaces = True
                    update.write(f"allow-hotplug {self.wlan}\n")
                else:
                    update.write(f"{line}")

        if changedInterfaces:
            self._logger.info(f"Uncommenting allow-hotplug for {self.wlan}.")
            os.rename("/etc/network/interfaces.new", "/etc/network/interfaces")
            self._restart_networking_noblock()
        else:
            os.remove("/etc/network/interfaces.new")

    def wifi_connect(self, ssid, passwd, country_code="00"):
        success = False

        self._add_wifi_hotplug()

        # wpa_supplicant can take extremely long to start up as long as eth0
        # has allow-hotplug. _wpa_cli_reconfigure will wait for that so this
        # test can take up to 60 seconds.

        # test wifi
        try:
            self._write_wpa_conf(
                ssid=ssid, passwd=passwd,
                path="/etc/wpa_supplicant/wpa_supplicant.conf",
                country_code=country_code)
        except:
            # note to self: don't call ifup from within this
            # stopping adsb-setup service will terminate wpa_supplicant somehow
            if not self._wait_wpa_supplicant():
                self._logger.exception(
                    "_wait_wpa_supplicant didn't work, restarting networking"
                    "and retrying.")
                self._restart_networking_noblock()
                self._wait_wpa_supplicant()

            success = self._wpa_cli_reconfigure()

        return success

    def scan_ssids(self):
        try:
            ssids = self._wpa_cli_scan()

            if len(ssids) > 0:
                self._logger.info(f"Found SSIDs: {ssids}")
                self.networks = {
                    ssid: WifiNetworkInfo(ssid=ssid, signal_strength=0)
                    for ssid in ssids}
            else:
                self._logger.error("No SSIDs found.")
        except:
            self._logger.exception("Error when scanning SSIDs.")


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
                    f"ifname {self.wlan}", timeout=20.0)
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
                try:
                    ssid, signal_strength_str = line.rsplit(":", maxsplit=1)
                    signal_strength = float(signal_strength_str)
                except:
                    self._logger.exception("Error parsing nmcli output.")
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
