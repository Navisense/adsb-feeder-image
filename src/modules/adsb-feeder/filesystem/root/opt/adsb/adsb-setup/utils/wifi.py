import os
import subprocess
import time
import traceback

from utils.util import get_baseos, print_err, run_shell_captured


def make_wifi(wlan="wlan0"):
    baseos = get_baseos()
    if baseos == "dietpi":
        return WpaSupplicantWifi(wlan)
    elif baseos in ["raspbian", "postmarketos"]:
        return NetworkManagerWifi(wlan)
    print_err(
        f"Unknown OS {baseos} - wifi will be unable to scan and connect.")
    return GenericWifi(wlan)


class GenericWifi:
    """Generic wifi that can't scan or connect."""
    def __init__(self, wlan):
        self.wlan = wlan
        self.ssids = []

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
        # wait for wpa_supplicant to be running
        startTime = time.time()
        success = False
        while time.time() - startTime < 45:
            success, output = run_shell_captured("pgrep wpa_supplicant", timeout=5)
            time.sleep(1)
            if success:
                break
        if not success:
            print_err("timeout while waiting for wpa_supplicant to start")
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
                # print_err(f"wpa_cli: {line.rstrip()})")
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
            print_err(traceback.format_exc())
        finally:
            if proc:
                proc.terminate()

        if not connected:
            print_err(f"Couldn't connect after wpa_cli reconfigure: ouput: {output}")

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

            output = ""

            startTime = time.time()
            while time.time() - startTime < 15:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue

                output += line
                # print(line, end="")
                if line.count("Interactive mode"):
                    proc.stdin.write("scan\n")
                    proc.stdin.flush()
                if line.count("CTRL-EVENT-SCAN-RESULTS"):
                    proc.stdin.write("scan_results\n")
                    proc.stdin.flush()
                    break

            startTime = time.time()
            while time.time() - startTime < 1:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue

                output += line
                if line.count("\t"):
                    fields = line.rstrip("\n").split("\t")
                    if len(fields) == 5:
                        ssids.append(fields[4])

        except:
            print_err(f"ERROR in _wpa_cli_scan(), wpa_cli ouput: {output}")
        finally:
            if proc:
                proc.terminate()

        return ssids

    def _write_wpa_conf(self, ssid=None, passwd=None, path=None, country_code="00"):
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
                            raise SyntaxError("unexpected close of network block")
                        inBlock = False
                        netblocks[exist_ssid] = netblock
        except:
            print_err(traceback.format_exc())
            print_err(f"ERROR when parsing existing wpa supplicant config, will DISCARD OLD CONFIG")
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
"""
                )
                for k in netblocks.keys():
                    conf.write(netblocks[k])
        except:
            print_err(traceback.format_exc())
            print_err(f"ERROR when writing wpa supplicant config to {path}")
            return False
        print_err("wpa supplicant config written to " + path)
        return True

    def _restart_networking_noblock(self):
        res, out = run_shell_captured("systemctl restart --no-block networking.service", timeout=5)

    def _add_wifi_hotplug(self):
        # enable dietpi wifi in case it is disabled
        changedInterfaces = False
        with open("/etc/network/interfaces", "r") as current, open("/etc/network/interfaces.new", "w") as update:
            lines = current.readlines()
            for line in lines:
                if line.startswith("#") and "allow-hotplug" in line and self.wlan in line:
                    changedInterfaces = True
                    update.write(f"allow-hotplug {self.wlan}\n")
                else:
                    update.write(f"{line}")

        if changedInterfaces:
            print_err(f"uncommenting allow-hotplug for {self.wlan}")
            os.rename("/etc/network/interfaces.new", "/etc/network/interfaces")
            self._restart_networking_noblock()
        else:
            os.remove("/etc/network/interfaces.new")

    def wifi_connect(self, ssid, passwd, country_code="00"):
        success = False

        self._add_wifi_hotplug()

        # wpa_supplicant can take extremely long to start up as long as eth0 has allow-hotplug
        # _wpa_cli_reconfigure will wait for that so this test can take up to 60 seconds

        # test wifi
        success = self._write_wpa_conf(
            ssid=ssid, passwd=passwd, path="/etc/wpa_supplicant/wpa_supplicant.conf", country_code=country_code
        )
        if success:
            # note to self: don't call ifup from within this
            # stopping adsb-setup service will terminate wpa_supplicant somehow
            if not self._wait_wpa_supplicant():
                print_err("ERROR: _wait_wpa_supplicant didn't work, restarting networking and re-trying")
                self._restart_networking_noblock()
                self._wait_wpa_supplicant()

            success = self._wpa_cli_reconfigure()

        return success

    def scan_ssids(self):
        try:
            ssids = self._wpa_cli_scan()

            if len(ssids) > 0:
                print_err(f"found SSIDs: {ssids}")
                self.ssids = ssids
            else:
                print_err("no SSIDs found")

        except Exception as e:
            print_err(f"ERROR in scan_ssids(): {e}")


class NetworkManagerWifi(GenericWifi):
    """Wifi using NetworkManager, e.g. for Raspbian."""
    def wifi_connect(self, ssid, passwd, country_code="00"):
        success = False

        # do a wifi scan to ensure the following connect works
        # this is apparently necessary for NetworkManager
        self.scan_ssids()
        # try for a while because it takes a bit for NetworkManager to come back up
        startTime = time.time()
        while time.time() - startTime < 20:
            try:
                result = subprocess.run(
                    [
                        "nmcli",
                        "d",
                        "wifi",
                        "connect",
                        f"{ssid}",
                        "password",
                        f"{passwd}",
                        "ifname",
                        f"{self.wlan}",
                    ],
                    capture_output=True,
                    timeout=20.0,
                )
            except subprocess.SubprocessError as e:
                # something went wrong
                output = ""
                if e.stdout:
                    output += e.stdout.decode()
                if e.stderr:
                    output += e.stderr.decode()
            else:
                output = result.stdout.decode() + result.stderr.decode()

            success = "successfully activated" in output

            if success:
                break
            else:
                # just to safeguard against super fast spin, sleep a bit
                print_err(f"failed to connect to '{ssid}': {output}")
                time.sleep(2)
                continue

        return success

    def scan_ssids(self):
        try:
            try:
                output = subprocess.run(
                    "nmcli --terse --fields SSID dev wifi",
                    shell=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                print_err(f"error scanning for SSIDs: {e}")
                return

            ssids = []
            for line in output.stdout.decode().split("\n"):
                if line and line != "--" and line not in ssids:
                    ssids.append(line)

            if len(ssids) > 0:
                print_err(f"found SSIDs: {ssids}")
                self.ssids = ssids
            else:
                print_err("no SSIDs found")

        except Exception as e:
            print_err(f"ERROR in scan_ssids(): {e}")
