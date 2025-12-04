import dataclasses as dc
import enum
import functools as ft
import ipaddress
import json
import logging
import pathlib
import select
import shutil
import socket
import subprocess
import threading
import time
from typing import Optional

import requests

import util
import wifi


@dc.dataclass
class NetworkDeviceInfo:
    device: str
    """Device name."""
    used_for_network_access: bool
    """Whether the device is used for network access."""
    ip: Optional[str]
    """IP address, set if the device is used for network access."""
    gateway: Optional[str]
    """Gateway IP address, set if the device is used for network access."""
    wifi: Optional[wifi.GenericWifi]
    """Wifi control, set if the device is a wifi device."""


@dc.dataclass
class SystemInfo:
    external_ip: Optional[str]
    network_device_infos: list[NetworkDeviceInfo]
    dns_is_working: bool
    has_low_disk: bool


@dc.dataclass
class ContainerInfo:
    id: str
    name: str
    state: str
    status: str
    base_image: str
    tag: Optional[str]

    @property
    def image(self) -> str:
        return f"{self.base_image}:{self.tag}"

    def up_less_than(self, seconds: float) -> bool:
        if not self.status.startswith("Up"):
            return False
        try:
            _, number, unit = self.status.split(" ")
            return unit == "seconds" and int(number) < seconds
        except:
            if "second" in self.status:
                # Handle status "Up Less than a second".
                return True
        return False


class TailscaleStatus(enum.StrEnum):
    NO_STATE = "no_state"
    ERROR = "error"
    NOT_INSTALLED = "not_installed"
    DISABLED = "disabled"
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"


@dc.dataclass
class TailscaleInfo:
    status: TailscaleStatus
    ips: list[str] = dc.field(default_factory=list)
    hostname: Optional[str] = None
    dns_name: Optional[str] = None

    @property
    def ipv4s(self) -> list[ipaddress.IPv4Address]:
        ipv4s = []
        for ip in self.ips:
            try:
                ipv4s.append(ipaddress.IPv4Address(ip))
            except ValueError:
                pass
        return ipv4s


class Systemctl:
    """Serialized access to systemctl."""
    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self._lock = threading.Lock()

    def run(
            self, commands: list[str], units: list[str], *,
            log_errors: bool = True) -> list[subprocess.CompletedProcess]:
        """
        Run systemctl commands.

        Runs each of the commands on all of the units. Each command is run on
        all units at once (i.e. converted to space-separated list). Commands
        may contain flags, e.g. "enable --now".

        Returns a list of CompletedProcess instances of the calls.
        """
        with self._lock:
            procs = []
            units_str = " ".join(units)
            for command in commands:
                proc = util.shell_with_combined_output(
                    f"systemctl {command} {units_str}")
                if proc.returncode and log_errors:
                    self._logger.error(f"systemctl failed: {proc.stdout}")
                procs.append(proc)
            return procs

    def run_transient(self, unit_name: str, arguments: list[str]):
        """Run a command using systemd-run."""
        if not arguments:
            raise ValueError("no arguments given")
        util.shell_with_combined_output(
            f"systemd-run -u {unit_name} " + " ".join(arguments), check=True)

    def unit_is_active(self, unit: str) -> bool:
        """Check whether a unit is active."""
        with self._lock:
            proc = util.shell_with_combined_output(
                f"systemctl is-active --quiet {unit}")
            return proc.returncode == 0


class Restart:
    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self.lock = threading.Lock()

    def bg_run(self, cmdline=None, func=None, silent=False):

        if not cmdline and not func:
            self._logger.warning("bg_run called without something to do.")
            return False

        gotLock = self.lock.acquire(blocking=False)

        if not gotLock:
            # we could not acquire the lock
            self._logger.error(f"Restart locked, couldn't run: {cmdline}")
            return False

        # we have acquired the lock

        def do_restart():
            try:
                if cmdline:
                    self._logger.info(f"Calling {cmdline}")
                    subprocess.run(
                        cmdline,
                        shell=True,
                        capture_output=silent,
                    )
                if func:
                    func()
            finally:
                self.lock.release()

        threading.Thread(target=do_restart).start()

        return True

    def wait_restart_done(self, timeout=-1):
        # acquire and release the lock immediately
        if self.lock.acquire(blocking=True, timeout=timeout):
            self.lock.release()

    @property
    def state(self):
        if self.lock.locked():
            return "busy"
        return "done"

    @property
    def is_restarting(self):
        return self.lock.locked()


class DmesgMonitor:
    def __init__(self, *, on_undervoltage):
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
                if ("Undervoltage" in new_output
                        or "under-voltage" in new_output):
                    self._on_undervoltage()
        finally:
            poll.unregister(proc.stdout)


class System:
    """
    Access to system functions.

    Provides properties for system info and Docker containers belonging to the
    application. Both are regularly refreshed in background tasks that are
    started and stopped by the class' context manager.
    """
    UNDERVOLTAGE_RESET_TIMEOUT = 2 * 3600
    LOW_DISK_THRESHOLD = 1024 * 1024 * 1024
    ZONEINFO_DIR = pathlib.Path("/usr/share/zoneinfo")

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self._restart = Restart()
        self._system_info = None
        self._system_info_lock = threading.Lock()
        self._containers = None
        self._containers_lock = threading.Lock()
        self._refresh_tasks = {
            "system_info": util.RepeatingTask(30, self.update_system_info),
            "containers": util.RepeatingTask(
                10, self._update_docker_containers),
            "wifi": util.RepeatingTask(10, self._update_wifi_info)}
        self._last_undervoltage_time = -self.UNDERVOLTAGE_RESET_TIMEOUT
        self._dmesg_monitor = DmesgMonitor(
            on_undervoltage=self._set_undervoltage)
        self._wifi_controls = {}

    def __enter__(self):
        for task in self._refresh_tasks.values():
            task.start(execute_now=True)
        self._dmesg_monitor.start()
        return self

    def __exit__(self, *_):
        for task_name, task in self._refresh_tasks.items():
            try:
                task.stop_and_wait()
            except:
                self._logger.exception(
                    f"Error stopping refresh task {task_name}.")
        self._dmesg_monitor.stop()
        return False

    def _set_undervoltage(self):
        self._last_undervoltage_time = time.monotonic()

    @property
    def undervoltage(self) -> bool:
        """Whether undervoltage has been detected recently."""
        earliest_undervoltage_time = (
            time.monotonic() - self.UNDERVOLTAGE_RESET_TIMEOUT)
        return self._last_undervoltage_time > earliest_undervoltage_time

    @property
    def system_info(self) -> SystemInfo:
        if not self._refresh_tasks["system_info"].running:
            raise ValueError("System info refresh task is not running.")
        # If we don't have a cached info, wait for it, otherwise return
        # whatever we have now.
        if not self._system_info:
            lock = self._system_info_lock
        else:
            lock = threading.Lock()
        with lock:
            return self._system_info

    @property
    @ft.cache
    def timezones(self) -> list[str]:
        if not self.ZONEINFO_DIR.is_dir():
            return ["UTC"]
        timezones = []
        for root, dirs, files in self.ZONEINFO_DIR.walk():
            # Filter out common non-timezone directories.
            dirs[:] = [d for d in dirs if d not in ["Etc", "posix", "right"]]
            for file in files:
                # Filter out common non-timezone files.
                if file not in ["posixrules", "localtime", "rightzone",
                                "zone.tab", "iso3166.tab", "zone1970.tab",
                                "leapseconds.list"]:
                    relative_path = (root / file).relative_to(
                        self.ZONEINFO_DIR)
                    timezones.append(str(relative_path))
        return sorted(timezones)

    def set_timezone(self, timezone):
        try:
            util.shell_with_combined_output(
                f"timedatectl set-timezone {timezone}", check=True)
            return
        except:
            self._logger.exception(
                f"Failed to set timezone {timezone} using timedatectl, trying "
                "to link timezone file instead.")
        # timedatectl can fail on dietpi installs (Failed to connect to
        # bus: No such file or directory), and on postmarketOS (Access denied,
        # even as root). Just link the time zone file and restart the
        # corresponding service.
        timezone_file = self.ZONEINFO_DIR / timezone
        if not timezone_file.is_file():
            raise ValueError(f"Timezone file {timezone_file} doesn't exist.")
        try:
            util.shell_with_combined_output(
                f"ln -sf {timezone_file} /etc/localtime", check=True)
        except Exception as e:
            raise ValueError(
                "Unable to set time zone by linking timezone file.") from e
        self._logger.debug("Linked time zone file.")
        try:
            procs = systemctl().run(["restart"], ["systemd-timedated"])
            procs[0].check_returncode()
            return
        except:
            self._logger.exception(
                "Unable to apply time zone change by restarting "
                "systemd-timedated.")
        try:
            util.shell_with_combined_output(
                "dpkg-reconfigure --frontend noninteractive tzdata",
                check=True)
        except Exception as e:
            raise ValueError(
                "Unable to apply time zone change by running dpkg-reconfigure."
            )

    def update_system_info(self):
        with self._system_info_lock:
            try:
                external_ip = self._get_external_ip()
            except:
                self._logger.exception("Error getting external IP.")
                external_ip = None
            try:
                network_device_infos = self._get_network_device_infos()
            except:
                self._logger.exception("Error getting network device infos.")
                network_device_infos = []
            self._system_info = SystemInfo(
                external_ip=external_ip,
                network_device_infos=network_device_infos,
                dns_is_working=self._dns_is_working(),
                has_low_disk=self._has_low_disk())

    @property
    def containers(self) -> list[ContainerInfo]:
        if not self._refresh_tasks["containers"].running:
            raise ValueError("Container info refresh task is not running.")
        # If we don't have a cached info, wait for it, otherwise return
        # whatever we have now.
        if not self._containers:
            lock = self._containers_lock
        else:
            lock = threading.Lock()
        with lock:
            return self._containers

    def _update_docker_containers(self):
        with self._containers_lock:
            proc = util.shell_with_combined_output(
                "docker ps -a "
                "--filter 'label=de.navisense/part-of=adsb-feeder' "
                "--format json")
            try:
                proc.check_returncode()
            except:
                self._logger.exception(
                    "Error checking Docker container status.")
            container_infos = []
            for line in proc.stdout.splitlines():
                container_dict = json.loads(line)
                try:
                    base_image, tag = container_dict["Image"].split(":")
                except ValueError:
                    base_image, tag = container_dict["Image"], None
                container_infos.append(
                    ContainerInfo(
                        id=container_dict["ID"],
                        name=container_dict["Names"],
                        state=container_dict["State"],
                        status=container_dict["Status"],
                        base_image=base_image,
                        tag=tag,
                    ))
            self._containers = container_infos

    def _get_external_ip(self) -> Optional[str]:
        """Get our external IP in the public internet."""
        # Force IPv4, so we don't get an IPv6 back.
        requests.packages.urllib3.util.connection.HAS_IPV6 = False
        headers = {
            "User-Agent": "Python3/requests/adsb.im", "Accept": "text/plain"}
        response = requests.get("https://api.ipify.org", headers=headers)
        response.raise_for_status()
        return response.text or None

    def _get_network_device_infos(self) -> list[NetworkDeviceInfo]:
        """Get information about network devices."""
        # First, get all network interfaces.
        link_proc = util.shell_with_combined_output(
            "ip --json link show", check=True)
        link_infos = json.loads(link_proc.stdout)
        device_names = [i["ifname"] for i in link_infos]
        # Then, get routing information to determine default routes and IPs.
        route_proc = util.shell_with_combined_output(
            "ip --json route show", check=True)
        route_infos = json.loads(route_proc.stdout)

        device_infos = []
        for device_name in device_names:
            ip, gateway, wifi_control = None, None, None
            try:
                default_route_info = next(
                    ri for ri in route_infos
                    if ri["dev"] == device_name and ri["dst"] == "default")
                gateway = default_route_info["gateway"]
                ip = default_route_info["prefsrc"]
                # This device has a default route, so it is used for network
                # access.
                used_for_network_access = True
            except StopIteration:
                # This device does not have a default route, so it is not used
                # for network access.
                used_for_network_access = False
            if any(device_name.startswith(prefix)
                   for prefix in ["wlan", "wlp", "ath"]):
                wifi_control = self._get_wifi_control(device_name)

            device_infos.append(
                NetworkDeviceInfo(
                    device=device_name,
                    used_for_network_access=used_for_network_access,
                    ip=ip,
                    gateway=gateway,
                    wifi=wifi_control,
                ))
        return device_infos

    def _get_wifi_control(self, device_name):
        try:
            return self._wifi_controls[device_name]
        except KeyError:
            wifi_control = wifi.make_wifi(device_name)
            self._wifi_controls[device_name] = wifi_control
            return wifi_control

    def _dns_is_working(self):
        try:
            for addr_info in socket.getaddrinfo("porttracker.co", 0):
                sock_addr = addr_info[4]
                if sock_addr[0]:
                    # We're able to resolve the hostname.
                    return True
        except:
            pass
        self._logger.exception("DNS seems to not be working.")
        return False

    def _has_low_disk(self):
        return shutil.disk_usage("/").free < self.LOW_DISK_THRESHOLD

    @property
    def wifi(self) -> Optional[wifi.GenericWifi]:
        ndis = self.system_info.network_device_infos
        return next(((device.wifi for device in ndis if device.wifi)), None)

    def _update_wifi_info(self):
        for device_info in self.system_info.network_device_infos:
            if device_info.wifi:
                device_info.wifi.refresh_ssid()
                device_info.wifi.scan_ssids()

    @property
    def is_restarting(self):
        return self._restart.is_restarting

    def shutdown_action(self, action="", delay=0):
        if (action == "shutdown"):
            cmd = "shutdown now"
        elif (action == "reboot"):
            cmd = "reboot"
        else:
            self._logger.error(f"Unknown shutdown action: {action}")
            return

        self._logger.info(f"Shutdown action: {action}")

        # best effort: allow reboot / shutdown even if lock is held
        gotLock = self._restart.lock.acquire(blocking=False)

        def do_action():
            time.sleep(delay)
            subprocess.call(cmd, shell=True)
            # just in case the reboot doesn't work,
            # release the lock after 30 seconds:
            if gotLock:
                time.sleep(30)
                self._restart.lock.release()

        threading.Thread(target=do_action).start()

    def shutdown(self, delay=0) -> None:
        self.shutdown_action(action="shutdown", delay=delay)

    def reboot(self, delay=0) -> None:
        self.shutdown_action(action="reboot", delay=delay)

    def os_update(self) -> None:
        util.shell_with_combined_output(
            "systemd-run --wait -u adsb-feeder-update-os "
            "/bin/bash /opt/adsb/scripts/update-os.bash")

    def is_ipv6_broken(self):
        try:
            util.shell_with_combined_output(
                "ip -6 addr show scope global "
                "$(ip -j route get 1.2.3.4 | jq '.[0].dev' -r) "
                "| grep inet6 | grep -v 'inet6 f'", timeout=2, check=True)
        except subprocess.SubprocessError:
            # Timeout or no global ipv6 addresses assigned, this means we don't
            # have ipv6 so it can't be broken.
            return False
        # We have at least one global ipv6 address, check if it works.
        try:
            util.shell_with_combined_output(
                "curl -o /dev/null -6 https://google.com", timeout=2,
                check=True)
            return False
        except subprocess.SubprocessError:
            return True

    def restart_containers(self, containers):
        self._logger.info(f"Restarting docker containers {containers}")
        try:
            subprocess.run(["/opt/adsb/docker-compose-adsb", "restart"]
                           + containers)
        except:
            self._logger.exception("docker compose restart failed")

    def recreate_containers(self, containers):
        self._logger.info(f"Recreating docker containers {containers}")
        try:
            subprocess.run(
                ["/opt/adsb/docker-compose-adsb", "down", "--remove-orphans"]
                + containers)
            subprocess.run([
                "/opt/adsb/docker-compose-adsb", "up", "-d",
                "--force-recreate", "--remove-orphans"] + containers)
        except:
            self._logger.exception("docker compose recreate failed")

    def get_tailscale_info(self) -> TailscaleInfo:
        try:
            proc = util.shell_with_combined_output("which tailscale")
            if proc.returncode != 0:
                return TailscaleInfo(status=TailscaleStatus.NOT_INSTALLED)
            proc, = systemctl().run(["status"], ["tailscaled"],
                                    log_errors=False)
            if proc.returncode != 0:
                return TailscaleInfo(status=TailscaleStatus.DISABLED)
            proc = util.shell_with_separate_output("tailscale status --json")
            if proc.returncode != 0:
                self._logger.error(
                    f"tailscale status --json returned an error: {proc.stdout}"
                )
                return TailscaleInfo(status=TailscaleStatus.ERROR)
            status_json = json.loads(proc.stdout)
            if status_json["BackendState"] == "NeedsLogin":
                return TailscaleInfo(status=TailscaleStatus.LOGGED_OUT)
            if status_json["BackendState"] == "Running":
                return TailscaleInfo(
                    status=TailscaleStatus.LOGGED_IN,
                    ips=status_json["Self"]["TailscaleIPs"],
                    hostname=status_json["Self"]["HostName"],
                    dns_name=status_json["Self"]["DNSName"],
                )
            return TailscaleInfo(status=TailscaleStatus.NO_STATE)
        except:
            self._logger.exception("Error getting Tailscale info.")
            return TailscaleInfo(status=TailscaleStatus.ERROR)

    def has_graphical_system(self):
        """
        Check whether the system has a graphical UI that can be used.

        There is no really good way of determining this. What we're doing here
        is check if there is any process matching "/usr/bin/X" or "wayland". If
        not, there can't be a graphical system.

        If there is we keep checking for a few seconds that it stays. We have
        to do this because even on a headless system, these can be installed
        and be stuck in a restarting loop where they exist for a short time. If
        we don't see it vanish, we assume there is a graphical system.
        """
        check_seconds = 20
        check_until = time.monotonic() + check_seconds
        while time.monotonic() <= check_until:
            proc = util.shell_with_combined_output(
                "ps aux | grep -E '/usr/bin/X|wayland' | grep -v grep")
            if proc.returncode != 0:
                self._logger.debug(
                    "No trace of X or wayland in processes, assuming there is "
                    "no graphical system.")
                return False
            time.sleep(0.5)
        self._logger.debug(
            "A process matching X or wayland has been running for "
            f"{check_seconds}, assuming the graphical system is available.")
        return True


_systemctl: Systemctl = None


def systemctl() -> Systemctl:
    """Get the global instance of Systemctl."""
    global _systemctl
    if _systemctl is None:
        _systemctl = Systemctl()
    return _systemctl
