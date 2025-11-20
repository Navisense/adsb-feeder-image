import dataclasses as dc
import enum
import ipaddress
import json
import logging
import socket
import subprocess
import threading
import time
from typing import Optional

import requests

import util


@dc.dataclass
class NetworkDeviceInfo:
    gateway: str
    device: str
    ip: str


@dc.dataclass
class SystemInfo:
    external_ip: Optional[str]
    network_device_infos: list[NetworkDeviceInfo]


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


class System:
    """
    Access to system functions.

    Provides properties for system info and Docker containers belonging to the
    application. Both are regularly refreshed in background tasks that are
    started and stopped by the class' context manager.
    """
    INFO_REFRESH_INTERVAL = 300
    CONTAINERS_REFRESH_INTERVAL = 10

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self._restart = Restart()
        self._system_info = None
        self._system_info_lock = threading.Lock()
        self._containers = None
        self._containers_lock = threading.Lock()
        self._refresh_tasks = {
            "system_info": util.RepeatingTask(
                self.INFO_REFRESH_INTERVAL, self._update_system_info),
            "containers": util.RepeatingTask(
                self.CONTAINERS_REFRESH_INTERVAL,
                self._update_docker_containers)}

    def __enter__(self):
        for task in self._refresh_tasks.values():
            task.start(execute_now=True)
        return self

    def __exit__(self, *_):
        for task in self._refresh_tasks.values():
            try:
                task.stop_and_wait()
            except:
                self._logger.exception("Error stopping refresh task.")
        return False

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

    def _update_system_info(self):
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
                network_device_infos=network_device_infos)

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
        proc = util.shell_with_combined_output("ip --json route show")
        proc.check_returncode()
        route_infos = json.loads(proc.stdout)
        device_infos = []
        for route_info in route_infos:
            try:
                if route_info["dst"] != "default":
                    continue
                device_infos.append(
                    NetworkDeviceInfo(
                        gateway=route_info["gateway"],
                        device=route_info["dev"],
                        ip=route_info["prefsrc"],
                    ))
            except KeyError:
                continue
        return device_infos

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

    def check_dns(self):
        try:
            responses = list(
                i[4][0]  # raw socket structure/internet protocol info/address
                for i in socket.getaddrinfo("adsb.im", 0)
                # if i[0] is socket.AddressFamily.AF_INET
                # and i[1] is socket.SocketKind.SOCK_RAW
            )
        except:
            return False
        return responses != list()

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
