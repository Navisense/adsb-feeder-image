import logging
import requests
import socket
import subprocess
import threading
import time

from .data import Data
from .util import print_err, run_shell_captured, shell_with_combined_output


class Systemctl:
    """Serialized access to systemctl."""
    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self._lock = threading.Lock()

    def run(
            self, commands: list[str], units: list[str], *,
            log_errors: bool = True):
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
                proc = shell_with_combined_output(
                    f"systemctl {command} {units_str}")
                if proc.returncode and log_errors:
                    self._logger.error(f"systemctl failed: {proc.stdout}")
                procs.append(proc)
            return procs

    def run_transient(self, unit_name: str, arguments: list[str]):
        """Run a command using systemd-run."""
        if not arguments:
            raise ValueError("no arguments given")
        shell_with_combined_output(
            f"systemd-run -u {unit_name} " + " ".join(arguments), check=True)


class Restart:
    def __init__(self):
        self.lock = threading.Lock()

    def bg_run(self, cmdline=None, func=None, silent=False):

        if not cmdline and not func:
            print_err(f"WARNING: bg_run called without something to do")
            return False

        gotLock = self.lock.acquire(blocking=False)

        if not gotLock:
            # we could not acquire the lock
            print_err(f"restart locked, couldn't run: {cmdline}")
            return False

        # we have acquired the lock

        def do_restart():
            try:
                if cmdline:
                    print_err(f"Calling {cmdline}")
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
    def __init__(self, data: Data):
        self._restart = Restart()
        self._d = data

        self.gateway_ips = None

        self.containerCheckLock = threading.RLock()
        self.lastContainerCheck = 0
        self.dockerPsCache = dict()

    @property
    def is_restarting(self):
        return self._restart.is_restarting

    def shutdown_action(self, action="", delay=0):
        if (action == "shutdown"):
            cmd = "shutdown now"
        elif (action == "reboot"):
            cmd = "reboot"
        else:
            print_err(f"unknown shutdown action: {action}")
            return

        print_err(f"shutdown action: {action}")

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
        subprocess.call("systemd-run --wait -u adsb-feeder-update-os /bin/bash /opt/adsb/scripts/update-os", shell=True)

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
        success, output = run_shell_captured(
            "ip -6 addr show scope global $(ip -j route get 1.2.3.4 | jq '.[0].dev' -r) | grep inet6 | grep -v 'inet6 f'",
            timeout=2,
        )
        if not success:
            # no global ipv6 addresses assigned, this means we don't have ipv6 so it can't be broken
            return False
        # we have at least one global ipv6 address, check if it works:
        success, output = run_shell_captured("curl -o /dev/null -6 https://google.com", timeout=2)

        if success:
            # it's working, so it's not broken
            return False

        # we have an ipv6 address but curl -6 isn't working
        return True

    def check_ip(self):
        requests.packages.urllib3.util.connection.HAS_IPV6 = False
        status = -1
        try:
            response = requests.get(
                "http://v4.ipv6-test.com/api/myip.php",
                headers={
                    "User-Agent": "Python3/requests/adsb.im",
                    "Accept": "text/plain",
                },
            )
        except (
            requests.HTTPError,
            requests.ConnectionError,
            requests.Timeout,
            requests.RequestException,
        ) as err:
            status = err.errno
        except:
            status = -1
        else:
            return response.text, response.status_code
        return None, status

    def check_gpsd(self):
        # gateway IP shouldn't change on a system, buffer it for the duration the program runs
        if self.gateway_ips:
            gateway_ips = self.gateway_ips
        else:
            # find host address on the docker network
            command = "docker exec adsb-setup-proxy ip route | mawk '/default/{ print($3) }'"
            success, output = run_shell_captured(
                command=command,
                timeout=5,
            )
            if success and len(output.strip()) > 4:
                self.gateway_ips = gateway_ips = [output.strip()]
            else:
                gateway_ips = ["172.17.0.1", "172.18.0.1"]
                print_err(f"ERROR: command: {command} failed with output: {output}")

        print_err(f"gpsd check: checking ips: {gateway_ips}")

        for ip in gateway_ips:
            # Create a TCP socket
            # print_err(f"Checking for gpsd: {ip}:2947")
            s = socket.socket()
            s.settimeout(2)
            try:
                s.connect((ip, 2947))
                print_err(f"Connected to gpsd on {ip}:2947")
                return True
            except socket.error as e:
                print_err(f"No gpsd on {ip}:2947 detected")
            finally:
                s.close()
        return False

    def list_containers(self):
        containers = []
        try:
            result = subprocess.run(
                ["docker", "ps", "--format='{{json .Names}}'"],
                capture_output=True,
                timeout=5,
            )
            output = result.stdout.decode("utf-8")
            for line in output.split("\n"):
                if line and line[1] == '"' and line[-2] == '"':
                    # the names show up as '"ultrafeeder"'
                    containers.append(line[2:-2])
        except subprocess.SubprocessError as e:
            print_err(f"docker ps failed {e}")
        return containers

    def restart_containers(self, containers):
        print_err(f"restarting {containers}")
        try:
            subprocess.run(["/opt/adsb/docker-compose-adsb", "restart"] + containers)
        except:
            print_err("docker compose restart failed")

    def recreate_containers(self, containers):
        print_err(f"recreating {containers}")
        try:
            subprocess.run(["/opt/adsb/docker-compose-adsb", "down", "--remove-orphans"] + containers)
            subprocess.run(["/opt/adsb/docker-compose-adsb", "up", "-d", "--force-recreate", "--remove-orphans"] + containers)
        except:
            print_err("docker compose recreate failed")

    def refreshDockerPs(self):
        with self.containerCheckLock:
            now = time.time()
            if now - self.lastContainerCheck < 10:
                # still fresh, do nothing
                return

            self.lastContainerCheck = now
            self.dockerPsCache = dict()
            cmdline = "docker ps --filter status=running --format '{{.Names}};{{.Status}}'"
            success, output = run_shell_captured(cmdline, timeout=5)
            if not success:
                print_err(f"Error: cmdline: {cmdline} output: {output}")
                return

            for line in output.split("\n"):
                if ";" in line:
                    name, status = line.split(";")
                    self.dockerPsCache[name] = status

    def getContainerStatus(self, name):
        with self.containerCheckLock:

            self.refreshDockerPs()

            status = self.dockerPsCache.get(name)
            # print_err(f"{name}: {status}")
            if not status:
                # assume down
                return "down"

            if not status.startswith("Up"):
                return "down"

            try:
                up, number, unit = status.split(" ")
                if unit == "seconds" and int(number) < 30:
                    # container up for less than 30 seconds, show 'starting'
                    return "starting"
            except:
                if "second" in status:
                    # handle status "Up Less than a second"
                    return "starting"

            return "up"


_systemctl: Systemctl = None


def systemctl() -> Systemctl:
    """Get the global instance of Systemctl."""
    global _systemctl
    if _systemctl is None:
        _systemctl = Systemctl()
    return _systemctl
