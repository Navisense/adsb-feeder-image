import functools as ft
import hashlib
import logging
import os
import pathlib
import re
import secrets
import requests
import subprocess
import tempfile
import threading
from typing import Optional

import flask

logger = logging.getLogger(__name__)


def get_device_id() -> str:
    """
    Create a unique device ID.

    This is based on /etc/machine-id and should be unique, but also anonymous.
    """
    machine_id_bytes = pathlib.Path("/etc/machine-id").read_bytes()
    return hashlib.md5(machine_id_bytes).hexdigest()


def cleanup_str(s: str) -> str:
    """Remove non-printable characters."""
    return "".join(c for c in s if c.isprintable())


# This is based on https://www.regular-expressions.info/email.html
def is_email(text: str):
    return re.match(
        r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, flags=re.IGNORECASE)


def checkbox_checked(value: Optional[str]) -> bool:
    """
    Parse a POST form checkbox as a bool.

    This relies on a small Javascript snippet that rewrites the value of any
    checked checkbox to "1", and of any unchecked one to "0". Normally,
    unchecked checkboxes don't appear in the form at all. If any values other
    than "0" or "1" are encountered, a warning is logged and False returned.
    """
    if value == "0":
        return False
    elif value == "1":
        return True
    logger.warning(
        f"Encountered unexpected value {value} when parsing a checkbox value. "
        "These should only ever contain the strings \"0\" or \"1\", as set by "
        "a necessary Javascript hook. This indicates a serious problem.")
    return False


def make_int(value):
    try:
        return int(value)
    except:
        logger.exception("Error parsing int, returning 0.")
        return 0


def generic_get_json(url: str, data=None, timeout=5.0):
    requests.packages.urllib3.util.connection.HAS_IPV6 = False
    if "host.docker.internal" in url:
        url = url.replace("host.docker.internal", "localhost")
    # use image specific but random value for user agent to distinguish
    # between requests from the same IP but different feeders
    agent = f"Porttracker SDR Feeder {get_device_id()[:8]}"
    status = -1
    try:
        response = requests.request(
            method="GET" if data == None else "POST",
            url=url,
            timeout=timeout,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": agent,},
        )
        json_response = response.json()
    except (
            requests.HTTPError,
            requests.ConnectionError,
            requests.Timeout,
            requests.RequestException,
    ) as err:
        logger.exception(f"Getting JSON from {url} failed.")
        status = err.errno
    except:
        logger.exception(f"Getting JSON from {url} failed.")
    else:
        return json_response, response.status_code
    return None, status


def create_fake_cpu_info():
    os.makedirs("/opt/adsb/rb/thermal_zone0", exist_ok=True)
    cpuinfo = pathlib.Path("/opt/adsb/rb/cpuinfo")
    # When docker tries to mount this file without it existing, it creates a
    # directory. If that has happened, remove it.
    if cpuinfo.is_dir():
        try:
            cpuinfo.rmdir()
        except:
            pass
    if not cpuinfo.exists():
        with open("/proc/cpuinfo", "r") as ci_in, open(cpuinfo, "w") as ci_out:
            for line in ci_in:
                if not line.startswith("Serial"):
                    ci_out.write(line)
            random_hex_string = secrets.token_hex(8)
            ci_out.write(f"Serial\t\t: {random_hex_string}\n")

    if not pathlib.Path("/opt/adsb/rb/thermal_zone0/temp").exists():
        with open("/opt/adsb/rb/thermal_zone0/temp", "w") as fake_temp:
            fake_temp.write("12345\n")
    return not pathlib.Path("/sys/class/thermal/thermal_zone0/temp").exists()


def write_string_to_file(string: str, file: pathlib.Path):
    if file.exists() and not file.is_file():
        raise ValueError(f"{file} exists, but is not a file")
    try:
        fd, tmp_path = tempfile.mkstemp(dir=file.parent, text=True)
        with open(fd, "w") as f:
            f.write(string)
        os.rename(tmp_path, file)
    except Exception:
        logger.exception(f'Error writing "{string}" to {file}.')


def get_plain_url(plain_url):
    requests.packages.urllib3.util.connection.HAS_IPV6 = False
    status = -1
    try:
        response = requests.get(
            plain_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",},
        )
    except (
            requests.HTTPError,
            requests.ConnectionError,
            requests.Timeout,
            requests.RequestException,
    ) as err:
        logger.exception(f"Getting text from {plain_url} failed.")
        status = err.errno
    except:
        logger.exception(f"Getting text from {plain_url} failed.")
    else:
        return response.text, response.status_code
    return None, status


def get_baseos():
    """Identify the underlying OS."""
    if os.path.exists("/boot/dietpi"):
        return "dietpi"
    elif os.path.exists("/etc/rpi-issue"):
        return "raspbian"
    return read_os_release().get("ID", "unknown")


def read_os_release():
    """Read /etc/os-release and return as a dict."""
    data = {}
    try:
        lines = pathlib.Path("/etc/os-release").read_text().split('\n')
    except:
        logger.exception("Error reading /etc/os-release.")
        return data
    for line in filter(None, lines):
        try:
            key, value = line.split("=", maxsplit=1)
        except ValueError:
            logger.exception(f"Unexpected line in /etc/os-release: {line}.")
            continue
        data[key] = _stripped_quotes(value)
    return data


def _stripped_quotes(s):
    """Strip equal quotes from beginning and end, if any."""
    for char in ['"', "'"]:
        if s and s[0] == char and s[-1] == char:
            return s[1:-1]
    return s


def shell_with_combined_output(args, **kwargs):
    """Execute in shell, combine stdout and stderr, return text."""
    for key in ["shell", "text", "stdout", "stderr", "capture_output"]:
        if key in kwargs:
            raise ValueError(f"Argument {key} must not be used.")
    return subprocess.run(
        args, **kwargs, shell=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)


def shell_with_separate_output(args, **kwargs):
    """Execute in shell, capture stdout and stderr, return text."""
    for key in ["shell", "text", "stdout", "stderr", "capture_output"]:
        if key in kwargs:
            raise ValueError(f"Argument {key} must not be used.")
    return subprocess.run(
        args, **kwargs, shell=True, text=True, capture_output=True)


def format_binary_prefix(num):
    """Format a number with a binary prefix."""
    for prefix in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024:
            break
        num /= 1024
    else:
        prefix = "Yi"
    if num == int(num):
        return f"{num}{prefix}"
    return f"{num:.1f}{prefix}"


@ft.total_ordering
class Semver:
    """A semantic version, prefixed with 'v'."""
    _regex = re.compile(r'^v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$')

    def __init__(self, major: int, minor: int, patch: int):
        if any(p < 0 for p in [major, minor, patch]):
            raise ValueError("Semver parts must be >= 0.")
        self._major = major
        self._minor = minor
        self._patch = patch

    def __str__(self) -> str:
        return f"v{self._major}.{self._minor}.{self._patch}"

    def __eq__(self, other: "Semver") -> bool:
        if not isinstance(other, Semver):
            return False
        return (
            self._major == other._major and self._minor == other._minor
            and self._patch == other._patch)

    def __lt__(self, other: "Semver") -> bool:
        if not isinstance(other, Semver):
            raise TypeError
        if self._major != other._major:
            return self._major < other._major
        if self._minor != other._minor:
            return self._minor < other._minor
        return self._patch < other._patch

    @staticmethod
    def parse(s: str) -> "Semver":
        match = Semver._regex.match(s)
        if not match:
            raise ValueError("Invalid format.")
        return Semver(
            int(match.group("major")), int(match.group("minor")),
            int(match.group("patch")))

    @staticmethod
    def is_semver(s: str) -> bool:
        """Check whether the string represents a semver."""
        try:
            Semver.parse(s)
            return True
        except ValueError:
            return False


class FlashingLogger(logging.getLoggerClass()):
    """
    Logger that can flash messages to the frontend.

    Overrides the logging functions with an additional parameter flash_message.
    If set, it uses flask's flash() method to store a message to be shown to
    the user on the next request. The category is set based on the log level.

    flash_message may be the message to show, or a boolean. If simply set to
    True, the same message that is logged will be flashed.
    """
    def log(
            self, level: int, msg: str, *args,
            flash_message: bool | str = False, **kwargs):
        if level in [logging.DEBUG, logging.INFO]:
            category = "info"
        elif level == logging.WARNING:
            category = "warning"
        elif level in [logging.ERROR, logging.CRITICAL]:
            category = "error"
        else:
            category = "message"
        self._maybe_flash(flash_message, msg, category)
        return super().log(level, msg, *args, **kwargs)

    def debug(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "info")
        return super().debug(msg, *args, **kwargs)

    def info(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "info")
        return super().info(msg, *args, **kwargs)

    def warning(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "warning")
        return super().warning(msg, *args, **kwargs)

    def error(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "error")
        return super().error(msg, *args, **kwargs)

    def critical(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "error")
        return super().critical(msg, *args, **kwargs)

    def exception(
            self, msg: str, *args, flash_message: bool | str = False,
            **kwargs):
        self._maybe_flash(flash_message, msg, "error")
        return super().exception(msg, *args, **kwargs)

    def _maybe_flash(self, flash_message, msg, category):
        if not flash_message:
            return
        elif flash_message is True:
            flash_message = msg
        if not flask.has_request_context():
            self.error(
                "This logger was used to try and flash a message, but the "
                "necessary Flask request context is not available.")
        else:
            flask.flash(flash_message, category)


class RepeatingTask:
    """Background task that keeps repeating."""
    def __init__(self, interval, function):
        self._logger = logging.getLogger(type(self).__name__)
        self._interval = interval
        self._function = function
        self._timer = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return bool(self._timer)

    def start(self, *, execute_now=False):
        with self._lock:
            if self._timer:
                raise ValueError("Already started.")
            if execute_now:
                self._run_locked()
            self._schedule_locked()

    def stop_and_wait(self):
        with self._lock:
            if not self._timer:
                raise ValueError("Not running.")
            self._timer.cancel()
            try:
                self._timer.join()
            except RuntimeError:
                # Thread wasn't running, that's fine.
                pass
            self._timer = None

    def _run_and_schedule(self):
        with self._lock:
            self._run_locked()
            self._schedule_locked()

    def _run_locked(self):
        try:
            self._function()
        except:
            self._logger.exception(f"Error executing {self._function}.")

    def _schedule_locked(self):
        self._timer = threading.Timer(self._interval, self._run_and_schedule)
        self._timer.start()
