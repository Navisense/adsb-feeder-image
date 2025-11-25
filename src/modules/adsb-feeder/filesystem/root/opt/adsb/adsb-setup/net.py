import itertools as it
import json
import logging
import re
import threading
import urllib.request

import zeroconf as zc

import util


class GitlabRepo:
    API_BASE_URL = "https://gitlab.navisense.de/api/v4/projects/96"

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def get_semver_tags(self) -> list[util.Semver]:
        """Get tags that are semvers, latest first."""
        semvers = []
        for tag in self.get_tags():
            try:
                semvers.append(util.Semver.parse(tag))
            except ValueError:
                pass
        return sorted(semvers, reverse=True)

    def get_tags(self) -> list[str]:
        url = self.API_BASE_URL + "/repository/tags"
        try:
            with urllib.request.urlopen(url) as response:
                json_response = json.load(response)
            return [tag["name"] for tag in json_response]
        except:
            self._logger.exception("Error getting available tags.")
            return []


_gitlab_repo: GitlabRepo = None


def gitlab_repo() -> GitlabRepo:
    """Get the global instance of GitlabRepo."""
    global _gitlab_repo
    if _gitlab_repo is None:
        _gitlab_repo = GitlabRepo()
    return _gitlab_repo


class FeederDiscoverer(zc.ServiceListener):
    """
    Service discovering other feeder devices.

    Uses zeroconf to discover services advertised on the network that look like
    Porttracker SDR services (i.e. <xxxxxxxx>-porttracker-sdr). Provides the
    other_feeder_names property, which contains the names of all other feeders
    that have been discovered.

    When a service announces that it goes offline, it will only be removed from
    other_feeder_names after a short grace period. That's because we restart
    the avahi-publish process regularly, but the service should remain visible.
    """
    REMOVE_GRACE_PERIOD = 5
    _service_name_regex = re.compile(
        r'(?P<hostname>[0-9a-fA-F]{8}-porttracker-sdr)\._http\._tcp\.local\.')

    def __init__(self, own_feeder_name):
        """
        :param own_feeder_name: The name of this feeder. Will be excluded from
            the other_feeder_names set.
        """
        self._logger = logging.getLogger(type(self).__name__)
        self._own_feeder_name = own_feeder_name
        self._zeroconf = zc.Zeroconf()
        self._service_browser = zc.ServiceBrowser(
            self._zeroconf, "_http._tcp.local.", self)
        self._other_feeder_names = set()
        self._other_feeder_names_timeout = set()
        self._set_lock = threading.Lock()

    def start(self):
        # Zeroconf starts on construction.
        assert self._zeroconf.started

    def stop(self):
        self._service_browser.cancel()
        self._zeroconf.close()

    @property
    def other_feeder_names(self) -> frozenset[str]:
        with self._set_lock:
            return frozenset(
                it.chain(
                    self._other_feeder_names,
                    self._other_feeder_names_timeout))

    def add_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            with self._set_lock:
                if other_feeder_name in self._other_feeder_names_timeout:
                    self._logger.debug(f"{other_feeder_name} is back.")
                else:
                    self._logger.info(
                        f"Discovered new other feeder {other_feeder_name}.")
                self._other_feeder_names.add(other_feeder_name)
                self._other_feeder_names_timeout.discard(other_feeder_name)

    def remove_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            with self._set_lock:
                self._logger.debug(
                    f"Other feeder {other_feeder_name} has gone away, moving "
                    "it into timeout set to be removed in "
                    f"{self.REMOVE_GRACE_PERIOD}s.")
                # Move the name to the timeout set so it will still be returned
                # for a while.
                self._other_feeder_names_timeout.add(other_feeder_name)
                self._other_feeder_names.discard(other_feeder_name)
                # Start a timer to remove the name even from the timeout set so
                # it disappears completely. If it reappears in the meantime, it
                # will be in the regular set again.
                threading.Timer(
                    self.REMOVE_GRACE_PERIOD,
                    self._maybe_remove_other_feeder_completely,
                    args=(other_feeder_name,))

    def _maybe_remove_other_feeder_completely(self, other_feeder_name):
        with self._set_lock:
            self._other_feeder_names_timeout.discard(other_feeder_name)

    def _extract_other_feeder_name(self, service_name):
        match = self._service_name_regex.match(service_name)
        if not match:
            return None
        feeder_name = match.group("hostname")
        if feeder_name == self._own_feeder_name:
            return None
        return feeder_name

    def update_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        pass
