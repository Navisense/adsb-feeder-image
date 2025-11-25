import json
import logging
import re
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
    """
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

    def start(self):
        # Zeroconf starts on construction.
        assert self._zeroconf.started

    def stop(self):
        self._service_browser.cancel()
        self._zeroconf.close()

    @property
    def other_feeder_names(self) -> frozenset[str]:
        return frozenset(self._other_feeder_names)

    def update_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            self._logger.info(
                f"Other feeder {other_feeder_name} has gone away.")
            self._other_feeder_names.discard(other_feeder_name)

    def add_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            self._logger.info(f"Discovered other feeder {other_feeder_name}.")
            self._other_feeder_names.add(other_feeder_name)

    def _extract_other_feeder_name(self, service_name):
        match = self._service_name_regex.match(service_name)
        if not match:
            return None
        feeder_name = match.group("hostname")
        if feeder_name == self._own_feeder_name:
            return None
        return feeder_name
