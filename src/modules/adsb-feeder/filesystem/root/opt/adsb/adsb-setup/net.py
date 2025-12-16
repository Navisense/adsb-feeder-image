import dataclasses as dc
import ipaddress
import itertools as it
import json
import logging
import re
import threading
import urllib.request

import zeroconf as zc

import util


class GithubRepo:
    API_BASE_URL = (
        "https://api.github.com/repos/maritime-datasystems/adsb-feeder-image")

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
        url = self.API_BASE_URL + "/tags"
        try:
            with urllib.request.urlopen(url) as response:
                json_response = json.load(response)
            return [tag["name"] for tag in json_response]
        except:
            self._logger.exception("Error getting available tags.")
            return []


_github_repo: GithubRepo = None


def github_repo() -> GithubRepo:
    """Get the global instance of GithubRepo."""
    global _github_repo
    if _github_repo is None:
        _github_repo = GithubRepo()
    return _github_repo


@dc.dataclass
class FeederInfo:
    feeder_name: str
    ip_addresses: list[ipaddress.IPv4Address]


class FeederDiscoverer(zc.ServiceListener):
    """
    Service discovering other feeder devices.

    Uses zeroconf to discover services advertised on the network that look like
    Porttracker SDR services (i.e. <xxxxxxxx>-porttracker-sdr). Provides the
    other_feeders property, which contains info on all other feeders that have
    been discovered.

    When a service announces that it goes offline, it will only be removed from
    other_feeders after a short grace period. That's because we restart the
    avahi-publish process regularly, but the service should remain visible.
    """
    REMOVE_GRACE_PERIOD = 5
    _service_name_regex = re.compile(
        r'(?P<hostname>[0-9a-fA-F]{8}-porttracker-sdr)\._http\._tcp\.local\.')

    def __init__(self, own_feeder_name):
        """
        :param own_feeder_name: The name of this feeder. Will be excluded from
            other_feeders.
        """
        self._logger = logging.getLogger(type(self).__name__)
        self._own_feeder_name = own_feeder_name
        self._zeroconf = zc.Zeroconf()
        self._service_browser = zc.ServiceBrowser(
            self._zeroconf, "_http._tcp.local.", self)
        self._other_feeders = {}
        self._other_feeders_timeout = {}
        self._dict_lock = threading.Lock()

    def start(self):
        # Zeroconf starts on construction.
        assert self._zeroconf.started

    def stop(self):
        self._service_browser.cancel()
        self._zeroconf.close()

    @property
    def other_feeders(self) -> list[FeederInfo]:
        with self._dict_lock:
            return list(
                it.chain(
                    self._other_feeders.values(),
                    self._other_feeders_timeout.values()))

    def add_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            with self._dict_lock:
                if other_feeder_name in self._other_feeders_timeout:
                    self._logger.debug(f"{other_feeder_name} is back.")
                else:
                    self._logger.info(
                        f"Discovered new other feeder {other_feeder_name}.")
                self._add_feeder_info(type_, name, other_feeder_name)

    def _add_feeder_info(self, type_, name, other_feeder_name):
        service_info = self._zeroconf.get_service_info(type_, name)
        if service_info is None:
            self._logger.error(f"Unable to get service info for {name}")
            return
        ip_addresses = sorted(
            ipaddress.IPv4Address(a)
            for a in service_info.addresses_by_version(zc.IPVersion.V4Only))
        self._other_feeders[other_feeder_name] = FeederInfo(
            feeder_name=other_feeder_name, ip_addresses=ip_addresses)
        self._other_feeders_timeout.pop(other_feeder_name, None)

    def update_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            self._logger.info(f"Received update for {other_feeder_name}.")
            with self._dict_lock:
                self._add_feeder_info(type_, name, other_feeder_name)

    def remove_service(self, zc: zc.Zeroconf, type_: str, name: str) -> None:
        if (other_feeder_name := self._extract_other_feeder_name(name)):
            with self._dict_lock:
                self._logger.debug(
                    f"Other feeder {other_feeder_name} has gone away, moving "
                    "it into timeout dict to be removed in "
                    f"{self.REMOVE_GRACE_PERIOD}s.")
                try:
                    # Move the name to the timeout dict so it will still be
                    # returned for a while.
                    other_feeder = self._other_feeders.pop(other_feeder_name)
                    self._other_feeders_timeout[other_feeder_name] = (
                        other_feeder)
                except KeyError:
                    # This feeder wasn't known anyway, nothing to do.
                    return
                # Start a timer to remove the name even from the timeout dict
                # so it disappears completely. If it reappears in the meantime,
                # it will be in the regular dict again.
                threading.Timer(
                    self.REMOVE_GRACE_PERIOD,
                    self._maybe_remove_other_feeder_completely,
                    args=(other_feeder_name,))

    def _maybe_remove_other_feeder_completely(self, other_feeder_name):
        with self._dict_lock:
            self._other_feeders_timeout.pop(other_feeder_name, None)

    def _extract_other_feeder_name(self, service_name):
        match = self._service_name_regex.match(service_name)
        if not match:
            return None
        feeder_name = match.group("hostname")
        if feeder_name == self._own_feeder_name:
            return None
        return feeder_name
