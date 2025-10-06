import abc
import enum
import json
import logging
import numbers
import pathlib
import re
import requests
import subprocess
import threading
import time
import typing as t
from typing import Any, Optional
import uuid

import config
import system
import util


class DataStatus(enum.StrEnum):
    UNKNOWN = "unknown"
    DISCONNECTED = "disconnected"
    CONTAINER_DOWN = "container_down"
    STARTING = "starting"
    BAD = "bad"
    WARNING = "warning"
    GOOD = "good"


class MlatStatus(enum.StrEnum):
    UNKNOWN = "unknown"
    DISCONNECTED = "disconnected"
    DISABLED = "disabled"
    BAD = "bad"
    WARNING = "warning"
    GOOD = "good"


class MessageType(enum.StrEnum):
    AIS = "ais"
    ADSB = "adsb"


class AisStatus(t.TypedDict):
    data_status: DataStatus


class AdsbStatus(t.TypedDict):
    data_status: DataStatus
    mlat_status: MlatStatus


class AggregatorStatus(t.TypedDict):
    ais: Optional[AdsbStatus]
    adsb: Optional[AdsbStatus]


class ConfigureError(Exception):
    pass


class StatusCheckError(Exception):
    pass


_aggregator_dict = None


def init_aggregators(conf: config.Config, system: system.System) -> None:
    """
    Initialize all aggregators.

    This populates the module's cache of all aggregators. This must be called
    exactly once before the first call to all_aggregators().
    """
    global _aggregator_dict
    if _aggregator_dict is not None:
        raise ValueError("Aggregators have already been initialized.")
    _aggregator_dict = {}
    aggregators = [
        AdsbLolAggregator(conf, system),
        UltrafeederAggregator(
            conf, system, agg_key="flyitaly", name="Fly Italy ADSB",
            map_url="https://mappa.flyitalyadsb.com/",
            status_url_or_factory="https://my.flyitalyadsb.com/am_i_feeding",
            netconfig=NetConfig(
                "adsb,dati.flyitalyadsb.com,4905,beast_reduce_plus_out",
                "mlat,dati.flyitalyadsb.com,30100,39002", has_policy=True)),
        UltrafeederAggregator(
            conf, system, agg_key="avdelphi", name="AVDelphi",
            map_url="https://www.avdelphi.com/coverage.html",
            status_url_or_factory=None, netconfig=NetConfig(
                "adsb,data.avdelphi.com,24999,beast_reduce_plus_out", "",
                has_policy=True)),
        UltrafeederAggregator(
            conf, system, agg_key="planespotters", name="Planespotters",
            map_url="https://radar.planespotters.net/",
            status_url_or_factory="https://www.planespotters.net/feed/status",
            netconfig=NetConfig(
                "adsb,feed.planespotters.net,30004,beast_reduce_plus_out",
                "mlat,mlat.planespotters.net,31090,39005", has_policy=True)),
        UltrafeederAggregator(
            conf, system, agg_key="tat", name="TheAirTraffic",
            map_url="https://globe.theairtraffic.com/",
            status_url_or_factory="https://theairtraffic.com/feed/myip/",
            netconfig=NetConfig(
                "adsb,feed.theairtraffic.com,30004,beast_reduce_plus_out",
                "mlat,feed.theairtraffic.com,31090,39004", has_policy=False)),
        UltrafeederAggregator(
            conf, system, agg_key="adsbfi", name="adsb.fi",
            map_url="https://globe.adsb.fi/",
            status_url_or_factory="https://api.adsb.fi/v1/myip",
            netconfig=NetConfig(
                "adsb,feed.adsb.fi,30004,beast_reduce_plus_out",
                "mlat,feed.adsb.fi,31090,39007", has_policy=True)),
        AdsbxAggregator(conf, system),
        UltrafeederAggregator(
            conf, system, agg_key="hpradar", name="HPRadar",
            map_url="https://skylink.hpradar.com/", status_url_or_factory=None,
            netconfig=NetConfig(
                "adsb,skyfeed.hpradar.com,30004,beast_reduce_plus_out",
                "mlat,skyfeed.hpradar.com,31090,39011", has_policy=False)),
        AirplanesLiveAggregator(conf, system),
        FlightRadar24Aggregator(conf, system),
        PlaneWatchAggregator(conf, system),
        FlightAwareAggregator(conf, system),
        AirnavRadarAggregator(conf, system),
        PlaneFinderAggregator(conf, system),
        AdsbHubAggregator(conf, system),
        OpenSkyAggregator(conf, system),
        RadarVirtuelAggregator(conf, system),
        TenNinetyUkAggregator(conf, system),
        SdrMapAggregator(conf, system),
        PorttrackerAggregator(conf, system),
        AiscatcherAggregator(conf, system),
        AishubAggregator(conf, system),]
    for aggregator in aggregators:
        assert aggregator.agg_key not in _aggregator_dict
        _aggregator_dict[aggregator.agg_key] = aggregator


def all_aggregators() -> dict[str, "Aggregator"]:
    """
    Get all aggregators.

    Returns a dict mapping each aggregator's key to its instance.
    """
    if _aggregator_dict is None:
        raise ValueError("Aggregators have not been initialized.")
    return _aggregator_dict


class NetConfig:
    """
    Ultrafeeder network config.

    This utility can generate part of the Ultrafeeder config string for a
    particular aggregator.
    """
    def __init__(self, adsb_config: str, mlat_config: str, has_policy: bool):
        self.adsb_config = adsb_config
        self.mlat_config = mlat_config
        self._has_policy = has_policy

    def generate(
            self, mlat_privacy: bool = True, uuid: str = None,
            mlat_enable: bool = True):
        adsb_line = self.adsb_config
        mlat_line = self.mlat_config

        if uuid and len(uuid) == 36:
            adsb_line += f",uuid={uuid}"
            if mlat_line:
                mlat_line += f",uuid={uuid}"
        if mlat_line and mlat_privacy:
            mlat_line += ",--privacy"
        if mlat_enable:
            return f"{adsb_line};{mlat_line}"
        else:
            return adsb_line

    @property
    def has_policy(self):
        return self._has_policy


class Aggregator(abc.ABC):
    MAX_CACHE_AGE = 10

    def __init__(
            self, conf: config.Config, system: system.System, *, agg_key: str,
            name: str, map_url: Optional[str],
            status_url_or_factory: Optional[str]):
        self._logger = logging.getLogger(type(self).__name__)
        self._conf = conf
        self._system = system
        self._agg_key = agg_key
        self._name = name
        self._map_url = map_url
        self._status_url_or_factory = status_url_or_factory
        self._last_check = 0
        self._status = AggregatorStatus(ais=None, adsb=None)
        self._check_lock = threading.Lock()

    def __repr__(self):
        return (
            f"{type(self).__name__}(last_check: {str(self._last_check)}, "
            f"status: {self._status})")

    @property
    def agg_key(self) -> str:
        return self._agg_key

    @property
    def name(self) -> str:
        return self._name

    @property
    def map_url(self) -> Optional[str]:
        return self._map_url

    @property
    def status_url(self) -> Optional[str]:
        if callable(self._status_url_or_factory):
            return self._status_url_or_factory()
        return self._status_url_or_factory

    @property
    @abc.abstractmethod
    def needs_key(self) -> bool:
        """Whether the aggregator needs a key in order to work."""
        raise NotImplementedError

    @property
    def status(self) -> AggregatorStatus:
        self.refresh_status_cache()
        return self._status

    @property
    @abc.abstractmethod
    def capable_message_types(self) -> set[MessageType]:
        """The message types this aggregator can handle."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def _container_name(self) -> str:
        raise NotImplementedError

    def enabled(self, *message_types: MessageType) -> bool:
        """"
        Whether the aggregator is enabled for the given message types.

        If no message types are given, returns whether the aggregator is
        enabled for any message types.
        """
        if not all(t in self.capable_message_types for t in message_types):
            return False
        return self._conf.get(f"aggregators.{self.agg_key}.is_enabled")

    def configure(self, enabled: bool, *args, **kwargs) -> None:
        self._conf.set(f"aggregators.{self.agg_key}.is_enabled", enabled)
        self._logger.info("Enabled." if enabled else "Disabled.")

    def refresh_status_cache(self) -> None:
        """Refresh cached status data."""
        if time.time() - self._last_check < self.MAX_CACHE_AGE:
            return
        try:
            with self._check_lock:
                status = self._get_status_locked()
        except:
            self._logger.exception("Error checking status.")
            status = AggregatorStatus(ais=None, adsb=None)
        self._status = status
        self._last_check = time.time()

    def _get_status_locked(self) -> AggregatorStatus:
        data_status_based_on_container = None
        try:
            container = next(
                c for c in self._system.containers
                if c.name == self._container_name)
            if container.up_less_than(30):
                data_status_based_on_container = DataStatus.STARTING
        except StopIteration:
            data_status_based_on_container = DataStatus.CONTAINER_DOWN
        if data_status_based_on_container:
            return AggregatorStatus(
                ais=None if MessageType.AIS not in self.capable_message_types
                else AisStatus(data_status=data_status_based_on_container),
                adsb=None if MessageType.ADSB not in self.capable_message_types
                else AdsbStatus(
                    data_status=data_status_based_on_container,
                    mlat_status=MlatStatus.DISABLED),
            )

        status = self._check_aggregator_status()
        if not self._conf.get("mlat_enable") and status["adsb"]:
            # If mlat isn't enabled, ignore status check results.
            status["adsb"]["mlat_status"] = MlatStatus.DISABLED
        return status

    @abc.abstractmethod
    def _check_aggregator_status(self) -> AggregatorStatus:
        """
        Check status.

        Returns a fresh status. May raise StatusCheckError or other exceptions
        to indicate that the check couldn't be performed.
        """
        raise NotImplementedError


class UltrafeederAggregator(Aggregator):
    """Simple, ultrafeeder-based aggregator."""
    ULTRAFEEDER_PATH = pathlib.Path("/run/adsb-feeder-ultrafeeder")

    def __init__(
            self, conf: config.Config, system: system.System, *, agg_key: str,
            name: str, map_url: Optional[str],
            status_url_or_factory: Optional[str], netconfig: NetConfig):
        super().__init__(
            conf, system, agg_key=agg_key, name=name, map_url=map_url,
            status_url_or_factory=status_url_or_factory)
        self._netconfig = netconfig

    @property
    def netconfig(self) -> NetConfig:
        return self._netconfig

    @property
    def capable_message_types(self) -> set[MessageType]:
        return {MessageType.ADSB}

    @property
    def _container_name(self) -> str:
        return "ultrafeeder"

    @property
    def needs_key(self) -> bool:
        return False

    def _check_aggregator_status(self) -> AggregatorStatus:
        data_status = self._get_data_status()
        mlat_status = self._get_mlat_status()
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(data_status=data_status, mlat_status=mlat_status))

    def _get_data_status(self) -> DataStatus:
        bconf = self._netconfig.adsb_config
        # example adsb_config:
        # "adsb,dati.flyitalyadsb.com,4905,beast_reduce_plus_out",
        if not bconf:
            self._logger.error(
                f"No adsb_config in netconfig for {self.agg_key}.")
            return DataStatus.UNKNOWN
        pattern = (
            'readsb_net_connector_status{{host="{host}",port="{port}"}} (\\d+)'
            .format(host=bconf.split(',')[1], port=bconf.split(',')[2]))
        stats_file = self.ULTRAFEEDER_PATH / "readsb" / "stats.prom"
        try:
            with stats_file.open() as f:
                readsb_status = f.read()
        except:
            return DataStatus.DISCONNECTED
        match = re.search(pattern, readsb_status)
        if match:
            status = int(match.group(1))
            # this status is the time in seconds the connection has been
            # established
            if status <= 0:
                return DataStatus.DISCONNECTED
            elif status > 20:
                return DataStatus.GOOD
            else:
                return DataStatus.WARNING
        self._logger.error(f"No match checking data status for {pattern}.")
        return DataStatus.UNKNOWN

    def _get_mlat_status(self) -> MlatStatus:
        mconf = self._netconfig.mlat_config
        if not mconf:
            return MlatStatus.DISABLED
        # example mlat_config: "mlat,dati.flyitalyadsb.com,30100,39002",
        filename = f"{mconf.split(',')[1]}:{mconf.split(',')[2]}.json"
        path = self.ULTRAFEEDER_PATH / "mlat-client" / filename
        try:
            with path.open() as f:
                mlat_json = json.load(f)
            percent_good = mlat_json.get("good_sync_percentage_last_hour", 0)
            percent_bad = mlat_json.get("bad_sync_percentage_last_hour", 0)
            now = mlat_json.get("now")
        except:
            return MlatStatus.DISCONNECTED
        if time.time() - now > 60:
            # that's more than a minute old... probably not connected
            return MlatStatus.DISCONNECTED
        elif percent_good > 10 and percent_bad <= 5:
            return MlatStatus.GOOD
        elif percent_bad > 15:
            return MlatStatus.BAD
        else:
            return MlatStatus.WARNING


class AirplanesLiveAggregator(UltrafeederAggregator):
    class AirplanesLiveAdsbStatus(AdsbStatus):
        alive_map_link: str

    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="alive", name="airplanes.live",
            map_url="https://globe.airplanes.live/",
            status_url_or_factory="https://airplanes.live/myfeed/",
            netconfig=NetConfig(
                "adsb,feed.airplanes.live,30004,beast_reduce_plus_out",
                "mlat,feed.airplanes.live,31090,39012", has_policy=True))
        self._alive_map_link = None

    def _check_aggregator_status(self) -> AggregatorStatus:
        status = super()._check_aggregator_status()
        if self._alive_map_link is None:
            json_url = "https://api.airplanes.live/feed-status"
            a_dict, status_code = util.generic_get_json(json_url)
            try:
                assert a_dict and status_code == 200
                self._alive_map_link = a_dict.get("map_link")
                assert self._alive_map_link
            except:
                self._logger.exception(
                    "Unexpected response when checking Airplanes.live map "
                    f"link: {a_dict}")
        status["adsb"]["alive_map_link"] = self._alive_map_link
        return status


class AdsbLolAggregator(UltrafeederAggregator):
    class AdsbLolAdsbStatus(AdsbStatus):
        adsblol_link: str

    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="adsblol", name="adsb.lol",
            map_url="https://adsb.lol/",
            status_url_or_factory="https://api.adsb.lol/0/me",
            netconfig=NetConfig(
                "adsb,feed.adsb.lol,30004,beast_reduce_plus_out",
                "mlat,feed.adsb.lol,31090,39001", has_policy=True))
        self._adsblol_link = None

    def _check_aggregator_status(self) -> AggregatorStatus:
        status = super()._check_aggregator_status()
        if self._adsblol_link is None:
            uuid = self._conf.get("adsblol_uuid")
            json_url = "https://api.adsb.lol/0/me"
            response_dict, status_code = util.generic_get_json(json_url)
            try:
                assert response_dict and status_code == 200
                for entry in response_dict.get("clients").get("beast"):
                    if entry.get("uuid", "xxxxxxxx-xxxx-")[:14] == uuid[:14]:
                        self._adsblol_link = entry.get("adsblol_my_url")
            except:
                self._logger.exception("Error getting map link from adsb.lol.")
        status["adsb"]["adsblol_link"] = self._adsblol_link
        return status


class AdsbxAggregator(UltrafeederAggregator):
    class AdsbxAdsbStatus(AdsbStatus):
        adsbx_feeder_id: str

    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="adsbx", name="ADSBExchange",
            map_url="https://globe.adsbexchange.com/",
            status_url_or_factory="https://www.adsbexchange.com/myip/",
            netconfig=NetConfig(
                "adsb,feed1.adsbexchange.com,30004,beast_reduce_plus_out",
                "mlat,feed.adsbexchange.com,31090,39003", has_policy=True))
        self._adsbx_feeder_id = None

    def _check_aggregator_status(self) -> AggregatorStatus:
        status = super()._check_aggregator_status()
        if self._adsbx_feeder_id is None:
            self._adsbx_feeder_id = self._get_feeder_id()
        status["adsb"]["adsbx_feeder_id"] = self._adsbx_feeder_id
        return status

    def _get_feeder_id(self):
        try:
            proc = util.shell_with_combined_output(
                f"docker logs ultrafeeder "
                "| grep 'www.adsbexchange.com/api/feeders' | tail -1")
            proc.check_returncode()
        except:
            self._logger.exception("Error trying to look at the adsbx logs.")
            return None
        match = re.search(
            r"www.adsbexchange.com/api/feeders/\?feed=([^&\s]*)", proc.stdout)
        if match:
            return match.group(1)
        self._logger.error(
            f"Unable to find adsbx ID in container logs: {proc.stdout}")
        return None


class AccountBasedAggregator(Aggregator):
    """
    Aggregator that requires an account.

    Account-based aggregators may all require at least some sort of
    authentication, a key, to be configured in order to work.
    """
    def __init__(self, *args, key_required=True, **kwargs):
        super().__init__(*args, **kwargs)
        self._key_required = key_required

    @property
    def needs_key(self) -> bool:
        return self._key_required

    @property
    def capable_message_types(self) -> set[MessageType]:
        return {MessageType.ADSB}

    def _lat(self):
        return self._conf.get("lat")

    def _lon(self):
        return self._conf.get("lon")

    def _alt(self):
        return self._conf.get("alt")

    def _alt_ft(self):
        return int(int(self._alt()) / 0.308)

    def configure(self, enabled: bool, key: Any, *args) -> None:
        if enabled and not key and self._key_required:
            raise ConfigureError("No key provided.")
        super().configure(enabled)
        self._conf.set(f"aggregators.{self.agg_key}.key", key)

    def _download_docker_image(self, image: str) -> bool:
        self._logger.info(f"download_docker_container {image}")
        cmdline = f"docker pull {image}"
        try:
            result = subprocess.run(cmdline, timeout=180.0, shell=True)
        except subprocess.TimeoutExpired:
            return False
        return True

    def _docker_run_with_timeout(self, cmdline: str, timeout: float) -> str:
        def force_remove_container(name):
            try:
                result2 = subprocess.run(
                    f"docker rm -f {name}",
                    timeout=15,
                    shell=True,
                    capture_output=True,
                )
            except subprocess.TimeoutExpired as exc2:
                self._logger.exception(
                    f"Failed to remove the container {name} stderr: "
                    f"{str(exc2.stdout)} / stdout: {str(exc2.stderr)}")

        # let's make sure the container isn't still there, if it is the docker run won't work
        force_remove_container("temp_container")
        try:
            result = subprocess.run(
                f"docker run --name temp_container {cmdline}",
                timeout=timeout,
                shell=True,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            # for several of these containers "timeout" is actually the expected behavior;
            # they don't stop on their own. So just grab the output and kill the container
            self._logger.exception(
                f"docker run {cmdline} received a timeout error after "
                f"{timeout} with output {exc.stdout}")
            output = exc.stdout.decode()

            force_remove_container("temp_container")
        except subprocess.SubprocessError as exc:
            self._logger.exception(
                f"docker run {cmdline} ended with an exception {exc}")
        else:
            output = result.stdout
            self._logger.info(
                f"docker run {cmdline} completed with output {output}")
        return output

    def _check_aggregator_status(self) -> AggregatorStatus:
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(
                data_status=DataStatus.UNKNOWN,
                mlat_status=MlatStatus.DISABLED),
        )


class PlaneFinderAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="planefinder", name="PlaneFinder",
            map_url="https://planefinder.net/",
            status_url_or_factory="/planefinder-stat/")

    @property
    def _container_name(self):
        return "pfclient"


class AdsbHubAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="adsbhub", name="ADSBHub",
            map_url="https://www.adsbhub.org/coverage.php",
            status_url_or_factory=None)

    @property
    def _container_name(self):
        return "adsbhub"


class OpenSkyAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="opensky", name="OpenSky Network",
            map_url="https://opensky-network.org/network/explorer",
            status_url_or_factory=None)

    @property
    def _container_name(self):
        return "opensky"

    def configure(
            self, enabled: bool, user: str, serial: Optional[str]) -> None:
        if not enabled:
            return super().configure(enabled, serial)
        if not user:
            raise ConfigureError("missing user name")
        if not serial:
            self._logger.info(f"need to request serial for OpenSky")
            serial = self._request_fr_serial(user)
            if not serial:
                raise ConfigureError("failed to get OpenSky serial")
        self._conf.set("aggregators.opensky.user", user)
        super().configure(enabled, serial)

    def _request_fr_serial(self, user):
        docker_image = self._conf.get("images.opensky")
        if not self._download_docker_image(docker_image):
            self._logger.error(
                "failed to download the OpenSky docker image",
                flash_message=True)
            return None

        cmdline = (
            f"--rm -i --network config_default -e BEASTHOST=ultrafeeder -e LAT={self._lat()} "
            f"-e LONG={self._lon()} -e ALT={self._alt()} -e OPENSKY_USERNAME={user} {docker_image}"
        )
        output = self._docker_run_with_timeout(cmdline, 60.0)
        serial_match = re.search(
            "Got a new serial number: ([-a-zA-Z0-9]*)", output)
        if not serial_match:
            self._logger.error(
                "couldn't find a serial number in the container output: "
                f"{output}",
                flash_message="OpenSky: couldn't find a serial number in "
                "server response")
            return None

        return serial_match.group(1)


class RadarVirtuelAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="radarvirtuel", name="RadarVirtuel",
            map_url="https://www.radarvirtuel.com/",
            status_url_or_factory=None)

    @property
    def _container_name(self):
        return "radarvirtuel"


class PorttrackerAggregator(AccountBasedAggregator):
    STATS_URL_TEMPLATE = (
        "https://porttracker-api.porttracker.co/api/v1/sharing/stations/"
        "{station_id}/stats/basic")

    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="porttracker", name="Porttracker",
            map_url="https://porttracker.co/",
            status_url_or_factory="https://www.porttracker.co/app/profile")
        self._station_id = None

    @property
    def capable_message_types(self) -> set[MessageType]:
        return {MessageType.AIS}

    @property
    def _container_name(self):
        return "shipfeeder"

    def __str__(self):
        return f"Porttracker aggregator for station ID {self._station_id}"

    def configure(
            self, enabled: bool, station_id: str, data_sharing_key: str,
            mqtt_protocol: str, mqtt_host: str, mqtt_port: str,
            mqtt_username: str, mqtt_password: str, mqtt_topic: str,
            prometheus_enabled: bool) -> None:
        if not enabled:
            # Prometheus metrics should only be enabled if the aggregator is.
            self._conf.set(
                "aggregators.porttracker.prometheus.is_enabled", False)
            return super().configure(enabled, data_sharing_key)
        if not all([station_id, data_sharing_key, mqtt_protocol, mqtt_host,
                    mqtt_port, mqtt_username, mqtt_password, mqtt_topic]):
            raise ConfigureError("missing setting")
        try:
            station_id = int(station_id)
        except Exception as e:
            raise ConfigureError(
                "invalid station ID (must be a number)") from e
        mqtt_url = "{}://{}:{}@{}:{}".format(
            mqtt_protocol, mqtt_username, mqtt_password, mqtt_host, mqtt_port)
        client_id = f"{mqtt_username}-{station_id}"
        self._conf.set("aggregators.porttracker.station_id", station_id)
        self._conf.set("aggregators.porttracker.mqtt_url", mqtt_url)
        self._conf.set("aggregators.porttracker.mqtt_client_id", client_id)
        self._conf.set("aggregators.porttracker.mqtt_qos", 0)
        self._conf.set("aggregators.porttracker.mqtt_topic", mqtt_topic)
        self._conf.set("aggregators.porttracker.mqtt_msgformat", "JSON_NMEA")
        self._conf.set(
            "aggregators.porttracker.prometheus.is_enabled",
            prometheus_enabled)
        super().configure(enabled, data_sharing_key)

    def _check_aggregator_status(self) -> AggregatorStatus:
        data_sharing_key = self._conf.get("aggregators.porttracker.key")
        station_id = self._conf.get("aggregators.porttracker.station_id")
        if not data_sharing_key or not station_id:
            raise StatusCheckError(
                "Data sharing key or station ID not configured.")
        response = requests.get(
            url=self.STATS_URL_TEMPLATE.format(station_id=station_id),
            headers={"X-Data-Sharing-Key": data_sharing_key}, timeout=5)
        response.raise_for_status()
        resp_dict = response.json()
        try:
            past5m = resp_dict["ais"]["past5m"]
            assert isinstance(past5m, numbers.Real)
            if past5m >= 100:
                data_status = DataStatus.GOOD
            elif past5m > 0:
                data_status = DataStatus.WARNING
            else:
                data_status = DataStatus.BAD
        except (KeyError, AssertionError):
            data_status = DataStatus.UNKNOWN
        return AggregatorStatus(
            ais=AisStatus(data_status=data_status), adsb=None)


class AirnavRadarAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="radarbox", name="AirNav Radar",
            map_url="https://www.airnavradar.com/coverage-map",
            status_url_or_factory=self._make_status_url)

    def _make_status_url(self) -> Optional[str]:
        if not self.enabled():
            return None
        feeder_id = self._conf.get("aggregators.radarbox.sn")
        return f"https://www.airnavradar.com/stations/{feeder_id}"

    @property
    def _container_name(self):
        return "rbfeeder"

    def configure(self, enabled: bool, sharing_key: Optional[str]) -> None:
        if not enabled:
            return super().configure(enabled, sharing_key)
        if not sharing_key:
            sharing_key = self._request_rb_sharing_key()
        if not sharing_key:
            raise ConfigureError("Couldn't get a new sharing key.")
        super().configure(enabled, sharing_key)

    def _request_rb_sharing_key(self):
        docker_image = self._conf.get("images.radarbox")

        if not self._download_docker_image(docker_image):
            self._logger.error(
                "failed to download the AirNav Radar docker image",
                flash_message=True)
            return None

        # make sure we correctly enable the hacks
        extra_env = f"-v /opt/adsb/rb/cpuinfo:/proc/cpuinfo "
        if self._conf.get("rbthermalhack"):
            extra_env += "-v /opt/adsb/rb:/sys/class/thermal:ro "

        cmdline = (
            f"--rm -i --network config_default -e BEASTHOST=ultrafeeder -e LAT={self._lat()} "
            f"-e LONG={self._lon()} -e ALT={self._alt()} {extra_env} {docker_image}"
        )
        output = self._docker_run_with_timeout(cmdline, 45.0)
        sharing_key_match = re.search("Your new key is ([a-zA-Z0-9]*)", output)
        if not sharing_key_match:
            self._logger.error(
                "couldn't find a sharing key in the container output: "
                f"{output}",
                flash_message="AirNav Radar: couldn't find a sharing key in "
                "server response")
            return None

        return sharing_key_match.group(1)

    def _check_aggregator_status(self) -> AggregatorStatus:
        rbkey = self._conf.get("aggregators.radarbox.key")
        # reset station number if the key has changed
        if rbkey != self._conf.get("aggregators.radarbox.snkey"):
            station_serial = self._conf.set("aggregators.radarbox.sn", "")

        station_serial = self._conf.get("aggregators.radarbox.sn")
        if not station_serial:
            try:
                result = subprocess.run(
                    "docker logs rbfeeder "
                    "| grep 'station serial number' | tail -1",
                    shell=True,
                    capture_output=True,
                    text=True,
                )
            except Exception as e:
                raise StatusCheckError(
                    "Error trying to look at the rbfeeder logs.") from e
            serial_text = result.stdout.strip()
            match = re.search(
                r"This is your station serial number: ([A-Z0-9]+)",
                serial_text)
            if match:
                station_serial = match.group(1)
                self._conf.set("aggregators.radarbox.sn", station_serial)
                self._conf.set("aggregators.radarbox.snkey", rbkey)
        if not station_serial:
            raise StatusCheckError(
                "Unable to parse station serial from rbfeeder logs.")
        html_url = f"https://www.radarbox.com/stations/{station_serial}"
        rb_page, _ = util.get_plain_url(html_url)
        match = re.search(r"window.init\((.*)\)", rb_page) if rb_page else None
        if not match:
            raise StatusCheckError(
                "Unable to find station info in radarbox response.")
        rb_json = match.group(1)
        rb_dict = json.loads(rb_json)
        station = rb_dict.get("station")
        if not station:
            raise StatusCheckError(
                "Unable to find station in radarbox response.")
        online = station.get("online")
        mlat_online = station.get("mlat_online")
        data_status = DataStatus.GOOD if online else DataStatus.DISCONNECTED
        mlat_status = MlatStatus.GOOD if mlat_online else MlatStatus.DISCONNECTED
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(data_status=data_status, mlat_status=mlat_status),
        )


class FlightAwareAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="flightaware", name="FlightAware",
            map_url="https://www.flightaware.com/live/map",
            status_url_or_factory="/fa-status/")

    @property
    def _container_name(self):
        return "piaware"

    def configure(self, enabled: bool, feeder_id: Optional[str]) -> None:
        if not enabled:
            return super().configure(enabled, feeder_id)
        if not feeder_id:
            feeder_id = self._request_fa_feeder_id()
            self._logger.info(f"Got back feeder ID {feeder_id}.")
        if not feeder_id:
            raise ConfigureError("Couldn't get a new feeder ID.")
        super().configure(enabled, feeder_id)

    def _request_fa_feeder_id(self):
        docker_image = self._conf.get("images.flightaware")
        if not self._download_docker_image(docker_image):
            self._logger.error(
                "failed to download the piaware docker image",
                flash_message=True)
            return None

        cmdline = f"--rm {docker_image}"
        output = self._docker_run_with_timeout(cmdline, 45.0)
        feeder_id_match = re.search(" feeder ID is ([-a-zA-Z0-9]*)", output)
        if feeder_id_match:
            return feeder_id_match.group(1)
        self._logger.error(
            f"couldn't find a feeder ID in the container output: {output}",
            flash_message="FlightAware: couldn't find a feeder ID in server "
            "response")
        return None

    def _check_aggregator_status(self) -> AggregatorStatus:
        host = f"http://127.0.0.1:{self._conf.get('ports.web')}"
        json_url = f"{host}/fa-status.json/"
        fa_dict, status = util.generic_get_json(json_url)
        if not fa_dict or status != 200:
            raise StatusCheckError(
                f"Flightaware at {json_url} returned {status}.")
        if fa_dict.get("adept") and fa_dict.get("adept").get(
                "status") == "green":
            data_status = DataStatus.GOOD
        else:
            data_status = DataStatus.DISCONNECTED

        if fa_dict.get("mlat"):
            if fa_dict.get("mlat").get("status") == "green":
                mlat_status = MlatStatus.GOOD
            elif fa_dict.get("mlat").get("status") == "amber":
                message = fa_dict.get("mlat").get("message").lower()
                if "unstable" in message:
                    mlat_status = MlatStatus.BAD
                elif "initializing" in message:
                    mlat_status = MlatStatus.UNKNOWN
                elif "no clock sync" in message:
                    mlat_status = MlatStatus.WARNING
                else:
                    mlat_status = MlatStatus.UNKNOWN
            else:
                mlat_status = MlatStatus.DISCONNECTED
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(data_status=data_status, mlat_status=mlat_status),
        )


class TenNinetyUkAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="1090uk", name="1090MHz UK",
            map_url="https://1090mhz.uk",
            status_url_or_factory=self._make_status_url)

    def _make_status_url(self) -> Optional[str]:
        if not self.enabled():
            return None
        api_key = self._conf.get("aggregators.1090uk.key")
        return f"https://www.1090mhz.uk/mystatus.php?key={api_key}"

    @property
    def _container_name(self):
        return "radar1090uk"

    def _check_aggregator_status(self) -> AggregatorStatus:
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(
                data_status=DataStatus.UNKNOWN,
                mlat_status=MlatStatus.DISABLED),
        )
        # TODO This unreachable code was in here from upstream. Not sure why
        # it's been disabled, but I'm leaving it here in case it becomes
        # useful.
        if False:
            key = self._conf.get("aggregators.1090uk.key")
            json_url = f"https://www.1090mhz.uk/mystatus.php?key={key}"
            tn_dict, status = util.generic_get_json(json_url)
            if tn_dict and status == 200:
                online = tn_dict.get("online", False)
                data_status = (
                    DataStatus.GOOD if online else DataStatus.DISCONNECTED)
            else:
                data_status = DataStatus.UNKNOWN
            return AggregatorStatus(
                ais=None,
                adsb=AdsbStatus(
                    data_status=data_status, mlat_status=MlatStatus.DISABLED),
            )


class FlightRadar24Aggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="flightradar", name="flightradar24",
            map_url="https://www.flightradar24.com/",
            status_url_or_factory="/fr24/")

    @property
    def _container_name(self):
        return "fr24feed"

    def configure(
            self, enabled: bool, adsb_sharing_key_or_email: str,
            uat_sharing_key_or_email: Optional[str]) -> None:
        if not enabled:
            return super().configure(enabled, adsb_sharing_key_or_email)
        if not adsb_sharing_key_or_email:
            raise ConfigureError("No sharing key or email provided.")
        uat_sharing_key_or_email = uat_sharing_key_or_email or ""
        self._logger.info(
            f"FR_activate adsb |{adsb_sharing_key_or_email}| uat "
            f"|{uat_sharing_key_or_email}|")

        if util.is_email(adsb_sharing_key_or_email):
            # that's an email address, so we are looking to get a sharing key
            adsb_sharing_key = self._request_fr24_sharing_key(
                adsb_sharing_key_or_email)
            self._logger.info(
                f"got back sharing_key |{adsb_sharing_key_or_email}|")
            if adsb_sharing_key and not re.match("[0-9a-zA-Z]+",
                                                 adsb_sharing_key):
                adsb_sharing_key = ""
                self._logger.error(
                    "invalid FR24 sharing key", flash_message=True)
        else:
            adsb_sharing_key = adsb_sharing_key_or_email

        if util.is_email(uat_sharing_key_or_email):
            # that's an email address, so we are looking to get a sharing key
            uat_sharing_key = self._request_fr24_uat_sharing_key(
                uat_sharing_key_or_email)
            self._logger.info(
                f"got back uat_sharing_key |{uat_sharing_key_or_email}|")
            if uat_sharing_key and not re.match("[0-9a-zA-Z]+",
                                                uat_sharing_key):
                uat_sharing_key = ""
                self._logger.error(
                    "invalid FR24 UAT sharing key", flash_message=True)
        else:
            uat_sharing_key = uat_sharing_key_or_email

        if adsb_sharing_key or uat_sharing_key:
            # we have at least one sharing key, let's just enable the container
            self._conf.set("aggregators.flightradar.uat_key", uat_sharing_key)
            super().configure(enabled, adsb_sharing_key)
        else:
            raise ConfigureError("Couldn't get any sharing key.")

    def _request_fr24_sharing_key(self, email: str):
        docker_image = self._conf.get("images.flightradar")
        if not self._download_docker_image(docker_image):
            self._logger.error(
                "Failed to download the FR24 docker image.",
                flash_message=True)
            return None

        lat = float(self._lat())
        lon = float(self._lon())

        if abs(lat) < 0.5 and abs(lon) < 0.5:
            # this is at null island, just fail for this
            self._logger.error(
                "FR24 cannot handle 'null island'", flash_message=True)
            return None

        # so this signup doesn't work for latitude / longitude <0.1, work
        # around that by just setting longitude 0.11 in that case we don't do
        # FR24 mlat anyhow ... if people want to fix it they can do so on the
        # fr24 homepage
        if abs(lat) < 0.11:
            lat = 0.11
        if abs(lon) < 0.11:
            lon = 0.11

        adsb_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{lat}" -e FEEDER_LONG="{lon}" -e FEEDER_ALT_FT="{self._alt_ft()}" '
            f'-e FR24_EMAIL="{email}" {docker_image} '
            f'-c "apt update && apt install -y expect && $(cat handsoff_signup_expect.sh)"'
        )
        open("/opt/adsb/handsoff_signup.sh",
             "w").write(f"#!/bin/bash\n{adsb_signup_command}")
        try:
            output = subprocess.run(
                "bash /opt/adsb/handsoff_signup.sh",
                cwd="/opt/adsb",
                timeout=180.0,
                shell=True,
                text=True,
                capture_output=True,
            ).stdout
        except subprocess.TimeoutExpired as exc:
            output = ""
            if exc.stdout:
                output += exc.stdout.decode()
            if exc.stderr:
                output += exc.stderr.decode()
            self._logger.exception(
                f"Timeout running the FR24 signup script, output: {output}",
                flash_message="FR24 signup script timed out.")
            return None

        sharing_key_match = re.search(
            "Your sharing key \\(([a-zA-Z0-9]*)\\) has been", output)
        if not sharing_key_match:
            self._logger.error(
                "Couldn't find a sharing key in the container output: "
                f"{output}",
                flash_message="FR24: couldn't find a sharing key in server "
                "response")
            return None
        adsb_key = sharing_key_match.group(1)
        self._logger.info(
            f"Found adsb sharing key {adsb_key} in the container output")
        return adsb_key

    def _request_fr24_uat_sharing_key(self, email: str):
        docker_image = self._conf.get("images.flightradar")
        if not self._download_docker_image(docker_image):
            self._logger.error(
                "Failed to download the FR24 docker image.",
                flash_message=True)
            return None

        uat_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{self._lat()}" -e FEEDER_LONG="{self._lon()}" -e FEEDER_ALT_FT="{self._alt_ft()}" '
            f'-e FR24_EMAIL="{email}" {docker_image} '
            f'-c "apt update && apt install -y expect && $(cat handsoff_signup_expect_uat.sh)"'
        )
        open("/opt/adsb/handsoff_signup_uat.sh",
             "w").write(f"#!/bin/bash\n{uat_signup_command}")
        try:
            output = subprocess.run(
                "bash /opt/adsb/handsoff_signup_uat.sh",
                cwd="/opt/adsb",
                timeout=180.0,
                shell=True,
                text=True,
                capture_output=True,
            ).stdout
        except subprocess.TimeoutExpired as exc:
            output = ""
            if exc.stdout:
                output += exc.stdout.decode()
            if exc.stderr:
                output += exc.stderr.decode()
            self._logger.exception(
                "timeout running the FR24 UAT signup script, output: "
                f"{output}", flash_message="FR24 UAT signup script timed out.")
            return None
        sharing_key_match = re.search(
            "Your sharing key \\(([a-zA-Z0-9]*)\\) has been", output)
        if not sharing_key_match:
            self._logger.error(
                "couldn't find a UAT sharing key in the container output: "
                f"{output}",
                flash_message="FR24: couldn't find a UAT sharing key in "
                "server response.")
            return None
        uat_key = sharing_key_match.group(1)
        self._logger.info(
            f"Found uat sharing key {uat_key} in the container output")
        return uat_key

    def _check_aggregator_status(self) -> AggregatorStatus:
        host = f"http://127.0.0.1:{self._conf.get('ports.web')}"
        json_url = f"{host}/fr24-monitor.json/"
        fr_dict, status = util.generic_get_json(json_url)
        if not fr_dict or status != 200:
            raise StatusCheckError(
                f"Flightradar at {json_url} returned {status}.")
        if fr_dict.get("feed_status") == "connected":
            data_status = DataStatus.GOOD
        else:
            data_status = DataStatus.DISCONNECTED
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(
                data_status=data_status, mlat_status=MlatStatus.DISABLED),
        )


class PlaneWatchAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="planewatch", name="Plane.watch",
            map_url="https:/plane.watch/desktop.html",
            status_url_or_factory=None)

    @property
    def _container_name(self):
        return "planewatch"

    def _check_aggregator_status(self) -> AggregatorStatus:
        # they sometimes call it key, sometimes uuid
        pw_uuid = self._conf.get("aggregators.planewatch.key")
        if not pw_uuid:
            raise StatusCheckError("Now Planewatch UUID set.")
        json_url = (
            f"https://atc.plane.watch/api/v1/feeders/{pw_uuid}/status.json")
        pw_dict, status = util.generic_get_json(json_url)
        if not pw_dict or status != 200:
            raise StatusCheckError(f"Planewatch returned {status}.")
        status = pw_dict.get("status")
        adsb = status.get("adsb")
        mlat = status.get("mlat")
        if not status or not adsb or not mlat:
            raise StatusCheckError(
                f"Unable to parse planewatch status {pw_dict}.")
        data_status = DataStatus.GOOD if adsb.get(
            "connected") else DataStatus.DISCONNECTED
        mlat_status = MlatStatus.GOOD if mlat.get(
            "connected") else MlatStatus.DISCONNECTED
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(data_status=data_status, mlat_status=mlat_status),
        )


class SdrMapAggregator(AccountBasedAggregator):
    FEED_OK_FILE = pathlib.Path("/run/sdrmap/feed_ok")

    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="sdrmap", name="sdrmap",
            map_url="https://sdrmap.org/", status_url_or_factory=None)

    @property
    def _container_name(self):
        return "sdrmap"

    def configure(self, enabled: bool, user: str, password: str) -> None:
        if not enabled:
            return super().configure(enabled, password)
        if not user:
            raise ConfigureError("missing user")
        if not password:
            raise ConfigureError("missing password")
        self._conf.set("aggregators.sdrmap.user", user)
        super().configure(enabled, password)

    def _check_aggregator_status(self) -> AggregatorStatus:
        if self.FEED_OK_FILE.exists():
            data_status = DataStatus.GOOD
        else:
            data_status = DataStatus.DISCONNECTED
        return AggregatorStatus(
            ais=None,
            adsb=AdsbStatus(
                data_status=data_status, mlat_status=MlatStatus.UNKNOWN),
        )


class AiscatcherAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="aiscatcher", name="AIS-catcher",
            map_url="https://www.aiscatcher.org/livemap",
            status_url_or_factory=None, key_required=False)

    @property
    def capable_message_types(self) -> set[MessageType]:
        return {MessageType.AIS}

    @property
    def _container_name(self):
        return "shipfeeder"

    def configure(self, enabled: bool, feeder_key: str) -> None:
        if not feeder_key:
            # Sharing key is optional, empty or None is fine.
            feeder_key_str = ""
        else:
            try:
                feeder_key_str = str(uuid.UUID(feeder_key))
            except Exception as e:
                raise ValueError("Invalid feeder key (must be a UUID).") from e
        super().configure(enabled, feeder_key_str)

    def _check_aggregator_status(self) -> AggregatorStatus:
        return AggregatorStatus(
            ais=AisStatus(data_status=DataStatus.UNKNOWN), adsb=None)


class AishubAggregator(AccountBasedAggregator):
    def __init__(self, conf: config.Config, system: system.System):
        super().__init__(
            conf, system, agg_key="aishub", name="Aishub",
            map_url="https://www.aishub.net/coverage",
            status_url_or_factory=self._make_status_url)

    @property
    def capable_message_types(self) -> set[MessageType]:
        return {MessageType.AIS}

    @property
    def _container_name(self):
        return "shipfeeder"

    @property
    def _udp_port(self) -> Optional[int]:
        return self._conf.get("aggregators.aishub.key")

    def _make_status_url(self) -> Optional[str]:
        if not self.enabled():
            return None
        return f"https://www.aishub.net/stations/{self._udp_port}"

    def configure(self, enabled: bool, udp_port: str) -> None:
        try:
            udp_port_int = int(udp_port)
        except Exception as e:
            if not enabled:
                return super().configure(enabled, None)
            raise ValueError("Invalid UDP port (must be an integer).") from e
        super().configure(enabled, udp_port_int)

    def _check_aggregator_status(self) -> AggregatorStatus:
        if not self._udp_port:
            raise StatusCheckError("No sharing UDP port configured.")
        response = requests.get(
            url=f"https://www.aishub.net/station/{self._udp_port}"
            "/daily-statistics.json",
            headers={"X-Requested-With": "XMLHttpRequest"}, timeout=5)
        response.raise_for_status()
        resp_dict = response.json()
        vessel_counts = resp_dict["count"]
        # Aishub gives us a list of the number of vessels over time. If there
        # have been any vessels at the latest measurement, we assume data is
        # arriving.
        if not vessel_counts or not vessel_counts[-1]:
            data_status = DataStatus.BAD
        else:
            data_status = DataStatus.GOOD
        return AggregatorStatus(
            ais=AisStatus(data_status=data_status), adsb=None)
