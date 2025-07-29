import abc
import enum
import json
import logging
import pathlib
import re
import subprocess
import threading
import time
from typing import Optional

import utils.data
import utils.system
import utils.util


class Status(enum.Enum):
    UNKNOWN = enum.auto()
    DISCONNECTED = enum.auto()
    DISABLED = enum.auto()
    CONTAINER_DOWN = enum.auto()
    STARTING = enum.auto()
    BAD = enum.auto()
    WARNING = enum.auto()
    GOOD = enum.auto()


_status_symbol = {
    Status.UNKNOWN: ".",
    Status.DISCONNECTED: "\u2612",
    Status.DISABLED: " ",
    Status.CONTAINER_DOWN: "\u2608",
    Status.STARTING: "\u27f3",
    Status.BAD: "\u2639",
    Status.WARNING: "\u26a0",
    Status.GOOD: "+",}

_status_dict = None


def statuses(data: utils.data.Data,
             system: utils.system.System) -> dict[str, "AggregatorStatus"]:
    global _status_dict
    if _status_dict is None:
        _status_dict = {}
        statuses = [
            AdsbLolAggregatorStatus(data, system),
            UltrafeederAggregatorStatus(
                data, system, agg_key="flyitaly", name="Fly Italy ADSB",
                map_url="https://mappa.flyitalyadsb.com/",
                status_url="https://my.flyitalyadsb.com/am_i_feeding"),
            UltrafeederAggregatorStatus(
                data, system, agg_key="avdelphi", name="AVDelphi",
                map_url="https://www.avdelphi.com/coverage.html",
                status_url=None),
            UltrafeederAggregatorStatus(
                data, system, agg_key="planespotters", name="Planespotters",
                map_url="https://radar.planespotters.net/",
                status_url="https://www.planespotters.net/feed/status"),
            UltrafeederAggregatorStatus(
                data, system, agg_key="tat", name="TheAirTraffic",
                map_url="https://globe.theairtraffic.com/",
                status_url="https://theairtraffic.com/feed/myip/"),
            UltrafeederAggregatorStatus(
                data, system, agg_key="adsbfi", name="adsb.fi",
                map_url="https://globe.adsb.fi/",
                status_url="https://api.adsb.fi/v1/myip"),
            AdsbxAggregatorStatus(data, system),
            UltrafeederAggregatorStatus(
                data, system, agg_key="hpradar", name="HPRadar",
                map_url="https://skylink.hpradar.com/", status_url=None),
            AirplanesLiveAggregatorStatus(data, system),
            FlightRadar24AggregatorStatus(data, system),
            PlaneWatchAggregatorStatus(data, system),
            FlightAwareAggregatorStatus(data, system),
            AirnavRadarAggregatorStatus(data, system),
            PlaneFinderAggregatorStatus(data, system),
            AdsbHubAggregatorStatus(data, system),
            OpenSkyAggregatorStatus(data, system),
            RadarVirtuelAggregatorStatus(data, system),
            TenNinetyUkAggregatorStatus(data, system),
            SdrMapAggregatorStatus(data, system),
            PorttrackerAggregatorStatus(data, system),]
        for status in statuses:
            assert status.agg_key not in _status_dict
            _status_dict[status.agg_key] = status
    return _status_dict


class AggregatorStatus(abc.ABC):
    def __init__(
            self, data: utils.data.Data, system: utils.system.System, *,
            agg_key: str, name: str, map_url: Optional[str],
            status_url: Optional[str]):
        self._logger = logging.getLogger(type(self).__name__)
        self._d = data
        self._system = system
        self._agg_key = agg_key
        self._name = name
        self._map_url = map_url
        self._status_url = status_url
        self._last_check = 0
        self._data_status = self._mlat_status = Status.UNKNOWN
        self._check_lock = threading.Lock()

    def __repr__(self):
        return (
            f"{type(self).__name__}(last_check: {str(self._last_check)}, "
            f"data: {self._data_status} mlat: {self._mlat_status})")

    @property
    def agg_key(self) -> str:
        return self._agg_key

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return self._d.list_is_enabled(self.agg_key, 0)

    @property
    def map_url(self) -> Optional[str]:
        return self._map_url

    @property
    def status_url(self) -> Optional[str]:
        return self._status_url

    @property
    def data_status(self) -> str:
        data_status, _, success = self._check()
        if success:
            return _status_symbol[data_status]
        return _status_symbol[Status.UNKNOWN]

    @property
    def mlat_status(self) -> str:
        _, mlat_status, success = self._check()
        if success:
            return _status_symbol[mlat_status]
        return _status_symbol[Status.UNKNOWN]

    @property
    @abc.abstractmethod
    def _container_name(self) -> str:
        raise NotImplementedError

    def refresh_cache(self):
        """
        Refresh the cached data.

        Fetches data in case it was outdated. This is not necessary to get the
        correct result, it will just make requests faster until the data times
        out again.
        """
        self._check()

    def _check(self) -> tuple[Optional[Status], Optional[Status], bool]:
        with self._check_lock:
            if time.time() - self._last_check < 10:
                return self._data_status, self._mlat_status, True

            container_status = self._system.getContainerStatus(
                self._container_name)
            if container_status in ["down", "restarting"]:
                self._last_check = time.time()
                return (
                    Status.CONTAINER_DOWN
                    if container_status == "down" else Status.STARTING,
                    Status.DISABLED,
                    True,
                )

            data_status, mlat_status = self._check_impl()
            # If mlat isn't enabled, ignore status check results.
            if not self._d.list_is_enabled("mlat_enable", 0):
                mlat_status = Status.DISABLED

            # if check_impl has updated last_check the status is available
            if time.time() - self._last_check < 10:
                self._data_status = data_status
                self._mlat_status = mlat_status
                return self._data_status, self._mlat_status, True

            return None, None, False

    @abc.abstractmethod
    def _check_impl(self) -> tuple[Status, Status]:
        """
        Check status.

        Returns a tuple of data_status, mlat_status. Implementations must set
        _last_check to the current time on success.
        """
        raise NotImplementedError


class UltrafeederAggregatorStatus(AggregatorStatus):
    """Status for all ultrafeeder aggregators."""
    ULTRAFEEDER_PATH = pathlib.Path("/run/adsb-feeder-ultrafeeder")

    def __init__(
            self, data: utils.data.Data, system: utils.system.System, *,
            agg_key: str, name: str, map_url: Optional[str],
            status_url: Optional[str]):
        super().__init__(
            data, system, agg_key=agg_key, name=name, map_url=map_url,
            status_url=status_url)
        self._netconfig = self._d.netconfigs.get(self.agg_key)
        if not self._netconfig:
            raise ValueError

    @property
    def _container_name(self) -> str:
        return "ultrafeeder"

    def _check_impl(self) -> tuple[Status, Status]:
        data_status = self._get_data_status()
        mlat_status = self._get_mlat_status()
        self._maybe_set_extra_info_to_settings()
        self._last_check = time.time()
        return data_status, mlat_status

    def _get_data_status(self) -> Status:
        bconf = self._netconfig.adsb_config
        # example adsb_config:
        # "adsb,dati.flyitalyadsb.com,4905,beast_reduce_plus_out",
        if not bconf:
            self._logger.error(
                f"No adsb_config in netconfig for {self.agg_key}.")
            return self._data_status
        pattern = (
            'readsb_net_connector_status{{host="{host}",port="{port}"}} (\\d+)'
            .format(host=bconf.split(',')[1], port=bconf.split(',')[2]))
        stats_file = self.ULTRAFEEDER_PATH / "readsb" / "stats.prom"
        try:
            with stats_file.open() as f:
                readsb_status = f.read()
        except:
            return Status.DISCONNECTED
        match = re.search(pattern, readsb_status)
        if match:
            status = int(match.group(1))
            # this status is the time in seconds the connection has been
            # established
            if status <= 0:
                return Status.DISCONNECTED
            elif status > 20:
                return Status.GOOD
            else:
                return Status.WARNING
        self._logger.error(f"No match checking data status for {pattern}.")
        return self._data_status

    def _get_mlat_status(self) -> Status:
        mconf = self._netconfig.mlat_config
        if not mconf:
            return Status.DISABLED
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
            return Status.DISCONNECTED
        if time.time() - now > 60:
            # that's more than a minute old... probably not connected
            return Status.DISCONNECTED
        elif percent_good > 10 and percent_bad <= 5:
            return Status.GOOD
        elif percent_bad > 15:
            return Status.BAD
        else:
            return Status.WARNING

    def _maybe_set_extra_info_to_settings(self):
        pass


class AirplanesLiveAggregatorStatus(UltrafeederAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="alive", name="airplanes.live",
            map_url="https://globe.airplanes.live/",
            status_url="https://airplanes.live/myfeed/")

    def _maybe_set_extra_info_to_settings(self):
        if self._d.env_by_tags("alivemaplink").list_get(0):
            return
        json_url = "https://api.airplanes.live/feed-status"
        a_dict, status = utils.util.generic_get_json(json_url)
        if a_dict and status == 200:
            map_link = a_dict.get("map_link")
            # seems to currently only have one map link per IP, we save it
            # per microsite nonetheless in case this changes in the future
            if map_link:
                self._d.env_by_tags("alivemaplink").list_set(0, map_link)


class AdsbLolAggregatorStatus(UltrafeederAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="adsblol", name="adsb.lol",
            map_url="https://adsb.lol/",
            status_url="https://api.adsb.lol/0/me")

    def _maybe_set_extra_info_to_settings(self):
        if self._d.env_by_tags("adsblol_link").list_get(0):
            return
        uuid = self._d.env_by_tags("adsblol_uuid").list_get(0)
        json_url = "https://api.adsb.lol/0/me"
        response_dict, status = utils.util.generic_get_json(json_url)
        if response_dict and status == 200:
            try:
                for entry in response_dict.get("clients").get("beast"):
                    if entry.get("uuid", "xxxxxxxx-xxxx-")[:14] == uuid[:14]:
                        self._d.env_by_tags("adsblol_link").list_set(
                            0, entry.get("adsblol_my_url"))
            except:
                self._logger.exception("Error getting map link from adsb.lol.")


class AdsbxAggregatorStatus(UltrafeederAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="adsbx", name="ADSBExchange",
            map_url="https://globe.adsbexchange.com/",
            status_url="https://www.adsbexchange.com/myip/")

    def _maybe_set_extra_info_to_settings(self):
        feeder_id = self._d.env_by_tags("adsbxfeederid").list_get(0)
        if feeder_id and len(feeder_id) == 12:
            return
        # get the adsbexchange feeder id for the anywhere map / status
        # things
        self._logger.info("Don't have the adsbX Feeder ID yet, getting it.")
        container_name = "ultrafeeder"
        try:
            result = subprocess.run(
                f"docker logs {container_name} "
                "| grep 'www.adsbexchange.com/api/feeders' | tail -1",
                shell=True,
                capture_output=True,
                text=True,
            )
            output = result.stdout
        except:
            self._logger.exception("Error trying to look at the adsbx logs.")
            return
        match = re.search(
            r"www.adsbexchange.com/api/feeders/\?feed=([^&\s]*)",
            output,
        )
        if match:
            adsbx_id = match.group(1)
            self._d.env_by_tags("adsbxfeederid").list_set(0, adsbx_id)
        else:
            self._logger.error(
                f"Unable to find adsbx ID in container logs: {output}")


class NoInfoAggregatorStatus(AggregatorStatus):
    """Aggregator status where we can't get information."""
    def _check_impl(self) -> tuple[Status, Status]:
        self._last_check = time.time()
        return Status.UNKNOWN, Status.DISABLED


class PlaneFinderAggregatorStatus(NoInfoAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="planefinder", name="PlaneFinder",
            map_url="https://planefinder.net/",
            status_url="/planefinder-stat/")

    @property
    def _container_name(self):
        return "pfclient"


class AdsbHubAggregatorStatus(NoInfoAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="adsbhub", name="ADSBHub",
            map_url="https://www.adsbhub.org/coverage.php", status_url=None)

    @property
    def _container_name(self):
        return "adsbhub"


class OpenSkyAggregatorStatus(NoInfoAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="opensky", name="OpenSky",
            map_url="https://opensky-network.org/network/explorer",
            status_url=None)

    @property
    def _container_name(self):
        return "opensky"


class RadarVirtuelAggregatorStatus(NoInfoAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="radarvirtuel", name="RadarVirtuel",
            map_url="https://www.radarvirtuel.com/", status_url=None)

    @property
    def _container_name(self):
        return "radarvirtuel"


class PorttrackerAggregatorStatus(NoInfoAggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="porttracker", name="Porttracker",
            map_url="https://porttracker.co/",
            status_url="https://www.porttracker.co/app/profile")

    @property
    def _container_name(self):
        return "shipfeeder"


class AirnavRadarAggregatorStatus(AggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="radarbox", name="AirNav Radar",
            map_url="https://www.airnavradar.com/coverage-map",
            status_url=None)

    @property
    def status_url(self) -> Optional[str]:
        feeder_id = self._d.env("FEEDER_RADARBOX_SN").list_get(0)
        return f"https://www.airnavradar.com/stations/{feeder_id}"

    @property
    def _container_name(self):
        return "rbfeeder"

    def _check_impl(self) -> tuple[Status, Status]:
        rbkey = self._d.env_by_tags(["radarbox", "key"]).list_get(0)
        # reset station number if the key has changed
        if rbkey != self._d.env_by_tags(["radarbox", "snkey"]).list_get(0):
            station_serial = self._d.env_by_tags(["radarbox",
                                                  "sn"]).list_set(0, "")

        station_serial = self._d.env_by_tags(["radarbox", "sn"]).list_get(0)
        if not station_serial:
            try:
                result = subprocess.run(
                    "docker logs rbfeeder "
                    "| grep 'station serial number' | tail -1",
                    shell=True,
                    capture_output=True,
                    text=True,
                )
            except:
                self._logger.exception(
                    "Error trying to look at the rbfeeder logs.")
                return Status.UNKNOWN, Status.UNKNOWN
            serial_text = result.stdout.strip()
            match = re.search(
                r"This is your station serial number: ([A-Z0-9]+)",
                serial_text)
            if match:
                station_serial = match.group(1)
                self._d.env_by_tags(["radarbox",
                                     "sn"]).list_set(0, station_serial)
                self._d.env_by_tags(["radarbox", "snkey"]).list_set(0, rbkey)
        if not station_serial:
            return Status.UNKNOWN, Status.UNKNOWN
        html_url = f"https://www.radarbox.com/stations/{station_serial}"
        rb_page, _ = utils.util.get_plain_url(html_url)
        match = re.search(r"window.init\((.*)\)", rb_page) if rb_page else None
        if not match:
            return Status.UNKNOWN, Status.UNKNOWN
        rb_json = match.group(1)
        rb_dict = json.loads(rb_json)
        station = rb_dict.get("station")
        if not station:
            return Status.UNKNOWN, Status.UNKNOWN
        self._last_check = time.time()
        online = station.get("online")
        mlat_online = station.get("mlat_online")
        data_status = Status.GOOD if online else Status.DISCONNECTED
        mlat_status = Status.GOOD if mlat_online else Status.DISCONNECTED
        return data_status, mlat_status


class FlightAwareAggregatorStatus(AggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="flightaware", name="FlightAware",
            map_url="https://www.flightaware.com/live/map",
            status_url="/fa-status/")

    @property
    def _container_name(self):
        return "piaware"

    def _check_impl(self) -> tuple[Status, Status]:
        host = f"http://127.0.0.1:{self._d.env_by_tags('webport').value}"
        json_url = f"{host}/fa-status.json/"
        fa_dict, status = utils.util.generic_get_json(json_url)
        if not fa_dict or status != 200:
            self._logger.warning(
                f"Flightaware at {json_url} returned {status}.")
            return Status.UNKNOWN, Status.UNKNOWN
        if fa_dict.get("adept") and fa_dict.get("adept").get(
                "status") == "green":
            data_status = Status.GOOD
        else:
            data_status = Status.DISCONNECTED

        if fa_dict.get("mlat"):
            if fa_dict.get("mlat").get("status") == "green":
                mlat_status = Status.GOOD
            elif fa_dict.get("mlat").get("status") == "amber":
                message = fa_dict.get("mlat").get("message").lower()
                if "unstable" in message:
                    mlat_status = Status.BAD
                elif "initializing" in message:
                    mlat_status = Status.UNKNOWN
                elif "no clock sync" in message:
                    mlat_status = Status.WARNING
                else:
                    mlat_status = Status.UNKNOWN
            else:
                mlat_status = Status.DISCONNECTED
        self._last_check = time.time()
        return data_status, mlat_status


class TenNinetyUkAggregatorStatus(AggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="1090uk", name="1090MHz UK",
            map_url="https://1090mhz.uk", status_url=None)

    @property
    def status_url(self) -> Optional[str]:
        api_key = self._d.env("FEEDER_1090UK_API_KEY").list_get(0)
        return f"https://www.1090mhz.uk/mystatus.php?key={api_key}"

    @property
    def _container_name(self):
        return "radar1090uk"

    def _check_impl(self) -> tuple[Status, Status]:
        self._last_check = time.time()
        return Status.UNKNOWN, Status.DISABLED
        # TODO This unreachable code was in here from upstream. Not sure why
        # it's been disabled, but I'm leaving it here in case it becomes
        # useful.
        if False:
            key = self._d.env_by_tags(["1090uk", "key"]).list_get(0)
            json_url = f"https://www.1090mhz.uk/mystatus.php?key={key}"
            tn_dict, status = utils.util.generic_get_json(json_url)
            if tn_dict and status == 200:
                online = tn_dict.get("online", False)
                data_status = Status.GOOD if online else Status.DISCONNECTED
            else:
                data_status = Status.UNKNOWN
            return data_status, Status.DISABLED


class FlightRadar24AggregatorStatus(AggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="flightradar", name="flightradar24",
            map_url="https://www.flightradar24.com/", status_url="/fr24/")

    @property
    def _container_name(self):
        return "fr24feed"

    def _check_impl(self) -> tuple[Status, Status]:
        host = f"http://127.0.0.1:{self._d.env_by_tags('webport').value}"
        json_url = f"{host}/fr24-monitor.json/"
        fr_dict, status = utils.util.generic_get_json(json_url)
        if not fr_dict or status != 200:
            self._logger.warning(
                f"Flightradar at {json_url} returned {status}.")
            return Status.UNKNOWN, Status.DISABLED
        if fr_dict.get("feed_status") == "connected":
            data_status = Status.GOOD
        else:
            data_status = Status.DISCONNECTED
        self._last_check = time.time()
        return data_status, Status.DISABLED


class PlaneWatchAggregatorStatus(AggregatorStatus):
    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="planewatch", name="Plane.watch",
            map_url="https:/plane.watch/desktop.html", status_url=None)

    @property
    def _container_name(self):
        return "planewatch"

    def _check_impl(self) -> tuple[Status, Status]:
        # they sometimes call it key, sometimes uuid
        pw_uuid = self._d.env_by_tags(["planewatch", "key"]).list_get(0)
        if not pw_uuid:
            return Status.UNKNOWN, Status.UNKNOWN
        json_url = (
            f"https://atc.plane.watch/api/v1/feeders/{pw_uuid}/status.json")
        pw_dict, status = utils.util.generic_get_json(json_url)
        if not pw_dict or status != 200:
            self._logger.warning(f"Planewatch returned {status}.")
            return Status.UNKNOWN, Status.UNKNOWN
        status = pw_dict.get("status")
        adsb = status.get("adsb")
        mlat = status.get("mlat")
        if not status or not adsb or not mlat:
            self._logger.warning(
                f"Unable to parse planewatch status {pw_dict}.")
            return Status.UNKNOWN, Status.UNKNOWN
        data_status = Status.GOOD if adsb.get(
            "connected") else Status.DISCONNECTED
        mlat_status = Status.GOOD if mlat.get(
            "connected") else Status.DISCONNECTED
        self._last_check = time.time()
        return data_status, mlat_status


class SdrMapAggregatorStatus(AggregatorStatus):
    FEED_OK_FILE = pathlib.Path("/run/sdrmap/feed_ok")

    def __init__(self, data: utils.data.Data, system: utils.system.System):
        super().__init__(
            data, system, agg_key="sdrmap", name="sdrmap",
            map_url="https://sdrmap.org/", status_url=None)

    @property
    def _container_name(self):
        return "sdrmap"

    def _check_impl(self) -> tuple[Status, Status]:
        self._last_check = time.time()
        if self.FEED_OK_FILE.exists():
            data_status = Status.GOOD
        else:
            data_status = Status.DISCONNECTED
        return data_status, Status.UNKNOWN
