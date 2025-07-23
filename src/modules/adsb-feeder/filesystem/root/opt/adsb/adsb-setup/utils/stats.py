import dataclasses as dc
import gzip
import json
import logging
import pathlib
import shutil
import tempfile
import time
import typing as t

import utils.data
import utils.util


@dc.dataclass
class TimeFrameStats:
    type: t.Literal["hour", "minute"]
    end_ts: float
    craft_ids: set[str | int]
    num_positions: int

    def __post_init__(self):
        if self.type not in ["hour", "minute"]:
            raise ValueError("Type must be hour or minute.")

    @staticmethod
    def from_dict(d):
        try:
            return TimeFrameStats(
                type=d["type"], end_ts=d["end_ts"],
                craft_ids=set(d["craft_ids"]),
                num_positions=d["num_positions"])
        except Exception as e:
            raise ValueError("Unexpected format.") from e

    @property
    def ts(self) -> float:
        """Representative timestamp (middle of the interval)."""
        if self.type == "hour":
            return self.end_ts - 1800
        assert self.type == "minute"
        return self.end_ts - 30

    @property
    def start_ts(self) -> float:
        if self.type == "hour":
            return self.end_ts - 3600
        assert self.type == "minute"
        return self.end_ts - 60

    @property
    def position_message_rate(self) -> float:
        if self.type == "hour":
            return self.num_positions / 3600
        assert self.type == "minute"
        return self.num_positions / 60


@dc.dataclass
class CraftStats:
    ships: list[TimeFrameStats] = dc.field(default_factory=list)
    planes: list[TimeFrameStats] = dc.field(default_factory=list)

    @staticmethod
    def from_dict(d):
        try:
            ships = [TimeFrameStats.from_dict(s) for s in d["ships"]]
            planes = [TimeFrameStats.from_dict(s) for s in d["planes"]]
            return CraftStats(ships=ships, planes=planes)
        except Exception as e:
            raise ValueError("Unexpected format.") from e


class ReceptionMonitor:
    STATS_FILE = utils.data.CONFIG_DIR / "reception_stats.json.gz"
    SCRAPE_INTERVAL = 60

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self.stats = None
        self._readsb_scraper = ReadsbScraper()
        self._scrape_tasks = [
            utils.util.RepeatingTask(self.SCRAPE_INTERVAL, scrape_function)
            for scrape_function in [
                self._scrape_readsb, self._scrape_ais_catcher]]

    def start(self):
        try:
            with gzip.open(self.STATS_FILE, "rt") as f:
                stats_dict = json.load(f)
            self.stats = CraftStats.from_dict(stats_dict)
        except:
            self._logger.exception(
                "Error loading stored stats, starting fresh.")
            self.stats = CraftStats()
        for task in self._scrape_tasks:
            task.start()

    def stop(self):
        for task in self._scrape_tasks:
            task.stop_and_wait()
        try:
            stats_json = json.dumps(
                dc.asdict(self.stats), cls=IterableAsListJSONEncoder)
            with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_file:
                tmp_file.write(gzip.compress(stats_json.encode()))
            shutil.move(tmp_file.name, self.STATS_FILE)
        except:
            self._logger.exception("Error storing stats.")

    def _scrape_readsb(self):
        try:
            last_minute_stats = self._readsb_scraper.get_last_minute_stats()
            self.stats.planes.append(last_minute_stats)
        except Scraper.NoStats:
            pass

    def _scrape_ais_catcher(self):
        pass


class Scraper:
    class NoStats(Exception):
        pass

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def get_last_minute_stats(self) -> TimeFrameStats:
        raise NotImplementedError


class ReadsbScraper(Scraper):
    STATS_PATH = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/stats.json")
    AIRCRAFT_PATH = pathlib.Path(
        "/run/adsb-feeder-ultrafeeder/readsb/aircraft.json")

    def get_last_minute_stats(self) -> TimeFrameStats:
        try:
            num_positions = self._get_last_minute_num_positions()
            icaos = self._get_last_minute_aircraft_icaos()
        except IOError as e:
            raise self.NoStats from e
        except Exception as e:
            self._logger.exception("Unexpected statistics file format.")
            raise self.NoStats from e
        return TimeFrameStats(
            type="minute", end_ts=time.time(), craft_ids=set(icaos),
            num_positions=num_positions)

    def _get_last_minute_num_positions(self) -> int:
        with self.STATS_PATH.open() as f:
            stats_dict = json.load(f)
            return stats_dict["last1min"]["position_count_total"]

    def _get_last_minute_aircraft_icaos(self) -> set[str]:
        with self.AIRCRAFT_PATH.open() as f:
            aircraft_dict = json.load(f)
            return {
                aircraft["hex"]
                for aircraft in aircraft_dict["aircraft"]
                if not aircraft["hex"].startswith("~")}


class IterableAsListJSONEncoder(json.JSONEncoder):
    def default(self, o):
        try:
            iterable = iter(o)
            return list(iterable)
        except TypeError:
            return super().default(o)
