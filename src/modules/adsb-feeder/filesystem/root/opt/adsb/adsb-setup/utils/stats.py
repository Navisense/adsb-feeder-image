import dataclasses as dc
import json
import logging
import pathlib
import time
import typing as t

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

    @property
    def ts(self) -> float:
        """Representative timestamp (middle of the interval)."""
        if self.type == "hour":
            return self.end_ts - 1800
        assert self.type == "minute"
        return self.num_positions - 30

    @property
    def start_ts(self) -> float:
        if self.type == "hour":
            return self.end_ts - 3600
        assert self.type == "minute"
        return self.num_positions - 60

    @property
    def position_message_rate(self) -> float:
        if self.type == "hour":
            return self.num_positions / 3600
        assert self.type == "minute"
        return self.num_positions / 60


@dc.dataclass
class CraftStats:
    history: list[TimeFrameStats] = dc.field(default_factory=list)


@dc.dataclass
class CraftsStats:
    ships: CraftStats = dc.field(default_factory=CraftStats)
    planes: CraftStats = dc.field(default_factory=CraftStats)


class ReceptionMonitor:
    SCRAPE_INTERVAL = 60

    def __init__(self):
        self._stats = CraftsStats()
        self._readsb_scraper = ReadsbScraper()
        self._scrape_tasks = [
            utils.util.RepeatingTask(self.SCRAPE_INTERVAL, scrape_function)
            for scrape_function in [
                self._scrape_readsb, self._scrape_ais_catcher]]

    def start(self):
        for task in self._scrape_tasks:
            task.start()

    def stop(self):
        for task in self._scrape_tasks:
            task.stop_and_wait()

    def _scrape_readsb(self):
        history = self._stats.planes.history
        try:
            history.append(self._readsb_scraper.get_last_minute_stats())
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

