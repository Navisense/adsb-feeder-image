import dataclasses as dc
import gzip
import itertools as it
import json
import logging
import pathlib
import shutil
import tempfile
import time
import typing as t

import requests

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
    history: list[TimeFrameStats] = dc.field(default_factory=list)

    @staticmethod
    def from_dict(d):
        try:
            return CraftStats(
                history=[TimeFrameStats.from_dict(s) for s in d["history"]])
        except Exception as e:
            raise ValueError("Unexpected format.") from e


@dc.dataclass
class Stats:
    ais: CraftStats = dc.field(default_factory=CraftStats)
    adsb: CraftStats = dc.field(default_factory=CraftStats)

    @staticmethod
    def from_dict(d):
        try:
            ais = CraftStats.from_dict(d["ais"])
            adsb = CraftStats.from_dict(d["adsb"])
            return Stats(ais=ais, adsb=adsb)
        except Exception as e:
            raise ValueError("Unexpected format.") from e


@dc.dataclass
class CurrentCraftStats:
    uptime: float
    num_crafts: int
    position_message_rate: float


@dc.dataclass
class CurrentStats:
    ais: CurrentCraftStats
    adsb: CurrentCraftStats


class ReceptionMonitor:
    """
    A monitor keeping track of message reception.

    Scrapes the statistics of AIS-catcher and readsb regularly to maintain
    statistics on the position message rate and which ships or planes are
    visible. Statistics are written minute-by-minute initially, and later
    aggregated into hourly statistics. They are deleted after a while.

    Also provides a method to get the current message rate and number of
    ships/planes.
    """
    STATS_FILE = utils.data.CONFIG_DIR / "reception_stats.json.gz"
    SCRAPE_INTERVAL = 60
    MAX_HISTORY_AGE = 14 * 24 * 3600

    def __init__(self, conf: utils.data.Config):
        self._logger = logging.getLogger(type(self).__name__)
        self.stats = None
        self._readsb_scraper = ReadsbScraper()
        self._ais_catcher_scraper = AisCatcherScraper(conf)
        self._scrape_tasks = [
            utils.util.RepeatingTask(self.SCRAPE_INTERVAL, scrape_function)
            for scrape_function in [
                self._scrape_readsb, self._scrape_ais_catcher]]

    def start(self):
        try:
            with gzip.open(self.STATS_FILE, "rt") as f:
                stats_dict = json.load(f)
            self.stats = Stats.from_dict(stats_dict)
        except:
            self._logger.exception(
                "Error loading stored stats, starting fresh.")
            self.stats = Stats()
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

    def get_current_stats(self) -> CurrentStats:
        return CurrentStats(
            ais=self._ais_catcher_scraper.get_current_stats(),
            adsb=self._readsb_scraper.get_current_stats())

    def _scrape_readsb(self):
        self._scrape(self._readsb_scraper, self.stats.adsb.history)

    def _scrape_ais_catcher(self):
        self._scrape(self._ais_catcher_scraper, self.stats.ais.history)

    def _scrape(self, scraper: "Scraper", history: list[TimeFrameStats]):
        try:
            last_minute_stats = scraper.get_last_minute_stats()
            history.append(last_minute_stats)
        except Scraper.NoStats:
            pass
        self._expire_old_history(history)
        self._aggregate_history(history)

    def _expire_old_history(self, history: list[TimeFrameStats]):
        min_ts = time.time() - self.MAX_HISTORY_AGE
        try:
            while history[0].end_ts < min_ts:
                history.pop(0)
        except IndexError:
            pass

    def _aggregate_history(self, history: list[TimeFrameStats]):
        """
        Aggregate minute-by-minute stats into hours.

        Go through the history and aggregate any contiguous sequences of stats
        of type minute that span at least an hour into hourly stats.
        """
        while True:
            try:
                start_idx, start_stats = next(
                    (i, s) for i, s in enumerate(history) if s.type != "hour")
            except StopIteration:
                # All hourly stats, nothing to do.
                return
            one_hour_later = start_stats.start_ts + 3600
            enumerated_end_stats = enumerate(
                it.pairwise(history[start_idx:]), start=1)
            for num_stats, (prev, curr) in enumerated_end_stats:
                if curr.end_ts >= one_hour_later:
                    # The current candidate is at least an hour later...
                    if curr.end_ts <= one_hour_later + 300:
                        # ... and ends at roughly the correct time.
                        end_stats = curr
                        end_ts = end_stats.end_ts
                    else:
                        # ... but ends way too late. Only aggregate to the
                        # previous candidate, and set an artificial end_ts.
                        end_stats = prev
                        end_ts = start_stats.start_ts + 3600
                    break
            else:
                # No stats after the start were at least an hour later.
                return
            craft_ids = set()
            num_positions = 0
            for stats in history[start_idx:start_idx + num_stats]:
                craft_ids |= stats.craft_ids
                num_positions += stats.num_positions
            hourly_stats = TimeFrameStats(
                type="hour", end_ts=end_ts, craft_ids=craft_ids,
                num_positions=num_positions)
            history[start_idx:start_idx + num_stats] = [hourly_stats]


class Scraper:
    class NoStats(Exception):
        pass

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def get_last_minute_stats(self) -> TimeFrameStats:
        raise NotImplementedError

    def get_current_stats(self) -> CurrentCraftStats:
        raise NotImplementedError


class ReadsbScraper(Scraper):
    STATS_PATH = pathlib.Path("/run/adsb-feeder-ultrafeeder/readsb/stats.json")
    AIRCRAFT_PATH = pathlib.Path(
        "/run/adsb-feeder-ultrafeeder/readsb/aircraft.json")

    def get_last_minute_stats(self) -> TimeFrameStats:
        try:
            stats_dict = self._read_stats_dict()
            num_positions = stats_dict["last1min"]["position_count_total"]
            icaos = self._get_last_minute_aircraft_icaos()
        except IOError as e:
            raise self.NoStats from e
        except Exception as e:
            self._logger.exception("Unexpected statistics file format.")
            raise self.NoStats from e
        return TimeFrameStats(
            type="minute", end_ts=time.time(), craft_ids=set(icaos),
            num_positions=num_positions)

    def _read_stats_dict(self) -> int:
        with self.STATS_PATH.open() as f:
            return json.load(f)

    def _get_last_minute_aircraft_icaos(self) -> set[str]:
        with self.AIRCRAFT_PATH.open() as f:
            aircraft_dict = json.load(f)
            return {
                aircraft["hex"]
                for aircraft in aircraft_dict["aircraft"]
                if not aircraft["hex"].startswith("~")}

    def get_current_stats(self) -> CurrentCraftStats:
        uptime = None
        num_positions = num_aircraft = 0
        try:
            stats_dict = self._read_stats_dict()
            num_positions = stats_dict["last1min"]["position_count_total"]
            num_aircraft = (
                stats_dict["aircraft_with_pos"]
                + stats_dict["aircraft_without_pos"])
            uptime = time.time() - stats_dict["total"]["start"]
        except IOError:
            # Probably not running, gracefully send empty stats.
            pass
        except:
            self._logger.exception("Unexpected statistics file format.")
        return CurrentCraftStats(
            uptime=uptime, num_crafts=num_aircraft,
            position_message_rate=num_positions / 60)


class AisCatcherScraper(Scraper):
    def __init__(self, conf: utils.data.Config):
        super().__init__()
        self._conf = conf

    def get_last_minute_stats(self) -> TimeFrameStats:
        try:
            stats_dict = self._get_stats_dict()
            num_positions = stats_dict["last_minute"]["count"]
            icaos = self._get_last_minute_ship_mmsis()
        except self.NoStats:
            raise
        except IOError as e:
            raise self.NoStats from e
        except Exception as e:
            self._logger.exception("Unexpected statistics file format.")
            raise self.NoStats from e
        return TimeFrameStats(
            type="minute", end_ts=time.time(), craft_ids=set(icaos),
            num_positions=num_positions)

    def _get_stats_dict(self) -> int:
        url = self._make_url("api/stat.json")
        return requests.get(url, timeout=1).json()

    def _make_url(self, path):
        port = self._conf.get("ports.aiscatcher")
        if not port:
            raise self.NoStats
        return f"http://localhost:{port}/{path}"

    def _get_last_minute_ship_mmsis(self) -> set[str]:
        url = self._make_url("api/ships_array.json")
        ships_array = requests.get(url, timeout=1).json()
        # Each ship is a plain array, with the first index being the MMSI.
        return {s[0] for s in ships_array["values"]}

    def get_current_stats(self) -> CurrentCraftStats:
        uptime = None
        num_positions = num_ships = 0
        try:
            stats_dict = self._get_stats_dict()
            num_positions = stats_dict["last_minute"]["count"]
            num_ships = stats_dict["last_minute"]["vessels"]
            uptime = float(stats_dict["run_time"] or 0)
        except IOError:
            # Probably not running, gracefully send empty stats.
            pass
        except:
            self._logger.exception("Unexpected statistics file format.")
        return CurrentCraftStats(
            uptime=uptime, num_crafts=num_ships,
            position_message_rate=num_positions / 60)


class IterableAsListJSONEncoder(json.JSONEncoder):
    def default(self, o):
        try:
            iterable = iter(o)
            return list(iterable)
        except TypeError:
            return super().default(o)
