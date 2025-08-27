import abc
import collections.abc as cl_abc
import datetime
import functools as ft
import itertools as it
import json
import logging
import numbers
import pathlib
import shutil
import threading
import typing as t
from typing import Optional

from .environment import Env
from .netconfig import NetConfig
from .util import is_true, print_err
from utils.config import read_values_from_env_file

APP_DIR = pathlib.Path("/opt/adsb")
METADATA_DIR = APP_DIR / "porttracker_feeder_install_metadata"
CONFIG_DIR = pathlib.Path("/etc/adsb")
CONFIG_FILE = CONFIG_DIR / "config.json"
CONFIG_FILE_BACKUP_TEMPLATE = (
    "config.json.backup.from:{from_version}.to:{to_version}.{ts}")
ENV_FILE = CONFIG_DIR / ".env"
VERSION_FILE = METADATA_DIR / "version.txt"
PREVIOUS_VERSION_FILE = METADATA_DIR / "previous_version.txt"
FRIENDLY_NAME_FILE = METADATA_DIR / "friendly_name.txt"
SECURE_IMAGE_FILE = APP_DIR / "adsb.im.secure_image"

logger = logging.getLogger(__name__)


class Setting(abc.ABC):
    """
    Abstract setting.

    A setting is a container for configuration data.
    """
    def __init__(self, config: "Config"):
        self._config = config

    @property
    @abc.abstractmethod
    def env_variables(self) -> dict[str, str]:
        """Dictionary of environment variables of this setting."""
        raise NotImplementedError

    @abc.abstractmethod
    def get(
            self, key_path: str, *, default: t.Any = None,
            use_setting_level_default: bool = True) -> t.Any:
        raise NotImplementedError

    @abc.abstractmethod
    def set(self, key_path: str, value: t.Any) -> None:
        raise NotImplementedError


class ScalarSetting(Setting):
    """
    A setting with a direct value.

    Scalar settings contain values directly, e.g. strings or numbers.
    """
    def __init__(
            self, config: "Config", value: t.Any, *,
            default: Optional[t.Any] = None,
            env_variable_name: Optional[str] = None, norestore: bool = False):
        """
        :param default: A default value to use if no value is set explicitly
            (i.e. is None).
        :param env_variable_name: The name of the environment variable with
            which this setting is represented. If None, the setting will not
            appear in the env file.
        :param norestore: Whether this setting should be omitted when restoring
            a config from backup.
        """
        super().__init__(config)
        self._value = value
        self._default = default
        self._env_variable_name = env_variable_name
        self._norestore = norestore

    @property
    def env_value_string(self) -> str:
        return str(self.get("", default=""))

    @property
    def env_variables(self) -> dict[str, str]:
        if self._env_variable_name is None:
            return {}
        return {self._env_variable_name: self.env_value_string}

    def get(
            self, key_path: t.Literal[""], *, default: t.Any = None,
            use_setting_level_default: bool = True) -> t.Any:
        """
        Get the value.

        The key_path must be the empty string. Gets the value of this setting,
        which is

        - the stored value, if it is not None,
        - otherwise the default given to this method, if it is not None,
        - otherwise the default given on setting construction, if
          use_setting_level_default is True,
        - otherwise None.

        :param use_setting_level_default: Whether to use the setting-level as
            the final fallback. If False, will return None if the value is None
            and the default in this get() call are None, even if the setting
            itself has a non-None default.
        """
        if key_path != "":
            raise ValueError("Scalar settings have no subkeys.")
        return self._coalesce_value(
            self._value, default, use_setting_level_default)

    def _coalesce_value(self, value, default, use_setting_level_default):
        if value is not None:
            return value
        elif default is not None:
            return default
        elif use_setting_level_default:
            return self._default
        return None

    def set(self, key_path: str, value: t.Any) -> None:
        """
        Set the value.

        The key_path must be the empty string. Sets the value and writes any
        changes through to the config file.
        """
        if key_path != "":
            raise ValueError("Scalar settings have no subkeys.")
        if value == self._value:
            return
        self._value = value
        # PERF we're writing to file with every change. we could introduce a
        # ctx manager that only writes on exit to save on writes++++++++++
        self._config.write_to_file()


class TypeConstrainedScalarSetting(ScalarSetting):
    """A scalar setting enforcing type constraints."""
    def __init__(
            self, required_type: type, config: "Config", value: t.Any, *args,
            default: Optional[t.Any] = None, **kwargs):
        self._required_type = required_type
        self._check_correct_type(value)
        if not isinstance(default, (self._required_type, type(None))):
            raise ValueError(
                f"Default value must be a {self._required_type}, but is "
                f"{type(default)}.")
        super().__init__(config, value, *args, default=default, **kwargs)

    def _check_correct_type(self, value):
        if not isinstance(value, (self._required_type, type(None))):
            raise ValueError(
                f"Value must be a {self._required_type}, but is {type(value)}."
            )

    def set(self, key_path: str, value: t.Any) -> None:
        self._check_correct_type(value)
        super().set(key_path, value)


class BoolSetting(TypeConstrainedScalarSetting):
    def __init__(
            self, *args, env_string_false="False", env_string_true="True",
            **kwargs):
        super().__init__(bool, *args, **kwargs)
        self._env_string_false = env_string_false
        self._env_string_true = env_string_true

    @property
    def env_value_string(self) -> str:
        if self._value is True:
            return self._env_string_true
        elif self._value is False:
            return self._env_string_false
        return super().env_value_string


class StringSetting(TypeConstrainedScalarSetting):
    def __init__(self, *args, **kwargs):
        super().__init__(str, *args, **kwargs)


class RealNumberSetting(TypeConstrainedScalarSetting):
    def __init__(self, *args, **kwargs):
        super().__init__(numbers.Real, *args, **kwargs)


class IntSetting(TypeConstrainedScalarSetting):
    def __init__(self, *args, **kwargs):
        super().__init__(int, *args, **kwargs)


class CompoundSetting(Setting):
    """
    A setting containing nested settings.

    Compound settings are essentially trees of settings nested according to a
    fixed schema. Child settings can be compound settings again for arbitrary
    nesting. The leaves of the tree are scalar settings, which can be accessed
    via period-delimited paths.
    """
    def __init__(
            self, config: "Config", settings_dict: Optional[dict[str, t.Any]],
            *, schema: dict[str, type[Setting]]):
        super().__init__(config)
        self._settings = {}
        if settings_dict is None:
            logger.warning(
                "No settings dictionary for compound settings with schema "
                f"{schema}, starting with an empty one.")
            settings_dict = {}
        for key, setting_class in schema.items():
            if "." in key:
                raise ValueError("Keys must not contain dots.")
            self._settings[key] = setting_class(
                self._config, settings_dict.get(key))

    @property
    def env_variables(self) -> dict[str, str]:
        env_variables = {}
        for setting in self._settings.values():
            if any(k in env_variables for k in setting.env_variables):
                logger.error(
                    "Overlapping environment variable names in "
                    f"{env_variables} and {setting.env_variables}.")
            env_variables |= setting.env_variables
        return env_variables

    def scalar_settings(self, prefix: str) -> set[tuple[str, ScalarSetting]]:
        settings = set()
        for key, setting in self._settings.items():
            sub_path = key
            if prefix:
                sub_path = f"{prefix}.{key}"
            if isinstance(setting, CompoundSetting):
                settings |= setting.scalar_settings(sub_path)
            else:
                settings.add((sub_path, setting))
        return settings

    def get(
            self, key_path: str, *, default: t.Any = None,
            use_setting_level_default: bool = True) -> t.Any:
        """
        Get the scalar setting's value at the given path.

        key_path is a period-delimited path to the desired setting, i.e. a
        sequence of keys at which the setting is nested. The behavior of
        default and use_setting_level_default is the same as for ScalarSetting
        (to which these parameters are passed down to).
        """
        key, key_path_tail = self._extract_key_head_and_tail(key_path)
        return self._settings[key].get(
            key_path_tail, default=default,
            use_setting_level_default=use_setting_level_default)

    def _extract_key_head_and_tail(self, key_path):
        components = key_path.split(".", maxsplit=1)
        try:
            key, key_path_tail = components
        except ValueError:
            key, key_path_tail = components[0], ""
        return key, key_path_tail

    def set(self, key_path: str, value: t.Any) -> None:
        """Set the value at the given path."""
        key, key_path_tail = self._extract_key_head_and_tail(key_path)
        self._settings[key].set(key_path_tail, value)


class GeneratedSetting(ScalarSetting):
    """
    A special scalar setting which generates its value based on other settings.

    Instead of a value, this setting is constructed with a value generator
    function, which takes the config as argument and produces the value. This
    way, settings can be defined that are dependent on multiple other settings.

    Generated settings cannot be set.

    The default value semantics are unchanged.
    """
    def __init__(
            self, config: "Config",
            value_generator: cl_abc.Callable[["Config"], t.Any], *,
            default: Optional[t.Any] = None,
            env_variable_name: Optional[str] = None):
        """
        :param value_generator: A function that takes the config as single
            parameter and returns the value of the setting.
        """
        super().__init__(
            config, None, default=default, env_variable_name=env_variable_name,
            norestore=True)
        self._value_generator = value_generator

    def get(
            self, key_path: t.Literal[""], *, default: t.Any = None,
            use_setting_level_default: bool = True) -> t.Any:
        if key_path != "":
            raise ValueError("Scalar settings have no subkeys.")
        value = self._value_generator(self._config)
        return self._coalesce_value(value, default, use_setting_level_default)

    def set(self, key_path: str, value: t.Any) -> None:
        raise ValueError("Generated settings can't be set.")


class SwitchedGeneratedSetting(GeneratedSetting):
    """
    A generated setting that takes one of 2 values based on a switch.

    This setting is configured with a switch_path, which is the path to a
    setting that is used as a boolean switch. Which value this setting takes on
    is based on the truthiness of that switch setting. The true and false
    values can be configured as either a fixed value, or as a path to a
    setting.
    """
    def __init__(
            self, config: "Config", _: t.Any, *, switch_path: str,
            true_value: t.Any = None, true_value_path: str = None,
            false_value: t.Any = None, false_value_path: str = None,
            env_variable_name: Optional[str] = None):
        """
        :param switch_path: Path to a setting that is used as the switch. If no
            setting with this path exists, it will default to None and the
            false value is used.
        :param true_value: The fixed value to use in case the switch is truthy.
            Mutually exclusive with true_value_path.
        :param true_value_path: The path to a setting whose value should be
            used in case the switch is truthy. Mutually exclusive with
            true_value.
        :param false_value: Similar to true_value.
        :param false_value_path: Similar to true_value_path.
        """
        if (None not in [true_value, true_value_path]
                or None not in [false_value, false_value_path]):
            raise ValueError(
                "For switch values, only a fixed value or a path can be "
                "specified, but not both.")

        def get_true_value():
            if true_value_path is not None:
                return config.get(true_value_path)
            return true_value

        def get_false_value():
            if false_value_path is not None:
                return config.get(false_value_path)
            return false_value

        def value_generator(config: "Config"):
            switch_value = config.get(switch_path)
            if switch_value is None:
                logger.warning(
                    "Switch value for a generated setting was None. This "
                    "indicates a misconfiguration.")
            if switch_value:
                return get_true_value()
            else:
                return get_false_value()

        super().__init__(
            config, value_generator, env_variable_name=env_variable_name)


class Config(CompoundSetting):
    """
    Application config.

    The config is a compoung setting which is the root of the settings tree. It
    may only be instantiated once.

    It has additionaly methods to read and write the config file, write the env
    file, and upgrade the config across versions. Any changes to the schema
    should introduce a new config version, for which there must be a migration
    function.
    """
    CONFIG_VERSION = 1
    _file_lock = threading.Lock()
    _has_instance = False
    _schema = {
        # --- Mandatory site data start ---
        "lat": ft.partial(RealNumberSetting, env_variable_name="FEEDER_LAT"),
        "lon": ft.partial(RealNumberSetting, env_variable_name="FEEDER_LONG"),
        "alt": ft.partial(RealNumberSetting, env_variable_name="FEEDER_ALT_M"),
        "tz": ft.partial(StringSetting, env_variable_name="FEEDER_TZ"),
        "site_name": ft.partial(StringSetting, env_variable_name="SITE_NAME"),
        # --- Mandatory site data end ---
        # sdrs_locked means the initial setup has been completed, don't change
        # SDR assignments unless requested explicitely by the user.
        "sdrs_locked": ft.partial(BoolSetting, default=False),
        # Misnomer, FEEDER_RTL_SDR is used as follows:
        # READSB_DEVICE_TYPE=${FEEDER_RTL_SDR}
        "readsb_device_type": ft.partial(
            StringSetting, default="rtlsdr",
            env_variable_name="FEEDER_RTL_SDR"),
        "biast": ft.partial(
            BoolSetting, default=False,
            env_variable_name="FEEDER_ENABLE_BIASTEE", env_string_false="",
            env_string_true="1"),
        "uatbiast": ft.partial(
            BoolSetting, default=False,
            env_variable_name="FEEDER_ENABLE_UATBIASTEE", env_string_false="",
            env_string_true="1"),
        "gain": ft.partial(StringSetting, default="autogain"),
        "gain_airspy": ft.partial(
            StringSetting, default="auto",
            env_variable_name="FEEDER_AIRSPY_GAIN"),
        "uatgain": ft.partial(
            StringSetting, default="autogain",
            env_variable_name="UAT_SDR_GAIN"),
        "serial_devices": ft.partial(
            CompoundSetting, schema={
                "1090": ft.partial(
                    StringSetting, env_variable_name="FEEDER_SERIAL_1090"),
                "978": ft.partial(
                    StringSetting, env_variable_name="FEEDER_SERIAL_978"),
                "ais": ft.partial(
                    StringSetting, env_variable_name="FEEDER_SERIAL_AIS"),
                "other-0": StringSetting,
                "other-1": StringSetting,
                "other-2": StringSetting,
                "other-3": StringSetting,}),
        "uat_device_type": ft.partial(
            StringSetting, default="rtlsdr",
            env_variable_name="FEEDER_UAT_DEVICE_TYPE"),
        "beast-reduce-optimize-for-mlat": BoolSetting,
        "max_range": ft.partial(
            RealNumberSetting, default=300,
            env_variable_name="FEEDER_MAX_RANGE"),
        "use_gpsd": ft.partial(BoolSetting, default=False),
        "has_gpsd": ft.partial(BoolSetting, default=False),
        "docker_concurrent": ft.partial(BoolSetting, default=True),
        "temperature_block": ft.partial(BoolSetting, default=False),
        # Ultrafeeder config, used for all 4 types of Ultrafeeder instances
        "ultrafeeder_config": ft.partial(
            StringSetting, env_variable_name="FEEDER_ULTRAFEEDER_CONFIG"),
        "adsblol_uuid": ft.partial(
            StringSetting, env_variable_name="ADSBLOL_UUID"),
        "ultrafeeder_uuid": ft.partial(
            StringSetting, env_variable_name="ULTRAFEEDER_UUID"),
        "mlat_privacy": ft.partial(
            BoolSetting, default=False, env_variable_name="MLAT_PRIVACY"),
        "mlat_enable": ft.partial(
            BoolSetting, default=True, env_variable_name="MLAT_ENABLE"),
        "route_api": ft.partial(
            BoolSetting, default=True,
            env_variable_name="FEEDER_TAR1090_USEROUTEAPI",
            env_string_false="", env_string_true="1"),
        "tar1090_configjs_append": ft.partial(
            StringSetting, env_variable_name="FEEDER_TAR1090_CONFIGJS_APPEND"),
        "tar1090_image_config_link": ft.partial(
            StringSetting, default="http://HOSTNAME:80/",
            env_variable_name="FEEDER_TAR1090_IMAGE_CONFIG_LINK"),
        "css_theme": ft.partial(StringSetting, default="auto"),
        "tar1090_query_params": ft.partial(StringSetting, default=""),
        "uat978": ft.partial(
            BoolSetting, default=False,
            env_variable_name="FEEDER_ENABLE_UAT978"),
        "replay978": StringSetting,
        # hostname ultrafeeder uses to get 978 data
        "978host": ft.partial(
            StringSetting, env_variable_name="FEEDER_UAT978_HOST"),
        "rb978host": ft.partial(
            StringSetting, env_variable_name="FEEDER_RB_UAT978_HOST"
        ),
        # add the URL to the dump978 map
        "978url": ft.partial(
            StringSetting, env_variable_name="FEEDER_URL_978"),
        # URL to get Airspy stats (used in stage2)
        "airspyurl": ft.partial(
            StringSetting, env_variable_name="FEEDER_URL_AIRSPY"),
        # port for Airspy stats (used in micro feeder and handed to stage2 via base_info)
        "airspyport": ft.partial(
            IntSetting, default=8070, env_variable_name="FEEDER_AIRSPY_PORT"),
        # URL to get remote 1090 stats data (for gain, %-age of strong signals, and signal graph)
        "rtlsdrurl": ft.partial(
            StringSetting, env_variable_name="FEEDER_URL_RTLSDR"
        ),
        # magic setting for piaware to get 978 data
        "978piaware": ft.partial(
            StringSetting, env_variable_name="FEEDER_PIAWARE_UAT978"),
        # Misc
        "heywhatsthat": ft.partial(BoolSetting, default=False),
        "heywhatsthat_id": ft.partial(
            StringSetting, env_variable_name="FEEDER_HEYWHATSTHAT_ID"),
        # Aggregators
        "aggregators": ft.partial(
            CompoundSetting,
            schema={
                "adsblol": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "flyitaly": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "adsbx": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "tat": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "planespotters": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "adsbfi": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "avdelphi": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "hpradar": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "alive": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                    }),
                "flightradar": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_FLIGHTRADAR24_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_FR24_SHARING_KEY"),
                        "uat_key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_FR24_UAT_SHARING_KEY"),
                    }),
                "flightaware": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_FLIGHTAWARE_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PIAWARE_FEEDER_ID"),}),
                "radarbox": ft.partial(
                    CompoundSetting,
                    schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_RADARBOX_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_RADARBOX_SHARING_KEY"),
                        # radarbox station number used for status link
                        "sn": StringSetting,
                        # radarbox key that was set when the station number was determined
                        # if it doesn't match the currently set share key, determine new station number
                        "snkey": StringSetting,}),
                "planefinder": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_PLANEFINDER_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PLANEFINDER_SHARECODE"),
                    }),
                "adsbhub": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_ADSBHUB_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_ADSBHUB_STATION_KEY"),}),
                "opensky": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_OPENSKY_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_OPENSKY_SERIAL"),
                        "user": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_OPENSKY_USERNAME"),}),
                "radarvirtuel": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_RADARVIRTUEL_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_RV_FEEDER_KEY"),}),
                "planewatch": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_PLANEWATCH_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PLANEWATCH_API_KEY"),}),
                "1090uk": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_1090UK_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_1090UK_API_KEY"),}),
                "sdrmap": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_SDRMAP_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_SM_PASSWORD"),
                        "user": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_SM_USERNAME"),}),
                "porttracker": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting, env_variable_name=
                            "FEEDER_PORTTRACKER_DATA_SHARING_KEY"),
                        "station_id": ft.partial(
                            IntSetting,
                            env_variable_name="FEEDER_PORTTRACKER_STATION_ID"),
                        "mqtt_url": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PORTTRACKER_MQTT_URL"),
                        "mqtt_client_id": ft.partial(
                            StringSetting, env_variable_name=
                            "FEEDER_PORTTRACKER_MQTT_CLIENT_ID"),
                        "mqtt_qos": ft.partial(
                            IntSetting,
                            env_variable_name="FEEDER_PORTTRACKER_MQTT_QOS"),
                        "mqtt_topic": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PORTTRACKER_MQTT_TOPIC"),
                        "mqtt_msgformat": ft.partial(
                            StringSetting, env_variable_name=
                            "FEEDER_PORTTRACKER_MQTT_MSGFORMAT"),}),
                "aiscatcher": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_AISCATCHER_ENABLED"),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_AISCATCHER_FEEDER_KEY"),
                    }),
                "aishub": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_AISHUB_ENABLED"),
                        "key": ft.partial(
                            IntSetting,
                            env_variable_name="FEEDER_AISHUB_UDP_PORT"),})}),
        "rbthermalhack": ft.partial(
            StringSetting, env_variable_name="FEEDER_RB_THERMAL_HACK"),
        # ADSB.im specific
        "aggregator_choice": ft.partial(
            StringSetting, env_variable_name="_ADSBIM_AGGREGATORS_SELECTION"),
        "base_version": ft.partial(
            StringSetting, env_variable_name="_ADSBIM_BASE_VERSION",
            norestore=True),
        "board_name": ft.partial(
            StringSetting, env_variable_name="_ADSBIM_STATE_BOARD_NAME",
            norestore=True),
        "mdns": ft.partial(
            CompoundSetting,
            schema={
                "is_enabled": ft.partial(BoolSetting, default=True),
                "domains": ft.partial(StringSetting, default=""),}),
        "prometheus": ft.partial(
            CompoundSetting, schema={
                "is_enabled": ft.partial(BoolSetting, default=False),
                "textfile_dir": ft.partial(
                    StringSetting, default="/var/lib/prometheus/node-exporter",
                    env_variable_name="AF_PROMETHEUS_TEXTFILE_DIR"),}),
        "ports": ft.partial(
            CompoundSetting,
            schema={
                "web": ft.partial(
                    IntSetting, default=80, env_variable_name="AF_WEBPORT",
                    norestore=True),
                "dazzle": ft.partial(
                    IntSetting, default=9999,
                    env_variable_name="AF_DAZZLE_PORT", norestore=True),
                "tar1090": ft.partial(
                    IntSetting, default=8080,
                    env_variable_name="AF_TAR1090_PORT", norestore=True),
                "tar1090adjusted": ft.partial(
                    IntSetting, default=8080,
                    env_variable_name="AF_TAR1090_PORT_ADJUSTED"),
                "nanotar1090adjusted": ft.partial(
                    IntSetting, default=8080,
                    env_variable_name="AF_NANO_TAR1090_PORT_ADJUSTED"
                ),
                "uat": ft.partial(
                    IntSetting, default=9780,
                    env_variable_name="AF_UAT978_PORT", norestore=True),
                "piamap": ft.partial(
                    IntSetting, default=8081,
                    env_variable_name="AF_PIAWAREMAP_PORT", norestore=True),
                "piastat": ft.partial(
                    IntSetting, default=8082,
                    env_variable_name="AF_PIAWARESTAT_PORT", norestore=True),
                "fr": ft.partial(
                    IntSetting, default=8754,
                    env_variable_name="AF_FLIGHTRADAR_PORT"),
                "pf": ft.partial(
                    IntSetting, default=30053,
                    env_variable_name="AF_PLANEFINDER_PORT"),
                "aiscatcher": ft.partial(
                    IntSetting, default=41580,
                    env_variable_name="AF_AIS_CATCHER_PORT"),}),
        "image_name": ft.partial(StringSetting, norestore=True),
        "secure_image": ft.partial(
            BoolSetting, default=False, env_variable_name="AF_IS_SECURE_IMAGE",
            norestore=True),
        "airspy": BoolSetting,
        "sdrplay": BoolSetting,
        "sdrplay_license_accepted": BoolSetting,
        "journal_configured": ft.partial(BoolSetting, default=False),
        "ssh_configured": BoolSetting,
        "base_config": ft.partial(
            BoolSetting, default=False,
            env_variable_name="AF_IS_BASE_CONFIG_FINISHED"),
        "aggregators_chosen": ft.partial(BoolSetting, default=False),
        "nightly_base_update": ft.partial(
            BoolSetting,
            env_variable_name="AF_IS_NIGHTLY_BASE_UPDATE_ENABLED"),
        "nightly_feeder_update": ft.partial(
            BoolSetting,
            env_variable_name="AF_IS_NIGHTLY_FEEDER_UPDATE_ENABLED"),
        "zerotierid": StringSetting,
        "tailscale_ll": StringSetting,
        "tailscale_name": StringSetting,
        "tailscale_extras": StringSetting,
        "ultrafeeder_extra_env": StringSetting,
        "ultrafeeder_extra_args": StringSetting,
        "tar1090_ac_db": ft.partial(
            BoolSetting, default=True,
            env_variable_name="FEEDER_TAR1090_ENABLE_AC_DB"),
        "mlathub_disable": ft.partial(
            BoolSetting, default=False,
            env_variable_name="FEEDER_MLATHUB_DISABLE"),
        "mlathub_enable": ft.partial(
            BoolSetting, default=True,
            env_variable_name="FEEDER_MLATHUB_ENABLE"),
        "remote_sdr": StringSetting,
        "dns_state": ft.partial(BoolSetting, norestore=True),
        "under_voltage": ft.partial(BoolSetting, norestore=True),
        "low_disk": ft.partial(BoolSetting, norestore=True),
        "stage2": ft.partial(
            BoolSetting, default=False, env_variable_name="AF_IS_STAGE2"
        ),
        "stage2_nano": ft.partial(
            BoolSetting, default=False,
            env_variable_name="AF_STAGE2_NANOFEEDER"
        ),
        "nano_beast_port": ft.partial(
            IntSetting, default=30005, env_variable_name="AF_NANO_BEAST_PORT"
        ),
        "nano_beastreduce_port": ft.partial(
            IntSetting, default=30006,
            env_variable_name="AF_NANO_BEASTREDUCE_PORT"
        ),
        "num_micro_sites": ft.partial(
            IntSetting, default=0, env_variable_name="AF_NUM_MICRO_SITES"
        ),
    }

    def __init__(self, settings_dict: dict[str, t.Any]):
        if Config._has_instance:
            raise ValueError("Config has already been instantiated.")
        Config._has_instance = True
        super().__init__(self, settings_dict, schema=self._schema)

    def write_to_file(self):
        config_dict = {}
        for key_path, setting in self.scalar_settings(""):
            if isinstance(setting, GeneratedSetting):
                # Don't write generated settings to the file.
                continue
            path_components = key_path.split(".")
            sub_dict = config_dict
            for key in path_components[:-1]:
                sub_dict = sub_dict.setdefault(key, {})
            sub_dict[path_components[-1]] = setting.get(
                "", use_setting_level_default=False)
        config_dict["config_version"] = self.CONFIG_VERSION
        with Config._file_lock, CONFIG_FILE.open("w") as f:
            json.dump(config_dict, f)

    def write_env_file(self):
        with Config._file_lock, ENV_FILE.open("w") as f:
            f.writelines(
                f"{key}={value}\n"
                for key, value in self.env_variables.items())


    @staticmethod
    def load_from_file() -> "Config":
        with Config._file_lock:
            config_dict = Config._load_and_maybe_upgrade_config_dict()
            return Config(config_dict)

    @staticmethod
    def _load_and_maybe_upgrade_config_dict() -> dict[str, t.Any]:
        with CONFIG_FILE.open() as f:
            config_dict = json.load(f)
        version = config_dict.pop("config_version", 0)
        if version != Config.CONFIG_VERSION:
            config_dict = Config._upgraded_config_dict(config_dict, version)
        return config_dict

    @staticmethod
    def _upgraded_config_dict(
            config_dict: dict[str, t.Any],
            from_version: int) -> dict[str, t.Any]:
        if from_version > Config.CONFIG_VERSION:
            raise ValueError(
                f"Found config with unknown higher version {from_version} "
                f"(need version {Config.CONFIG_VERSION}).")
        upgrade_path = list(
            it.pairwise(range(from_version, Config.CONFIG_VERSION + 1)))
        logger.info(
            f"Found config with version {from_version}, need to upgrade to "
            f"{Config.CONFIG_VERSION}. Upgrade path: {upgrade_path}.")
        for from_version, to_version in upgrade_path:
            config_dict = Config._upgrade_config_file(from_version, to_version)
        return config_dict

    @staticmethod
    def _upgrade_config_file(from_version: int,
                             to_version: int) -> dict[str, t.Any]:
        upgrader = Config._config_upgraders[(from_version, to_version)]
        with CONFIG_FILE.open() as f:
            config_dict = json.load(f)
        version = config_dict.pop("config_version", 0)
        assert version == from_version
        ts = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
        backup_file = (
            CONFIG_DIR / CONFIG_FILE_BACKUP_TEMPLATE.format(
                from_version=from_version, to_version=to_version, ts=ts))
        shutil.copyfile(CONFIG_FILE, backup_file)
        logger.info(
            f"Upgrading config from {from_version} to {to_version}. Wrote "
            f"backup file {backup_file}.")
        try:
            config_dict = upgrader(config_dict)
        except:
            logger.exception(
                f"Error upgrading config from {from_version} to {to_version}.")
            raise
        config_dict["config_version"] = Config.CONFIG_VERSION
        with CONFIG_FILE.open("w") as f:
            json.dump(config_dict, f)
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_legacy_to_1(
            config_dict: dict[str, t.Any]) -> dict[str, t.Any]:
        return {
            "lat": float(config_dict["FEEDER_LAT"][0]),
            "lon": float(config_dict["FEEDER_LONG"][0]),
            "alt": float(config_dict["FEEDER_ALT_M"][0]),
            "tz": config_dict["FEEDER_TZ"][0],
            "site_name": config_dict["MLAT_SITE_NAME"][0],
            "sdrs_locked": config_dict["FEEDER_SDRS_LOCKED"],
            "readsb_device_type": config_dict["FEEDER_RTL_SDR"],
            "biast": config_dict["FEEDER_ENABLE_BIASTEE"],
            "uatbiast": config_dict["FEEDER_ENABLE_UATBIASTEE"],
            "gain": config_dict["FEEDER_READSB_GAIN"],
            "gain_airspy": config_dict["FEEDER_AIRSPY_GAIN"],
            "uatgain": config_dict["UAT_SDR_GAIN"],
            "serial_devices": {
                "1090": config_dict["FEEDER_SERIAL_1090"],
                "978": config_dict["FEEDER_SERIAL_978"],
                "ais": config_dict["FEEDER_SERIAL_AIS"],
                "other-0": config_dict["FEEDER_UNUSED_SERIAL_0"],
                "other-1": config_dict["FEEDER_UNUSED_SERIAL_1"],
                "other-2": config_dict["FEEDER_UNUSED_SERIAL_2"],
                "other-3": config_dict["FEEDER_UNUSED_SERIAL_3"],},
            "uat_device_type": config_dict["FEEDER_UAT_DEVICE_TYPE"],
            "beast-reduce-optimize-for-mlat": config_dict[
                "READSB_NET_BR_OPTIMIZE_FOR_MLAT"],
            "max_range": config_dict["FEEDER_MAX_RANGE"][0],
            "use_gpsd": config_dict["FEEDER_USE_GPSD"],
            "has_gpsd": config_dict["_ADSBIM_FEEDER_HAS_GPSD"],
            "docker_concurrent": config_dict[
                "_ADSBIM_STATE_DOCKER_CONCURRENT"],
            "temperature_block": config_dict[
                "_ADSBIM_STATE_TEMPERATURE_BLOCK"],
            "ultrafeeder_config": config_dict["FEEDER_ULTRAFEEDER_CONFIG"][0],
            "adsblol_uuid": config_dict["ADSBLOL_UUID"][0],
            "ultrafeeder_uuid": config_dict["ULTRAFEEDER_UUID"][0],
            "mlat_privacy": config_dict["MLAT_PRIVACY"][0],
            "mlat_enable": config_dict["MLAT_ENABLE"][0],
            "route_api": config_dict["FEEDER_TAR1090_USEROUTEAPI"][0],
            "tar1090_configjs_append": config_dict[
                "FEEDER_TAR1090_CONFIGJS_APPEND"],
            "tar1090_image_config_link": config_dict[
                "FEEDER_TAR1090_IMAGE_CONFIG_LINK"],
            "css_theme": config_dict["_ASDBIM_CSS_THEME"],
            "tar1090_query_params": config_dict[
                "_ASDBIM_TAR1090_QUERY_PARAMS"],
            "uat978": config_dict["FEEDER_ENABLE_UAT978"][0],
            "replay978": config_dict["FEEDER_UAT_REPLAY978"][0],
            "978host": config_dict["FEEDER_UAT_REPLAY978"][0],
            "rb978host": config_dict["FEEDER_RB_UAT978_HOST"][0],
            "978url": config_dict["FEEDER_URL_978"][0],
            "airspyurl": config_dict["FEEDER_URL_AIRSPY"][0],
            "airspyport": config_dict["FEEDER_AIRSPY_PORT"],
            "rtlsdrurl": config_dict["FEEDER_URL_RTLSDR"][0],
            "978piaware": config_dict["FEEDER_PIAWARE_UAT978"][0],
            "heywhatsthat": config_dict["_ADSBIM_HEYWHATSTHAT_ENABLED"][0],
            "heywhatsthat_id": config_dict["FEEDER_HEYWHATSTHAT_ID"][0],
            "aggregators": {
                "adsblol": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBLOL_ENABLED"][0],},
                "flyitaly": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_FLYITALYADSB_ENABLED"]
                    [0],},
                "adsbx": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBX_ENABLED"][0],},
                "tat": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_TAT_ENABLED"][0],},
                "planespotters": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_PLANESPOTTERS_ENABLED"]
                    [0],},
                "adsbfi": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBFI_ENABLED"][0],},
                "avdelphi": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_AVDELPHI_ENABLED"][0],},
                "hpradar": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_HPRADAR_ENABLED"][0],},
                "alive": {
                    "is_enabled": config_dict[
                        "_ADSBIM_STATE_IS_ULTRAFEEDER_ALIVE_ENABLED"][0],},
                "flightradar": {
                    "is_enabled": config_dict["AF_IS_FLIGHTRADAR24_ENABLED"]
                    [0],
                    "key": config_dict["FEEDER_FR24_SHARING_KEY"][0],
                    "uat_key": config_dict["FEEDER_FR24_UAT_SHARING_KEY"][0],},
                "flightaware": {
                    "is_enabled": config_dict["AF_IS_FLIGHTAWARE_ENABLED"][0],
                    "key": config_dict["FEEDER_PIAWARE_FEEDER_ID"][0],},
                "radarbox": {
                    "is_enabled": config_dict["AF_IS_RADARBOX_ENABLED"][0],
                    "key": config_dict["FEEDER_RADARBOX_SHARING_KEY"][0],
                    "sn": config_dict["FEEDER_RADARBOX_SN"][0],
                    "snkey": config_dict[
                        "_ADSBIM_STATE_FEEDER_RADARBOX_SN_KEY"][0],},
                "planefinder": {
                    "is_enabled": config_dict["AF_IS_PLANEFINDER_ENABLED"][0],
                    "key": config_dict["FEEDER_PLANEFINDER_SHARECODE"][0],},
                "adsbhub": {
                    "is_enabled": config_dict["AF_IS_ADSBHUB_ENABLED"][0],
                    "key": config_dict["FEEDER_ADSBHUB_STATION_KEY"][0],},
                "opensky": {
                    "is_enabled": config_dict["AF_IS_OPENSKY_ENABLED"][0],
                    "key": config_dict["FEEDER_OPENSKY_SERIAL"][0],
                    "user": config_dict["FEEDER_OPENSKY_USERNAME"][0],},
                "radarvirtuel": {
                    "is_enabled": config_dict["AF_IS_RADARVIRTUEL_ENABLED"][0],
                    "key": config_dict["FEEDER_RV_FEEDER_KEY"][0],},
                "planewatch": {
                    "is_enabled": config_dict["AF_IS_PLANEWATCH_ENABLED"][0],
                    "key": config_dict["FEEDER_PLANEWATCH_API_KEY"][0],},
                "1090uk": {
                    "is_enabled": config_dict["AF_IS_1090UK_ENABLED"][0],
                    "key": config_dict["FEEDER_1090UK_API_KEY"][0],},
                "sdrmap": {
                    "is_enabled": config_dict["AF_IS_SDRMAP_ENABLED"][0],
                    "key": config_dict["FEEDER_SM_PASSWORD"][0],
                    "user": config_dict["FEEDER_SM_USERNAME"][0],},
                "porttracker": {
                    "is_enabled": config_dict["AF_IS_PORTTRACKER_ENABLED"][0],
                    "key": config_dict["FEEDER_PORTTRACKER_DATA_SHARING_KEY"]
                    [0],
                    "station_id": int(
                        config_dict["FEEDER_PORTTRACKER_STATION_ID"][0]),
                    "mqtt_url": config_dict["FEEDER_PORTTRACKER_MQTT_URL"][0],
                    "mqtt_client_id": config_dict[
                        "FEEDER_PORTTRACKER_MQTT_CLIENT_ID"][0],
                    "mqtt_qos": int(
                        config_dict["FEEDER_PORTTRACKER_MQTT_QOS"][0]),
                    "mqtt_topic": config_dict["FEEDER_PORTTRACKER_MQTT_TOPIC"]
                    [0],
                    "mqtt_msgformat": config_dict[
                        "FEEDER_PORTTRACKER_MQTT_MSGFORMAT"][0],},
                "aiscatcher": {
                    "is_enabled": config_dict["AF_IS_AISCATCHER_ENABLED"][0],
                    "key": config_dict["FEEDER_AISCATCHER_FEEDER_KEY"][0],},
                "aishub": {
                    "is_enabled": config_dict["AF_IS_AISHUB_ENABLED"][0],
                    "key": config_dict["FEEDER_AISHUB_UDP_PORT"][0],},},
            "rbthermalhack": config_dict["FEEDER_RB_THERMAL_HACK"],
            "aggregator_choice": config_dict["_ADSBIM_AGGREGATORS_SELECTION"],
            "base_version": config_dict["_ADSBIM_BASE_VERSION"],
            "board_name": config_dict["_ADSBIM_STATE_BOARD_NAME"],
            "mdns": {
                "is_enabled": config_dict["AF_IS_MDNS_ENABLED"],
                "domains": config_dict["AF_MDNS_DOMAINS"],},
            "prometheus": {
                "is_enabled": config_dict["AF_IS_PROMETHEUS_EXPORTER_ENABLED"],
                "textfile_dir": config_dict["AF_PROMETHEUS_TEXTFILE_DIR"],},
            "ports": {
                "web": config_dict["AF_WEBPORT"],
                "dazzle": config_dict["AF_DAZZLE_PORT"],
                "tar1090": config_dict["AF_TAR1090_PORT"],
                "tar1090adjusted": config_dict["AF_TAR1090_PORT_ADJUSTED"],
                "nanotar1090adjusted": config_dict[
                    "AF_NANO_TAR1090_PORT_ADJUSTED"],
                "uat": config_dict["AF_UAT978_PORT"],
                "piamap": config_dict["AF_PIAWAREMAP_PORT"],
                "piastat": config_dict["AF_PIAWARESTAT_PORT"],
                "fr": config_dict["AF_FLIGHTRADAR_PORT"],
                "pf": config_dict["AF_PLANEFINDER_PORT"],
                "aiscatcher": config_dict["AF_AIS_CATCHER_PORT"],},
            "image_name": config_dict["_ADSBIM_STATE_IMAGE_NAME"],
            "secure_image": config_dict["AF_IS_SECURE_IMAGE"],
            "airspy": config_dict["AF_IS_AIRSPY_ENABLED"],
            "sdrplay": config_dict["AF_IS_SDRPLAY_ENABLED"],
            "sdrplay_license_accepted": config_dict[
                "AF_IS_SDRPLAY_LICENSE_ACCEPTED"],
            "journal_configured": config_dict[
                "_ADSBIM_STATE_JOURNAL_CONFIGURED"],
            "ssh_configured": config_dict["_ADSBIM_STATE_IS_SSH_CONFIGURED"],
            "base_config": config_dict["AF_IS_BASE_CONFIG_FINISHED"],
            "aggregators_chosen": config_dict[
                "_ADSBIM_STATE_AGGREGATORS_CHOSEN"],
            "nightly_base_update": config_dict[
                "AF_IS_NIGHTLY_BASE_UPDATE_ENABLED"],
            "nightly_feeder_update": config_dict[
                "AF_IS_NIGHTLY_FEEDER_UPDATE_ENABLED"],
            "zerotierid": config_dict["_ADSBIM_STATE_ZEROTIER_KEY"],
            "tailscale_ll": config_dict["_ADSBIM_STATE_TAILSCALE_LOGIN_LINK"],
            "tailscale_name": config_dict["_ADSBIM_STATE_TAILSCALE_NAME"],
            "tailscale_extras": config_dict[
                "_ADSBIM_STATE_TAILSCALE_EXTRA_ARGS"],
            "ultrafeeder_extra_env": config_dict["_ADSBIM_STATE_EXTRA_ENV"],
            "ultrafeeder_extra_args": config_dict[
                "_ADSBIM_STATE_ULTRAFEEDER_EXTRA_ARGS"],
            "tar1090_ac_db": config_dict["FEEDER_TAR1090_ENABLE_AC_DB"],
            "mlathub_disable": config_dict["FEEDER_MLATHUB_DISABLE"],
            "mlathub_enable": config_dict["FEEDER_MLATHUB_ENABLE"],
            "remote_sdr": config_dict["_ADSBIM_STATE_REMOTE_SDR"],
            "dns_state": config_dict["_ADSBIM_STATE_LAST_DNS_CHECK"],
            "under_voltage": config_dict["_ADSBIM_STATE_UNDER_VOLTAGE"],
            "low_disk": config_dict["_ADSBIM_STATE_LOW_DISK"],
            "stage2": config_dict["AF_IS_STAGE2"],
            "stage2_nano": config_dict["AF_STAGE2_NANOFEEDER"],
            "nano_beast_port": int(config_dict["AF_NANO_BEAST_PORT"]),
            "nano_beastreduce_port": int(
                config_dict["AF_NANO_BEASTREDUCE_PORT"]),
            "num_micro_sites": config_dict["AF_NUM_MICRO_SITES"],}

    _config_upgraders = {(0, 1): _upgrade_config_dict_from_legacy_to_1}
    for k in it.pairwise(range(CONFIG_VERSION + 1)):
        # Make sure we have an upgrade function for every version increment,
        # where the _config_upgraders dict maps tuples of
        # (from_version, to_version) to upgrader functions.
        assert k in _config_upgraders
        assert callable(_config_upgraders[k])

class Data:
    def __new__(cc):
        if not hasattr(cc, "instance"):
            cc.instance = super(Data, cc).__new__(cc)
        return cc.instance

    _env_by_tags_dict = dict()

    _proxy_routes = [
        # endpoint, port, url_path
        ["/map/", "TAR1090", "/"],
        ["/tar1090/", "TAR1090", "/"],
        ["/graphs1090/", "TAR1090", "/graphs1090/"],
        ["/graphs/", "TAR1090", "/graphs1090/"],
        ["/stats/", "TAR1090", "/graphs1090/"],
        ["/fa/", "PIAWAREMAP", "/"],
        ["/fa-status/", "PIAWARESTAT", "/"],
        ["/fa-status.json/", "PIAWARESTAT", "/status.json"],
        ["/fr24/", "FLIGHTRADAR", "/"],
        ["/fr24-monitor.json/", "FLIGHTRADAR", "/monitor.json"],
        ["/planefinder/", "PLANEFINDER", "/"],
        ["/planefinder-stat/", "PLANEFINDER", "/stats.html"],
        ["/dump978/", "UAT978", "/skyaware978/"],
        ["/logs/", "DAZZLE", "/"],
        ["/dozzle/<sub_path>", "DAZZLE", "/"],
        ["/config/", "DAZZLE", "/setup"],
        ["/ais-catcher/", "AIS_CATCHER", "/"],
    ]

    @property
    def proxy_routes(self):
        ret = []
        for [endpoint, _env, path] in self._proxy_routes:
            env = "AF_" + _env.upper() + "_PORT"
            port = self.env(env).value
            ret.append([endpoint, port, path])
            if endpoint in [
                "/fr24/",
                "/fr24-monitor.json/",
                "/fa/",
                "/fa-status/",
                "/fa-status.json/",
                "/planefinder/",
                "/planefinder-stat/",
            ]:
                # inc_port is the id of the stage2 microfeeder
                # example endpoint: '/fa-status.json_<int:inc_port>/'
                # this is passed to the URL handling function in flask.py
                # this function will add (inc_port * 1000) to the port
                if endpoint[-1] == "/":
                    ret.append([endpoint[:-1] + f"_<int:inc_port>/", port, path])
                else:
                    ret.append([endpoint + f"_<int:inc_port>", port, path])
            if endpoint in [
                "/map/",
                "/stats/",
            ]:
                # idx is the id of the stage2 microfeeder
                # example endpoint: '/map_<int:idx>/'
                # this is passed to the URL handling function in flask.py
                # this function will insert /idx into the URL after the domain
                if endpoint[-1] == "/":
                    ret.append([endpoint[:-1] + f"_<int:idx>/", port, path])
                else:
                    ret.append([endpoint + f"_<int:idx>", port, path])
        return ret

    # these are the default values for the env file
    netconfigs = {
        "adsblol": NetConfig(
            "adsb,feed.adsb.lol,30004,beast_reduce_plus_out",
            "mlat,feed.adsb.lol,31090,39001",
            has_policy=True,
        ),
        "flyitaly": NetConfig(
            "adsb,dati.flyitalyadsb.com,4905,beast_reduce_plus_out",
            "mlat,dati.flyitalyadsb.com,30100,39002",
            has_policy=True,
        ),
        "adsbx": NetConfig(
            "adsb,feed1.adsbexchange.com,30004,beast_reduce_plus_out",
            "mlat,feed.adsbexchange.com,31090,39003",
            has_policy=True,
        ),
        "tat": NetConfig(
            "adsb,feed.theairtraffic.com,30004,beast_reduce_plus_out",
            "mlat,feed.theairtraffic.com,31090,39004",
            has_policy=False,
        ),
        "planespotters": NetConfig(
            "adsb,feed.planespotters.net,30004,beast_reduce_plus_out",
            "mlat,mlat.planespotters.net,31090,39005",
            has_policy=True,
        ),
        "adsbfi": NetConfig(
            "adsb,feed.adsb.fi,30004,beast_reduce_plus_out",
            "mlat,feed.adsb.fi,31090,39007",
            has_policy=True,
        ),
        "avdelphi": NetConfig(
            "adsb,data.avdelphi.com,24999,beast_reduce_plus_out",
            "",
            has_policy=True,
        ),
        "hpradar": NetConfig(
            "adsb,skyfeed.hpradar.com,30004,beast_reduce_plus_out",
            "mlat,skyfeed.hpradar.com,31090,39011",
            has_policy=False,
        ),
        "alive": NetConfig(
            "adsb,feed.airplanes.live,30004,beast_reduce_plus_out",
            "mlat,feed.airplanes.live,31090,39012",
            has_policy=True,
        ),
    }
    # we have four different types of "feeders":
    # 1. integrated feeders (single SBC where one Ultrafeeder collects from SDR and send to aggregator)
    # 2. micro feeders (SBC with SDR(s) attached, talking to a stage2 micro proxy)
    # 3. stage2 micro proxies (run on the stage2 system, each talking to a micro feeder and to aggregators)
    # 4. stage2 aggregator (showing a combined map of the micro feeders)
    # most feeder related values are lists with element 0 being used either for an
    # integrated feeder, a micro feeder, or the aggregator in a stage2 setup, and
    # elements 1 .. num_micro_sites are used for the micro-proxy instances
    _env = {
        # Mandatory site data
        Env("FEEDER_LAT", default=[""], is_mandatory=True, tags=["lat"]),
        Env("FEEDER_LONG", default=[""], is_mandatory=True, tags=["lon"]),
        Env("FEEDER_ALT_M", default=[""], is_mandatory=True, tags=["alt"]),
        Env("FEEDER_TZ", default=[""], tags=["tz"]),
        Env("MLAT_SITE_NAME", default=[""], is_mandatory=True, tags=["site_name"]),
        # SDR settings are only valid on an integrated feeder or a micro feeder, not on stage2
        # sdrs_locked means the initial setup has been completed, don't change
        # SDR assignments unless requested explicitely by the user
        Env("FEEDER_SDRS_LOCKED", default=False, tags=["sdrs_locked"]),
        # misnomer, FEEDER_RTL_SDR is used as follows: READSB_DEVICE_TYPE=${FEEDER_RTL_SDR}
        Env("FEEDER_RTL_SDR", default="rtlsdr", tags=["readsb_device_type"]),
        Env(
            "FEEDER_ENABLE_BIASTEE",
            default=False,
            tags=["biast", "is_enabled", "false_is_empty"],
        ),
        Env(
            "FEEDER_ENABLE_UATBIASTEE",
            default=False,
            tags=["uatbiast", "is_enabled", "false_is_empty"],
        ),
        Env("FEEDER_READSB_GAIN", default="autogain", tags=["gain"]),
        Env("FEEDER_AIRSPY_GAIN", default="auto", tags=["gain_airspy"]),
        Env("UAT_SDR_GAIN", default="autogain", tags=["uatgain"]),
        Env("FEEDER_SERIAL_1090", tags=["1090serial"]),
        Env("FEEDER_SERIAL_978", tags=["978serial"]),
        Env("FEEDER_SERIAL_AIS", tags=["aisserial"]),
        Env("FEEDER_UAT_DEVICE_TYPE", default="rtlsdr", tags=["uat_device_type"]),
        Env("FEEDER_UNUSED_SERIAL_0", tags=["other-0"]),
        Env("FEEDER_UNUSED_SERIAL_1", tags=["other-1"]),
        Env("FEEDER_UNUSED_SERIAL_2", tags=["other-2"]),
        Env("FEEDER_UNUSED_SERIAL_3", tags=["other-3"]),
        Env("READSB_NET_BR_OPTIMIZE_FOR_MLAT", tags=["beast-reduce-optimize-for-mlat"]),
        Env("FEEDER_MAX_RANGE", default=[300], tags=["max_range"]),
        Env("FEEDER_USE_GPSD", default=False, tags=["use_gpsd", "is_enabled"]),
        Env("_ADSBIM_FEEDER_HAS_GPSD", default=False, tags=["has_gpsd", "is_enabled"]),
        Env("_ADSBIM_STATE_DOCKER_CONCURRENT", default=True, tags=["docker_concurrent", "is_enabled"]),
        Env("_ADSBIM_STATE_TEMPERATURE_BLOCK", default=False, tags=["temperature_block", "is_enabled"]),
        #
        # Ultrafeeder config, used for all 4 types of Ultrafeeder instances
        Env("FEEDER_ULTRAFEEDER_CONFIG", default=[""], tags=["ultrafeeder_config"]),
        Env("ADSBLOL_UUID", default=[""], tags=["adsblol_uuid"]),
        Env("ULTRAFEEDER_UUID", default=[""], tags=["ultrafeeder_uuid"]),
        Env("MLAT_PRIVACY", default=[False], tags=["mlat_privacy", "is_enabled"]),
        Env("MLAT_ENABLE", default=[True], tags=["mlat_enable", "is_enabled"]),
        Env(
            "FEEDER_TAR1090_USEROUTEAPI",
            default=[True],
            tags=["route_api", "is_enabled", "false_is_zero"],
        ),
        Env(
            "FEEDER_TAR1090_CONFIGJS_APPEND",
            default="",
            tags=["tar1090_configjs_append"],
        ),
        Env(
            "FEEDER_TAR1090_IMAGE_CONFIG_LINK",
            default="http://HOSTNAME:80/",
            tags=["tar1090_image_config_link"],
        ),
        Env("_ASDBIM_CSS_THEME", default="auto", tags=["css_theme"]),
        Env("_ASDBIM_TAR1090_QUERY_PARAMS", default="", tags=["tar1090_query_params"]),
        # 978
        # start the container (integrated / micro) or the replay
        Env("FEEDER_ENABLE_UAT978", default=[False], tags=["uat978", "is_enabled"]),
        Env(
            "FEEDER_UAT_REPLAY978",
            default=[""],
            tags=["replay978"],
        ),
        # hostname ultrafeeder uses to get 978 data
        Env("FEEDER_UAT978_HOST", default=[""], tags=["978host"]),
        Env("FEEDER_RB_UAT978_HOST", default=[""], tags=["rb978host"]),
        # add the URL to the dump978 map
        Env("FEEDER_URL_978", default=[""], tags=["978url"]),
        # URL to get Airspy stats (used in stage2)
        Env("FEEDER_URL_AIRSPY", default=[""], tags=["airspyurl"]),
        # port for Airspy stats (used in micro feeder and handed to stage2 via base_info)
        Env("FEEDER_AIRSPY_PORT", default=8070, tags=["airspyport"]),
        # URL to get remote 1090 stats data (for gain, %-age of strong signals, and signal graph)
        Env("FEEDER_URL_RTLSDR", default=[""], tags=["rtlsdrurl"]),
        # magic setting for piaware to get 978 data
        Env("FEEDER_PIAWARE_UAT978", default=[""], tags=["978piaware"]),
        # Misc
        Env(
            "_ADSBIM_HEYWHATSTHAT_ENABLED",
            default=[False],
            tags=["heywhatsthat", "is_enabled"],
        ),
        Env(
            "FEEDER_HEYWHATSTHAT_ID",
            default=[""],
            tags=["heywhatsthat_id", "key"],
        ),
        # Other aggregators keys
        Env(
            "FEEDER_FR24_SHARING_KEY",
            default=[""],
            tags=["flightradar", "key"],
        ),
        Env(
            "FEEDER_FR24_UAT_SHARING_KEY",
            default=[""],
            tags=["flightradar_uat", "key"],
        ),
        Env(
            "FEEDER_PIAWARE_FEEDER_ID",
            default=[""],
            tags=["flightaware", "key"],
        ),
        Env(
            "FEEDER_RADARBOX_SHARING_KEY",
            default=[""],
            tags=["radarbox", "key"],
        ),
        # radarbox station number used for status link
        Env(
            "FEEDER_RADARBOX_SN",
            default=[""],
            tags=["radarbox", "sn"],
        ),
        # radarbox key that was set when the station number was determined
        # if it doesn't match the currently set share key, determine new station number
        Env(
            "_ADSBIM_STATE_FEEDER_RADARBOX_SN_KEY",
            default=[""],
            tags=["radarbox", "snkey"],
        ),
        Env(
            "FEEDER_RB_THERMAL_HACK",
            is_mandatory=False,
            default="",
            tags=["rbthermalhack"],
        ),
        Env(
            "FEEDER_PLANEFINDER_SHARECODE",
            default=[""],
            tags=["planefinder", "key"],
        ),
        Env(
            "FEEDER_ADSBHUB_STATION_KEY",
            default=[""],
            tags=["adsbhub", "key"],
        ),
        Env(
            "FEEDER_OPENSKY_USERNAME",
            default=[""],
            tags=["opensky", "user"],
        ),
        Env(
            "FEEDER_OPENSKY_SERIAL",
            default=[""],
            tags=["opensky", "key"],
        ),
        Env(
            "FEEDER_RV_FEEDER_KEY",
            default=[""],
            tags=["radarvirtuel", "key"],
        ),
        Env(
            "FEEDER_PLANEWATCH_API_KEY",
            default=[""],
            tags=["planewatch", "key"],
        ),
        Env(
            "FEEDER_1090UK_API_KEY",
            default=[""],
            tags=["1090uk", "key"],
        ),
        Env(
            "FEEDER_SM_USERNAME",
            default=[""],
            tags=["sdrmap", "user"],
        ),
        Env(
            "FEEDER_SM_PASSWORD",
            default=[""],
            tags=["sdrmap", "key"],
        ),
        Env(
            "FEEDER_PORTTRACKER_DATA_SHARING_KEY",
            default=[""],
            tags=["porttracker", "key", "data_sharing_key"],
        ),
        Env(
            "FEEDER_PORTTRACKER_STATION_ID",
            default=[""],
            tags=["porttracker", "station_id"],
        ),
        Env(
            "FEEDER_PORTTRACKER_MQTT_URL",
            default=[""],
            tags=["porttracker", "mqtt_url"],
        ),
        Env(
            "FEEDER_PORTTRACKER_MQTT_CLIENT_ID",
            default=[""],
            tags=["porttracker", "mqtt_client_id"],
        ),
        Env(
            "FEEDER_PORTTRACKER_MQTT_QOS",
            default=[""],
            tags=["porttracker", "mqtt_qos"],
        ),
        Env(
            "FEEDER_PORTTRACKER_MQTT_TOPIC",
            default=[""],
            tags=["porttracker", "mqtt_topic"],
        ),
        Env(
            "FEEDER_PORTTRACKER_MQTT_MSGFORMAT",
            default=[""],
            tags=["porttracker", "mqtt_msgformat"],
        ),
        Env(
            "FEEDER_AISCATCHER_FEEDER_KEY",
            default=[""],
            tags=["aiscatcher", "key", "feeder_key"],
        ),
        Env(
            "FEEDER_AISHUB_UDP_PORT",
            default=[None],
            tags=["aishub", "key", "udp_port"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_URL",
            default=[""],
            tags=["shipfeeder_config_porttracker", "mqtt_url"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_CLIENT_ID",
            default=[""],
            tags=["shipfeeder_config_porttracker", "mqtt_client_id"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_QOS",
            default=[""],
            tags=["shipfeeder_config_porttracker", "mqtt_qos"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_TOPIC",
            default=[""],
            tags=["shipfeeder_config_porttracker", "mqtt_topic"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_MSGFORMAT",
            default=[""],
            tags=["shipfeeder_config_porttracker", "mqtt_msgformat"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_AISCATCHER_FEEDER_KEY",
            default=[None],
            tags=["shipfeeder_config_aiscatcher", "key", "feeder_key"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_AISCATCHER_SHAREDATA",
            default=["false"],
            tags=["shipfeeder_config_aiscatcher", "share_data"],
        ),
        Env(
            "SHIPFEEDER_CONFIG_AISHUB_UDP_PORT",
            default=[None],
            tags=["shipfeeder_config_aishub", "key", "udp_port"],
        ),
        # ADSB.im specific
        Env("_ADSBIM_AGGREGATORS_SELECTION", tags=["aggregator_choice"]),
        Env(
            "_ADSBIM_BASE_VERSION",
            default="",
            tags=["base_version", "norestore"],
        ),
        Env(
            "_ADSBIM_STATE_BOARD_NAME",
            tags=["board_name", "norestore"],
        ),
        Env("AF_IS_MDNS_ENABLED", default=True, tags=["mdns", "is_enabled"]),
        Env("AF_MDNS_DOMAINS", default="", tags=["mdns", "domains"]),
        Env("AF_IS_PROMETHEUS_EXPORTER_ENABLED", default=False, tags=["prometheus_exporter", "is_enabled"]),
        Env("AF_PROMETHEUS_TEXTFILE_DIR", default="/var/lib/prometheus/node-exporter", tags=["prometheus_exporter", "textfile_dir"]),
        # ports used by our proxy system
        Env("AF_WEBPORT", default=80, tags=["webport", "norestore"]),
        Env("AF_DAZZLE_PORT", default=9999, tags=["dazzleport", "norestore"]),
        Env("AF_TAR1090_PORT", default=8080, tags=["tar1090port", "norestore"]),
        Env("AF_TAR1090_PORT_ADJUSTED", default=8080, tags=["tar1090portadjusted"]),
        Env("AF_NANO_TAR1090_PORT_ADJUSTED", default=8080, tags=["nanotar1090portadjusted"]),
        Env("AF_UAT978_PORT", default=9780, tags=["uatport", "norestore"]),
        Env("AF_PIAWAREMAP_PORT", default=8081, tags=["piamapport", "norestore"]),
        Env("AF_PIAWARESTAT_PORT", default=8082, tags=["piastatport", "norestore"]),
        Env("AF_FLIGHTRADAR_PORT", default=8754, tags=["frport"]),
        Env("AF_PLANEFINDER_PORT", default=30053, tags=["pfport"]),
        Env("AF_AIS_CATCHER_PORT", default=41580, tags=["aiscatcherport"]),
        Env(
            "_ADSBIM_STATE_IMAGE_NAME",
            default="Porttracker feeder",
            tags=["image_name", "norestore"],
        ),
        # legacy secure image state, now handled via separate file
        # keep it around to handle updates from before the changeover
        # and easy checks in webinterface
        Env(
            "AF_IS_SECURE_IMAGE",
            default=False,
            tags=["secure_image", "is_enabled", "norestore"],
        ),
        Env(
            "AF_IS_FLIGHTRADAR24_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "flightradar"],
        ),
        Env(
            "AF_IS_PLANEWATCH_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "planewatch"],
        ),
        Env(
            "AF_IS_FLIGHTAWARE_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "flightaware"],
        ),
        Env(
            "AF_IS_RADARBOX_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "radarbox"],
        ),
        Env(
            "AF_IS_PLANEFINDER_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "planefinder"],
        ),
        Env(
            "AF_IS_ADSBHUB_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "adsbhub"],
        ),
        Env(
            "AF_IS_OPENSKY_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "opensky"],
        ),
        Env(
            "AF_IS_RADARVIRTUEL_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "radarvirtuel"],
        ),
        Env(
            "AF_IS_1090UK_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "1090uk"],
        ),
        Env(
            "AF_IS_SDRMAP_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "sdrmap"],
        ),
        Env(
            "AF_IS_PORTTRACKER_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "porttracker"],
        ),
        Env(
            "AF_IS_AISCATCHER_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "aiscatcher"],
        ),
        Env(
            "AF_IS_AISHUB_ENABLED",
            default=[False],
            tags=["other_aggregator", "is_enabled", "aishub"],
        ),
        Env(
            "AF_IS_AIRSPY_ENABLED",
            tags=["airspy", "is_enabled"],
        ),
        Env(
            "AF_IS_SDRPLAY_ENABLED",
            tags=["sdrplay", "is_enabled"],
        ),
        Env(
            "AF_IS_SDRPLAY_LICENSE_ACCEPTED",
            tags=["sdrplay_license_accepted", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_JOURNAL_CONFIGURED",
            default=False,
            tags=["journal_configured", "is_enabled", "norestore"],
        ),
        Env(
            "_ADSBIM_STATE_IS_SSH_CONFIGURED",
            tags=["ssh_configured", "is_enabled", "norestore"],
        ),
        Env(
            "AF_IS_BASE_CONFIG_FINISHED",
            default=False,
            tags=["base_config", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_AGGREGATORS_CHOSEN",
            default=False,
            tags=["aggregators_chosen"],
        ),
        Env(
            "AF_IS_NIGHTLY_BASE_UPDATE_ENABLED",
            tags=["nightly_base_update", "is_enabled"],
        ),
        Env(
            "AF_IS_NIGHTLY_FEEDER_UPDATE_ENABLED",
            tags=["nightly_feeder_update", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_ZEROTIER_KEY",
            tags=["zerotierid", "key"],
        ),
        Env(
            "_ADSBIM_STATE_TAILSCALE_LOGIN_LINK",
            tags=["tailscale_ll"],
            default="",
        ),
        Env(
            "_ADSBIM_STATE_TAILSCALE_NAME",
            tags=["tailscale_name"],
            default="",
        ),
        Env(
            "_ADSBIM_STATE_TAILSCALE_EXTRA_ARGS",
            tags=["tailscale_extras"],
        ),
        Env(
            "_ADSBIM_STATE_EXTRA_ENV",
            tags=["ultrafeeder_extra_env"],
        ),
        # Ultrafeeder config
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBLOL_ENABLED",
            default=[False],
            tags=["adsblol", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_FLYITALYADSB_ENABLED",
            default=[False],
            tags=["flyitaly", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBX_ENABLED",
            default=[False],
            tags=["adsbx", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_TAT_ENABLED",
            default=[False],
            tags=["tat", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_PLANESPOTTERS_ENABLED",
            default=[False],
            tags=["planespotters", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_ADSBFI_ENABLED",
            default=[False],
            tags=["adsbfi", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_AVDELPHI_ENABLED",
            default=[False],
            tags=["avdelphi", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_HPRADAR_ENABLED",
            default=[False],
            tags=["hpradar", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_IS_ULTRAFEEDER_ALIVE_ENABLED",
            default=[False],
            tags=["alive", "ultrafeeder", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_ULTRAFEEDER_EXTRA_ARGS",
            tags=["ultrafeeder_extra_args"],
        ),
        Env(
            "_ADSBIM_STATE_ULTRAFEEDER_EXTRA_ARGS_MICROSITES",
            tags=["ultrafeeder_extra_args_microsites"],
        ),
        Env(
            "FEEDER_TAR1090_ENABLE_AC_DB",
            default=True,
            tags=["tar1090_ac_db", "is_enabled"],
        ),
        Env(
            "FEEDER_MLATHUB_DISABLE",
            default=False,
            tags=["mlathub_disable", "is_enabled"],
        ),
        Env(
            "FEEDER_MLATHUB_ENABLE",
            default=True,
            tags=["mlathub_enable", "is_enabled"],
        ),
        Env(
            "_ADSBIM_STATE_REMOTE_SDR",
            tags=["remote_sdr"],
        ),
        Env(
            "_ADSBIM_STATE_LAST_DNS_CHECK",
            tags=["dns_state", "norestore"],
        ),
        Env(
            "_ADSBIM_STATE_UNDER_VOLTAGE",
            tags=["under_voltage", "norestore"],
        ),
        Env(
            "_ADSBIM_STATE_LOW_DISK",
            tags=["low_disk", "norestore"],
        ),
        Env(
            "AF_IS_STAGE2",
            default=False,
            tags=["stage2", "is_enabled"],
        ),
        Env("AF_STAGE2_NANOFEEDER", default=False, tags=["stage2_nano", "is_enabled"]),
        Env("AF_NANO_BEAST_PORT", default="30005", tags=["nano_beast_port"]),
        Env("AF_NANO_BEASTREDUCE_PORT", default="30006", tags=["nano_beastreduce_port"]),
        Env(
            "AF_NUM_MICRO_SITES",
            default=0,
            tags=["num_micro_sites"],
        ),
        Env("AF_MICRO_PORT", default=[""], tags=["mf_port"]),
        Env("AF_MICRO_BROFM", default=[False], tags=["mf_brofm", "is_enabled"]),
        Env(
            "AF_MICRO_BROFM_CAPABLE",
            default=[False],
            tags=["mf_brofm_capable", "is_enabled"],
        ),
        Env("AF_FEEDER_VERSION", default=[""], tags=["mf_version"]),
        Env("AF_FEEDER_INITIAL_VERSION", default="", tags=["initial_version"]),
    }

    # Container images
    # -- these names are magic and are used in yaml files and the structure
    #    of these names is used in scripting around that
    # the version of the adsb-setup app and the containers are linked and
    # there are subtle dependencies between them - so let's not include these
    # in backup/restore

    tag_for_name = {
        "ULTRAFEEDER_CONTAINER": "ultrafeeder",
        "FR24_CONTAINER": "flightradar",
        "FA_CONTAINER": "flightaware",
        "RB_CONTAINER": "radarbox",
        "PF_CONTAINER": "planefinder",
        "AH_CONTAINER": "adsbhub",
        "OS_CONTAINER": "opensky",
        "RV_CONTAINER": "radarvirtuel",
        "PW_CONTAINER": "planewatch",
        "TNUK_CONTAINER": "1090uk",
        "SDRMAP_CONTAINER": "sdrmap",
        "SHIPFEEDER_CONTAINER": "shipfeeder",
    }
    with open(APP_DIR / "docker.image.versions", "r") as file:
        for line in file:
            if line.startswith("#"):
                continue
            items = line.replace("\n", "").split("=")
            if len(items) != 2:
                print_err(f"docker.image.versions check line: {line}")
                continue
            key = items[0]
            value = items[1]
            # .get(key, key) defaults to key for key DOZZLE_CONTAINER / ALPINE_CONTAINER, that's fine as we never need
            # to check if they are enabled as they are always enabled
            # this also defaults to key for the airspy and sdrplay container
            tag = tag_for_name.get(key, key)
            entry = Env(key, tags=[tag, "container", "norestore"])
            entry.value = value  # always use value from docker.image.versions as definitive source
            _env.add(entry)  # add to _env set

    def __init__(self):
        self.previous_version = self._read_previous_version()
        self.env_by_tags("image_name").value = self._read_friendly_name()

    @property
    def envs_for_envfile(self):

        # read old values from env file so we can debug print only those that have changed
        old_values = read_values_from_env_file()

        def adjust_bool_impl(e, value):
            if "false_is_zero" in e.tags:
                return "1" if is_true(value) else "0"
            if "false_is_empty" in e.tags:
                return "1" if is_true(value) else ""
            return is_true(value)

        def adjust_bool(e, value):
            v = adjust_bool_impl(e, value)
            print_err(f"adjust_bool({e}, {e.tags}) = {v}", level=8)
            return v

        def adjust_heywhatsthat(value):
            enabled = self.env_by_tags(["heywhatsthat", "is_enabled"])._value
            new_value = []
            for i in range(len(value)):
                new_value.append(value[i] if enabled[i] else "")
            return new_value

        def value_for_env(e, value):
            if type(value) == bool or "is_enabled" in e.tags:
                value = adjust_bool(e, value)

            # the env vars have no concept of None, convert to empty string
            if value == None or value == "None":
                value = ""

            if type(value) == str:
                # remove spaces
                value = value.strip()

                # docker compose does weird stuff if there are $ in the env vars
                # escape them using $$
                value = value.replace("$", "$$")

            return value

        ret = {}
        for e in self._env:

            def printChanged(descriptor, envKey, newValue, oldValue):
                # omit state vars as they are never in the env file so we don't know if they changed
                oldValue = str(oldValue)
                newValue = str(newValue)
                if oldValue != newValue and not envKey.startswith("_ADSBIM_STATE"):
                    emptyStringPrint = "''"
                    print_err(
                        f"{descriptor}: {envKey} = {emptyStringPrint if newValue == '' else newValue}",
                        level=2,
                    )

            if type(e._value) == list:
                if e._name == "FEEDER_HEYWHATSTHAT_ID":
                    actual_value = adjust_heywhatsthat(e._value)
                else:
                    actual_value = e._value

                for i in range(len(actual_value)):
                    suffix = "" if i == 0 else f"_{i}"
                    value = actual_value[i]
                    envKey = e._name + suffix

                    ret[envKey] = value_for_env(e, value)

                    printChanged("ENV_FILE LIST", envKey, ret[envKey], old_values.get(envKey))

            else:
                envKey = e._name

                ret[envKey] = value_for_env(e, e._value)

                printChanged("ENV_FILE OTHR", envKey, ret[envKey], old_values.get(envKey))

        # add convenience values
        # fmt: off
        ret["AF_FALSE_ON_STAGE2"] = "false" if self.is_enabled(["stage2"]) else "true"
        if self.is_enabled(["stage2"]):
            for i in range(1, self.env_by_tags("num_micro_sites").value + 1):
                ret[f"AF_TAR1090_PORT_{i}"] = int(ret[f"AF_TAR1090_PORT"]) + i * 1000
                ret[f"AF_PIAWAREMAP_PORT_{i}"] = int(ret[f"AF_PIAWAREMAP_PORT"]) + i * 1000
                ret[f"AF_PIAWARESTAT_PORT_{i}"] = int(ret[f"AF_PIAWARESTAT_PORT"]) + i * 1000
                ret[f"AF_FLIGHTRADAR_PORT_{i}"] = int(ret[f"AF_FLIGHTRADAR_PORT"]) + i * 1000
                ret[f"AF_PLANEFINDER_PORT_{i}"] = int(ret[f"AF_PLANEFINDER_PORT"]) + i * 1000
                site_name = self.env_by_tags("site_name").list_get(i)
                ret[f"GRAPHS1090_WWW_TITLE_{i}"] = f"{site_name} graphs1090 stats"
                ret[f"GRAPHS1090_WWW_HEADER_{i}"] = f"Performance Graphs: {site_name}"
        return ret
        # fmt: on

    @property
    def env_values(self):
        return {e.name: e._value for e in self._env}

    @property
    def stage2_envs(self):
        return [e for e in self._env if e.is_list]

    def read_version(self):
        """Read the version string from the version file."""
        return self._read_file(VERSION_FILE)

    def _read_previous_version(self):
        return self._read_file(PREVIOUS_VERSION_FILE)

    def _read_friendly_name(self):
        return self._read_file(FRIENDLY_NAME_FILE)

    def _read_file(self, file: pathlib.Path) -> str:
        try:
            with file.open() as f:
                return f.read().strip()
        except FileNotFoundError:
            return "unknown"

    # helper function to find env by name
    def env(self, name: str):
        for e in self._env:
            if e.name == name:
                return e
        return None

    # helper function to find env by tags
    # Return only if there is one env with all the tags,
    # Raise error if there are more than one match
    def env_by_tags(self, _tags):
        if type(_tags) == str:
            tags = [_tags]
        elif type(_tags) == list:
            tags = _tags
        else:
            raise Exception(f"env_by_tags called with invalid argument {_tags} of type {type(_tags)}")
        if not tags:
            return None

        # make the list a tuple so it's hashable
        tags = tuple(tags)
        cached = self._env_by_tags_dict.get(tags)
        if cached:
            return cached

        matches = []
        for e in self._env:
            if not e.tags:
                print_err(f"{e} has no tags")
            if all(t in e.tags for t in tags):
                matches.append(e)
        if len(matches) == 0:
            return None
        if len(matches) > 1:
            print_err(f"More than one match for tags {tags}")
            for e in matches:
                print_err(f"  {e}")

        self._env_by_tags_dict[tags] = matches[0]
        return matches[0]

    def _get_enabled_env_by_tags(self, tags):
        # we append is_enabled to tags
        tags.append("is_enabled")
        # stack_info(f"taglist {tags} gets us env {self.env_by_tags(tags)}")
        return self.env_by_tags(tags)

    # helper function to see if something is enabled
    def is_enabled(self, tags):
        if type(tags) != list:
            tags = [tags]
        e = self._get_enabled_env_by_tags(tags)
        if e is None:
            return False
        if type(e._value) == list:
            ret = e and is_true(e.list_get(0))
            print_err(f"is_enabled called on list: {e}[0] = {ret}")
            return ret
        return e and is_true(e._value)

    # helper function to see if list element is enabled
    def list_is_enabled(self, tags, idx):
        if type(tags) != list:
            tags = [tags]
        e = self._get_enabled_env_by_tags(tags)
        ret = is_true(e.list_get(idx)) if e else False
        print_err(f"list_is_enabled: {e}[{idx}] = {ret}", level=8)
        return ret
