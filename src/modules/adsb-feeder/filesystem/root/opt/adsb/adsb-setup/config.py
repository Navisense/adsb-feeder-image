#!/usr/bin/env python

import abc
import argparse
import collections.abc as cl_abc
import datetime
import functools as ft
import itertools as it
import json
import logging
import numbers
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import threading
import typing as t
from typing import Any, Literal, Optional
import uuid

import util
import system

if t.TYPE_CHECKING:
    import aggregators

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
DOCKER_COMPOSE_UP_FAILED_FILE = pathlib.Path(
    "/run/porttracker-feeder-docker-compose-up-failed")

logger = logging.getLogger(__name__)


def _mandatory_config_is_complete(conf: "Config") -> bool:
    """Check whether all mandatory settings are set."""
    mandatory_setting_key_paths = {"lon", "lat", "alt", "site_name"}
    return all(
        conf.get(key_path) is not None
        for key_path in mandatory_setting_key_paths)


def _read_file(conf: "Config", *, file: pathlib.Path) -> str:
    try:
        with file.open() as f:
            return f.read().strip()
    except FileNotFoundError:
        return "unknown"


def _get_boardname(conf: "Config") -> str:
    board = ""
    if pathlib.Path("/sys/firmware/devicetree/base/model").exists():
        # that's some kind of SBC most likely
        with open("/sys/firmware/devicetree/base/model", "r") as model:
            board = util.cleanup_str(model.read().strip())
    else:
        # are we virtualized?
        try:
            output = subprocess.run(
                "systemd-detect-virt",
                timeout=2.0,
                shell=True,
                capture_output=True,
            )
        except subprocess.SubprocessError:
            pass  # whatever
        else:
            virt = output.stdout.decode().strip()
            if virt and virt != "none":
                board = (
                    f"Virtualized {platform.machine()} environment under "
                    f"{virt}")
            else:
                prod = ""
                manufacturer = ""
                try:
                    prod = subprocess.run(
                        "dmidecode -s system-product-name",
                        shell=True,
                        capture_output=True,
                        text=True,
                    )
                    manufacturer = subprocess.run(
                        "dmidecode -s system-manufacturer",
                        shell=True,
                        capture_output=True,
                        text=True,
                    )
                except:
                    pass
                if prod or manufacturer:
                    board = (
                        f"Native on {manufacturer.stdout.strip()} "
                        f"{prod.stdout.strip()} {platform.machine()} system")
                else:
                    board = f"Native on {platform.machine()} system"
    if board == "Firefly roc-rk3328-cc":
        return f"Libre Computer Renegade ({board})"
    elif board == "Libre Computer AML-S905X-CC":
        return "Libre Computer Le Potato (AML-S905X-CC)"
    return board or f"Unknown {platform.machine()} system"


def _has_gpsd(conf: "Config") -> bool:
    """Check whether gpsd is running."""
    # Find host address on the docker network.
    proc = util.shell_with_combined_output(
        "docker exec adsb-setup-proxy ip route | mawk '/default/{ print($3) }'",
        timeout=5)
    try:
        proc.check_returncode()
        assert len(proc.stdout.strip()) > 4
        gateway_ips = [proc.stdout.strip()]
    except:
        logger.exception(
            f"Finding the host address failed with output: {proc.stdout}")
        gateway_ips = ["172.17.0.1", "172.18.0.1"]

    logger.info(f"gpsd check checking ips: {gateway_ips}.")
    for ip in gateway_ips:
        try:
            with socket.socket() as s:
                s.settimeout(2)
                s.connect((ip, 2947))
                logger.info(f"Found gpsd on {ip}:2947.")
                return True
        except socket.error:
            logger.info(f"No gpsd on {ip}:2947 detected.")
    return False


def _get_enabled_ultrafeeder_aggregators(
        conf: "Config"
) -> cl_abc.Generator["aggregators.UltrafeederAggregator"]:
    """
    Generate all enabled Ultrafeeder aggregators.

    Checks the aggregator_choice setting, and actively enables aggregators if
    set to "all" or "privacy". Yields all enabled aggregators.
    """
    import aggregators
    choice = conf.get("aggregator_choice")
    for agg_key, aggregator in aggregators.all_aggregators().items():
        try:
            netconfig = aggregator.netconfig
        except AttributeError:
            # Not an Ultrafeedeer aggregator with a netconfig, ignore.
            continue
        assert isinstance(aggregator, aggregators.UltrafeederAggregator)
        if aggregator.enabled():
            yield aggregator
            continue
        should_be_enabled = (
            choice == "all" or (choice == "privacy" and netconfig.has_policy))
        if should_be_enabled:
            logger.info(
                f"Enabling {aggregator} because of aggregator_choice {choice}."
            )
            conf.set(f"aggregators.{agg_key}.is_enabled", True)
            yield aggregator


def _generate_ultrafeeder_config_string(conf: "Config") -> str:
    """
    Generate the string used to configure Ultrafeeder.

    Concatenates all necessary settings into a string that can be fed to
    Ultrafeeder. Generates UUIDs if necessary.
    """
    args = set()
    for aggregator in _get_enabled_ultrafeeder_aggregators(conf):
        if aggregator.agg_key == "adsblol":
            uuid_setting_path = "adsblol_uuid"
        else:
            uuid_setting_path = "ultrafeeder_uuid"
        agg_uuid = conf.get(uuid_setting_path)
        if not agg_uuid:
            agg_uuid = str(uuid.uuid4())
            conf.set(uuid_setting_path, agg_uuid)
        args.add(
            aggregator.netconfig.generate(
                mlat_privacy=conf.get("mlat_privacy"), uuid=agg_uuid,
                mlat_enable=conf.get("mlat_enable")))

    if conf.get("uat978_config.is_enabled"):
        args.add("adsb,dump978,30978,uat_in")

    # Make sure we only ever use 1 SDR / network input for Ultrafeeder.
    if conf.get("readsb_device_type"):
        pass
    elif conf.get("airspy"):
        args.add("adsb,airspy_adsb,30005,beast_in")
    elif conf.get("sdrplay"):
        args.add("adsb,sdrplay-beast1090,30005,beast_in")
    elif (remote_sdr := conf.get("remote_sdr")):
        if remote_sdr.find(",") == -1:
            remote_sdr += ",30005"
        args.add(f"adsb,{remote_sdr.replace(' ', '')},beast_in")

    if conf.get("use_gpsd"):
        args.add("gpsd,host.docker.internal,2947")

    # Finally, add user provided things.
    if (ultrafeeder_extra_args := conf.get("ultrafeeder_extra_args")):
        args.add(ultrafeeder_extra_args)

    # Sort the args to make the string deterministic (avoid unnecessary
    # container recreation by docker compose).
    args.discard("")
    args = sorted(args)
    logger.debug(f"Generated Ultrafeeder args {args}")
    return ";".join(args)


class Setting(abc.ABC):
    """
    Abstract setting.

    A setting is a container for configuration data.
    """
    def __init__(self, config: "Config"):
        self._config = config

    @property
    def persistent(self) -> bool:
        """Whether this setting should be written to the config file."""
        return True

    @property
    @abc.abstractmethod
    def env_variables(self) -> dict[str, str]:
        """Dictionary of environment variables of this setting."""
        raise NotImplementedError

    @abc.abstractmethod
    def get(
            self, key_path: str, *, default: Any = None,
            use_setting_level_default: bool = True) -> Any:
        raise NotImplementedError

    @abc.abstractmethod
    def set(self, key_path: str, value: Any) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def init_with_default(self) -> None:
        """
        Initialize the value with defaults, if appropriate.

        If there is some sort of default value, and no actual value has been
        set, permanently use the default value.
        """
        raise NotImplementedError


class ScalarSetting(Setting):
    """
    A setting with a direct value.

    Scalar settings contain values directly, e.g. strings or numbers.
    """
    def __init__(
            self, config: "Config", value: Any, *,
            default: Optional[Any] = None,
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
            self, key_path: Literal[""], *, default: Any = None,
            use_setting_level_default: bool = True) -> Any:
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

    def set(self, key_path: str, value: Any) -> None:
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
        self._config.write_to_file()

    def init_with_default(self) -> None:
        if self._value:
            logger.warning(
                "Setting is being initialized with default, but we already "
                "have a value.")
        self._value = self._default


class TypeConstrainedScalarSetting(ScalarSetting):
    """A scalar setting enforcing type constraints."""
    def __init__(
            self, required_type: type, config: "Config", value: Any, *args,
            default: Optional[Any] = None, **kwargs):
        self._required_type = required_type
        self._check_correct_type(value, "value")
        self._check_correct_type(default, "default value")
        super().__init__(config, value, *args, default=default, **kwargs)

    def _check_correct_type(self, value, value_name):
        if not isinstance(value, (self._required_type, type(None))):
            raise ValueError(
                f"{value_name} must be a {self._required_type}, but is "
                f"{type(value)}")

    def set(self, key_path: str, value: Optional[Any]) -> None:
        self._check_correct_type(value, "value")
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


class ListSetting(ScalarSetting):
    """
    A scalar setting that is a list of values of the same type.

    Lists can not be represented as environment variables.
    """
    def __init__(
            self, config: "Config", value: list[Any], *,
            required_value_type: type, default: Optional[list[Any]] = None,
            norestore: bool = False):
        self._required_value_type = required_value_type
        self._check_correct_type(value, "value")
        self._check_correct_type(default, "default value")
        super().__init__(
            config, value, default=default, env_variable_name=None,
            norestore=norestore)

    def _check_correct_type(self, value, value_name):
        if value is None:
            return
        if not isinstance(value, list):
            raise ValueError(
                f"{value_name} must be a list, but is {type(value)}")
        if any(not isinstance(e, self._required_value_type) for e in value):
            raise ValueError(
                f"elements of {value_name} must be of type "
                f"{self._required_value_type}, but at least one is "
                f"{type(value)}")

    def set(self, key_path: str, value: Optional[list[Any]]) -> None:
        self._check_correct_type(value, "value")
        super().set(key_path, value)


class CompoundSetting(Setting):
    """
    A setting containing nested settings.

    Compound settings are essentially trees of settings nested according to a
    fixed schema. Child settings can be compound settings again for arbitrary
    nesting. The leaves of the tree are scalar settings, which can be accessed
    via period-delimited paths.
    """
    def __init__(
            self, config: "Config", settings_dict: Optional[dict[str, Any]], *,
            schema: dict[str, type[Setting]]):
        super().__init__(config)
        self._settings = {}
        if settings_dict is None:
            settings_dict_was_none = True
            settings_dict = {}
        else:
            settings_dict_was_none = False
        for key, setting_class in schema.items():
            if "." in key:
                raise ValueError("Keys must not contain dots.")
            self._settings[key] = setting_class(
                self._config, settings_dict.get(key))
        if (settings_dict_was_none
                and any(s.persistent for s in self._settings.values())):
            logger.warning(
                "No settings dictionary for compound settings with schema "
                f"{schema}, starting with an empty one.")

    def __iter__(self) -> cl_abc.Iterator[tuple[str, Setting]]:
        """
        Iterate over keys and settings.

        Yields tuples of (key, setting), where key is a single key (not a path,
        i.e. doesn't contain "."), and setting is the corresponding setting
        (may be a compound or scalar setting).
        """
        yield from self._settings.items()

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
            self, key_path: str, *, default: Any = None,
            use_setting_level_default: bool = True) -> Any:
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

    def get_setting(self, key_path: str) -> Setting:
        """
        Get the setting at the given path.

        In contrast to get(), this returns a Setting object rather than a
        scalar setting's value. This can also return compound settings.
        """
        key, key_path_tail = self._extract_key_head_and_tail(key_path)
        setting = self._settings[key]
        if key_path_tail:
            return setting.get_setting(key_path_tail)
        return setting

    def set(self, key_path: str, value: Any) -> None:
        """Set the value at the given path."""
        key, key_path_tail = self._extract_key_head_and_tail(key_path)
        self._settings[key].set(key_path_tail, value)

    def init_with_default(self) -> None:
        for _, setting in self:
            setting.init_with_default()


class TransientSetting(ScalarSetting):
    """A setting that doesn't get written to the config file."""
    def __init__(self, config: "Config", value: Any, *args, **kwargs):
        super().__init__(config, value, *args, **kwargs, norestore=True)

    @property
    def persistent(self) -> bool:
        return False

    def init_with_default(self) -> None:
        pass


class ConstantSetting(TransientSetting):
    """
    A setting that always has a fixed value.

    Constants can be modified at runtime, but those changes are not persisted
    to the config file (i.e. the constant value will be reset on the next
    load).
    """
    def __init__(
            self, config: "Config", unused_value: Any, *, constant_value: Any,
            env_variable_name: Optional[str] = None):
        # unused_value is what CompoungSetting will automatically give us,
        # extracted from the config file. We want to use the constant value
        # instead.
        super().__init__(
            config, constant_value, env_variable_name=env_variable_name)


class GeneratedSetting(TransientSetting):
    """
    A special scalar setting which generates its value based on other settings.

    Instead of a value, this setting is constructed with a value generator
    function, which takes the config as argument and produces the value. This
    way, settings can be defined that are dependent on multiple other settings.

    Generated settings cannot be set.

    The default value semantics are unchanged.
    """
    def __init__(
            self, config: "Config", _: Any, *,
            value_generator: cl_abc.Callable[["Config"], Any],
            default: Optional[Any] = None,
            env_variable_name: Optional[str] = None):
        """
        :param value_generator: A function that takes the config as single
            parameter and returns the value of the setting.
        """
        super().__init__(
            config, None, default=default, env_variable_name=env_variable_name)
        self._value_generator = value_generator

    def get(
            self, key_path: Literal[""], *, default: Any = None,
            use_setting_level_default: bool = True) -> Any:
        if key_path != "":
            raise ValueError("Scalar settings have no subkeys.")
        value = self._value_generator(self._config)
        return self._coalesce_value(value, default, use_setting_level_default)

    def set(self, key_path: str, value: Any) -> None:
        raise ValueError("Generated settings can't be set.")


class CachedGeneratedSetting(GeneratedSetting):
    """A generated setting that only calculates its value once."""
    def __init__(
            self, config: "Config", _: Any, *,
            value_generator: cl_abc.Callable[["Config"], Any],
            default: Optional[Any] = None,
            env_variable_name: Optional[str] = None):
        super().__init__(
            config, None, value_generator=value_generator, default=default,
            env_variable_name=env_variable_name)
        self._has_cache = False
        self._cached_value = None

    def get(
            self, key_path: Literal[""], *, default: Any = None,
            use_setting_level_default: bool = True) -> Any:
        if key_path != "":
            raise ValueError("Scalar settings have no subkeys.")
        if not self._has_cache:
            self._cached_value = super().get(
                key_path, default=default,
                use_setting_level_default=use_setting_level_default)
            self._has_cache = True
        return self._cached_value


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
            self, config: "Config", _: Any, *, switch_path: str,
            true_value: Any = None, true_value_path: str = None,
            false_value: Any = None, false_value_path: str = None,
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
            config, None, value_generator=value_generator,
            env_variable_name=env_variable_name)


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
    CONFIG_VERSION = 7
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
                "unused": ft.partial(
                    ListSetting, required_value_type=str, default=[]),}),
        "uat_device_type": ft.partial(
            StringSetting, default="rtlsdr",
            env_variable_name="FEEDER_UAT_DEVICE_TYPE"),
        "max_range": ft.partial(
            RealNumberSetting, default=300,
            env_variable_name="FEEDER_MAX_RANGE"),
        "use_gpsd": ft.partial(BoolSetting, default=False),
        "has_gpsd": ft.partial(
            CachedGeneratedSetting, value_generator=_has_gpsd),
        "docker_concurrent": ft.partial(BoolSetting, default=True),
        "temperature_block": ft.partial(BoolSetting, default=False),
        # Ultrafeeder config, used for all 4 types of Ultrafeeder instances
        "ultrafeeder_config": ft.partial(
            GeneratedSetting,
            value_generator=_generate_ultrafeeder_config_string,
            env_variable_name="FEEDER_ULTRAFEEDER_CONFIG"),
        "adsblol_uuid": StringSetting,
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
        "uat978_config": ft.partial(
            CompoundSetting, schema={
                "is_enabled": ft.partial(
                    SwitchedGeneratedSetting, switch_path="serial_devices.978",
                    true_value=True, false_value=False,
                    env_variable_name="FEEDER_ENABLE_UAT978"),
                "host": ft.partial(
                    SwitchedGeneratedSetting, switch_path="serial_devices.978",
                    true_value="dump978", false_value="",
                    env_variable_name="FEEDER_UAT978_HOST"),
                "url": ft.partial(
                    SwitchedGeneratedSetting, switch_path="serial_devices.978",
                    true_value="http://dump978/skyaware978", false_value="",
                    env_variable_name="FEEDER_URL_978"),
                "piaware": ft.partial(
                    SwitchedGeneratedSetting, switch_path="serial_devices.978",
                    true_value="relay", false_value="",
                    env_variable_name="FEEDER_PIAWARE_UAT978"),}),
        # URL to get Airspy stats (used in stage2)
        "airspyurl": ft.partial(
            StringSetting, env_variable_name="FEEDER_URL_AIRSPY"),
        # port for Airspy stats (used in micro feeder and handed to stage2 via base_info)
        "airspyport": ft.partial(
            IntSetting, default=8070, env_variable_name="FEEDER_AIRSPY_PORT"),
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
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_FR24_SHARING_KEY"),
                        "uat_key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_FR24_UAT_SHARING_KEY"),
                    }),
                "flightaware": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PIAWARE_FEEDER_ID"),}),
                "radarbox": ft.partial(
                    CompoundSetting,
                    schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
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
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PLANEFINDER_SHARECODE"),
                    }),
                "adsbhub": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_ADSBHUB_STATION_KEY"),}),
                "opensky": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_OPENSKY_SERIAL"),
                        "user": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_OPENSKY_USERNAME"),}),
                "radarvirtuel": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_RV_FEEDER_KEY"),}),
                "planewatch": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_PLANEWATCH_API_KEY"),}),
                "1090uk": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_1090UK_API_KEY"),}),
                "sdrmap": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_SM_PASSWORD"),
                        "user": ft.partial(
                            StringSetting,
                            env_variable_name="FEEDER_SM_USERNAME"),}),
                "porttracker": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(BoolSetting, default=False),
                        "key": StringSetting,
                        "station_id": IntSetting,
                        "mqtt_url": StringSetting,
                        "mqtt_client_id": StringSetting,
                        "mqtt_qos": IntSetting,
                        "mqtt_topic": StringSetting,
                        "mqtt_msgformat": StringSetting,
                        "shipfeeder_config_mqtt_url": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.porttracker.is_enabled",
                            true_value_path="aggregators.porttracker.mqtt_url",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_URL"),
                        "shipfeeder_config_mqtt_client_id": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.porttracker.is_enabled",
                            true_value_path=
                            "aggregators.porttracker.mqtt_client_id",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_CLIENT_ID"),
                        "shipfeeder_config_mqtt_qos": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.porttracker.is_enabled",
                            true_value_path="aggregators.porttracker.mqtt_qos",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_QOS"),
                        "shipfeeder_config_mqtt_topic": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.porttracker.is_enabled",
                            true_value_path=
                            "aggregators.porttracker.mqtt_topic",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_TOPIC"),
                        "shipfeeder_config_mqtt_msgformat": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.porttracker.is_enabled",
                            true_value_path=
                            "aggregators.porttracker.mqtt_msgformat",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_PORTTRACKER_MQTT_MSGFORMAT"),
                        "prometheus": ft.partial(
                            CompoundSetting, schema={
                                "is_enabled": ft.partial(
                                    BoolSetting, default=False),
                                "textfile_dir": ft.partial(
                                    ConstantSetting, constant_value=
                                    "/var/lib/prometheus/node-exporter",
                                    env_variable_name=
                                    "AF_PROMETHEUS_TEXTFILE_DIR"),}),}),
                "aiscatcher": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_string_false="false", env_string_true="true",
                            env_variable_name="AF_IS_AISCATCHER_ENABLED"),
                        "key": StringSetting,
                        "shipfeeder_config_feeder_key": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.aiscatcher.is_enabled",
                            true_value_path="aggregators.aiscatcher.key",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_AISCATCHER_FEEDER_KEY"),}),
                "aishub": ft.partial(
                    CompoundSetting, schema={
                        "is_enabled": ft.partial(
                            BoolSetting, default=False,
                            env_variable_name="AF_IS_AISHUB_ENABLED"),
                        "key": IntSetting,
                        "shipfeeder_config_udp_port": ft.partial(
                            SwitchedGeneratedSetting,
                            switch_path="aggregators.aishub.is_enabled",
                            true_value_path="aggregators.aishub.key",
                            false_value="", env_variable_name=
                            "SHIPFEEDER_CONFIG_AISHUB_UDP_PORT"),})}),
        "rbthermalhack": ft.partial(
            StringSetting, env_variable_name="FEEDER_RB_THERMAL_HACK"),
        # ADSB.im specific
        "aggregator_choice": StringSetting,
        "base_version": ft.partial(
            CachedGeneratedSetting,
            value_generator=ft.partial(_read_file, file=VERSION_FILE)),
        "previous_version": ft.partial(
            CachedGeneratedSetting,
            value_generator=ft.partial(_read_file,
                                       file=PREVIOUS_VERSION_FILE)),
        "board_name": ft.partial(
            CachedGeneratedSetting, value_generator=_get_boardname),
        "mdns": ft.partial(
            CompoundSetting, schema={
                "is_enabled": ft.partial(BoolSetting, default=True),
                "domains": ft.partial(
                    ListSetting, required_value_type=str, default=[]),}),
        "ports": ft.partial(
            CompoundSetting, schema={
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
        "image_name": ft.partial(
            CachedGeneratedSetting,
            value_generator=ft.partial(_read_file, file=FRIENDLY_NAME_FILE)),
        "secure_image": ft.partial(BoolSetting, default=False, norestore=True),
        "airspy": BoolSetting,
        "sdrplay": BoolSetting,
        "sdrplay_license_accepted": BoolSetting,
        "journal_configured": ft.partial(BoolSetting, default=False),
        "ssh_configured": BoolSetting,
        "mandatory_config_is_complete": ft.partial(
            GeneratedSetting, value_generator=_mandatory_config_is_complete),
        "aggregators_chosen": ft.partial(BoolSetting, default=False),
        "nightly_base_update": ft.partial(BoolSetting, default=False),
        "nightly_feeder_update": ft.partial(BoolSetting, default=False),
        "zerotierid": StringSetting,
        "tailscale": ft.partial(
            CompoundSetting, schema={
                "is_enabled": ft.partial(BoolSetting, default=False),
                "login_link": StringSetting,
                "extras": StringSetting,}),
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
        "images": ft.partial(
            CompoundSetting, schema={
                "dozzle": ft.partial(
                    ConstantSetting,
                    constant_value="ghcr.io/amir20/dozzle:v8.11.7",
                    env_variable_name="DOCKER_IMAGE_DOZZLE"),
                "alpine": ft.partial(
                    ConstantSetting, constant_value="alpine:3.21.3",
                    env_variable_name="DOCKER_IMAGE_ALPINE"),
                "ultrafeeder": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder:latest-build-688",
                    env_variable_name="DOCKER_IMAGE_ULTRAFEEDER"),
                "uat978": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-dump978:latest-build-736",
                    env_variable_name="DOCKER_IMAGE_UAT978"),
                "flightradar": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-flightradar24:latest-build-783",
                    env_variable_name="DOCKER_IMAGE_FLIGHTRADAR"),
                "flightaware": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-piaware:latest-build-603",
                    env_variable_name="DOCKER_IMAGE_FLIGHTAWARE"),
                "radarbox": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-airnavradar:latest-build-760",
                    env_variable_name="DOCKER_IMAGE_RADARBOX"),
                "radarvirtuel": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-radarvirtuel:latest-build-681",
                    env_variable_name="DOCKER_IMAGE_RADARVIRTUEL"),
                "opensky": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-opensky-network:latest-build-772",
                    env_variable_name="DOCKER_IMAGE_OPENSKY"),
                "planefinder": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-planefinder:latest-build-464",
                    env_variable_name="DOCKER_IMAGE_PLANEFINDER"),
                "adsbhub": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-adsbhub:latest-build-465",
                    env_variable_name="DOCKER_IMAGE_ADSBHUB"),
                "planewatch": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/plane-watch/docker-plane-watch:latest-build-207",
                    env_variable_name="DOCKER_IMAGE_PLANEWATCH"),
                "airspy": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/airspy_adsb:latest-build-250",
                    env_variable_name="DOCKER_IMAGE_AIRSPY"),
                "1090uk": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-radar1090:latest-build-236",
                    env_variable_name="DOCKER_IMAGE_1090UK"),
                "sdrmap": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-sdrmap:latest-build-19",
                    env_variable_name="DOCKER_IMAGE_SDRMAP"),
                "sdrplay": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-sdrplay-beast1090:latest-build-24",
                    env_variable_name="DOCKER_IMAGE_SDRPLAY"),
                "webproxy": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-reversewebproxy:latest-build-683",
                    env_variable_name="DOCKER_IMAGE_WEBPROXY"),
                "shipfeeder": ft.partial(
                    ConstantSetting, constant_value=
                    "ghcr.io/sdr-enthusiasts/docker-shipfeeder:latest-build-1731",
                    env_variable_name="DOCKER_IMAGE_SHIPFEEDER"),}),}

    def __init__(self, settings_dict: dict[str, Any]):
        if Config._has_instance:
            raise ValueError("Config has already been instantiated.")
        Config._has_instance = True
        super().__init__(self, settings_dict, schema=self._schema)

    def write_to_file(self):
        config_dict = {}
        for key_path, setting in self.scalar_settings(""):
            if not setting.persistent:
                # Don't write transient settings like constants or generated
                # settings.
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
            for key, value in self.env_variables.items():
                escaped_value = value.replace('"', r'\"')
                f.write(f'{key}="{escaped_value}"\n')

    @staticmethod
    def create_default() -> "Config":
        """Create a config with default values."""
        conf = Config({})
        conf.init_with_default()
        return conf

    @staticmethod
    def load_from_file() -> "Config":
        with Config._file_lock:
            config_dict = Config._load_and_maybe_upgrade_config_dict()
            return Config(config_dict)

    @staticmethod
    def _load_and_maybe_upgrade_config_dict() -> dict[str, Any]:
        with CONFIG_FILE.open() as f:
            config_dict = json.load(f)
        version = config_dict.pop("config_version", 0)
        if version != Config.CONFIG_VERSION:
            config_dict = Config._upgraded_config_dict(config_dict, version)
        return config_dict

    @staticmethod
    def _upgraded_config_dict(config_dict: dict[str, Any],
                              from_version: int) -> dict[str, Any]:
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
                             to_version: int) -> dict[str, Any]:
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
        config_dict["config_version"] = to_version
        with CONFIG_FILE.open("w") as f:
            json.dump(config_dict, f)
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_legacy_to_1(
            config_dict: dict[str, Any]) -> dict[str, Any]:
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

    @staticmethod
    def _upgrade_config_dict_from_1_to_2(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        # These are generated now.
        del config_dict["image_name"]
        del config_dict["board_name"]
        del config_dict["base_version"]
        del config_dict["has_gpsd"]
        # mDNS domains are now represented as an actual list.
        config_dict["mdns"]["domains"] = (
            config_dict["mdns"]["domains"].split(";"))
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_2_to_3(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        config_dict["tailscale"] = {
            "is_enabled": bool(config_dict["tailscale_name"]),
            "login_link": config_dict["tailscale_ll"],
            "extras": config_dict["tailscale_extras"]}
        del config_dict["tailscale_ll"]
        del config_dict["tailscale_name"]
        del config_dict["tailscale_extras"]
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_3_to_4(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        # This is generated now.
        del config_dict["ultrafeeder_config"]
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_4_to_5(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        # This is generated now.
        del config_dict["base_config"]
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_5_to_6(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        # Prometheus settings are moved to the Porttracker aggregator, and the
        # textfile_dir has become a constant.
        prometheus_settings = config_dict.pop("prometheus")
        del prometheus_settings["textfile_dir"]
        config_dict["aggregators"]["porttracker"]["prometheus"] = (
            prometheus_settings)
        return config_dict

    @staticmethod
    def _upgrade_config_dict_from_6_to_7(
            config_dict: dict[str, Any]) -> dict[str, Any]:
        config_dict = config_dict.copy()
        # The other-{0,1,2,3} settings for device assignments are now a list.
        unused_serials = set()
        for i in [0, 1, 2, 3]:
            serial = config_dict["serial_devices"].pop(f"other-{i}")
            if not serial:
                continue
            assert isinstance(serial, str)
            unused_serials.add(serial)
        config_dict["serial_devices"]["unused"] = sorted(unused_serials)
        # These settings are generated now.
        del config_dict["uat978"]
        del config_dict["978url"]
        del config_dict["978host"]
        del config_dict["978piaware"]
        # This setting is obsolete.
        del config_dict["sdrs_locked"]
        return config_dict

    _config_upgraders = {(0, 1): _upgrade_config_dict_from_legacy_to_1,
                         (1, 2): _upgrade_config_dict_from_1_to_2,
                         (2, 3): _upgrade_config_dict_from_2_to_3,
                         (3, 4): _upgrade_config_dict_from_3_to_4,
                         (4, 5): _upgrade_config_dict_from_4_to_5,
                         (5, 6): _upgrade_config_dict_from_5_to_6,
                         (6, 7): _upgrade_config_dict_from_6_to_7}

    for k in it.pairwise(range(CONFIG_VERSION + 1)):
        # Make sure we have an upgrade function for every version increment,
        # where the _config_upgraders dict maps tuples of
        # (from_version, to_version) to upgrader functions.
        assert k in _config_upgraders
        assert callable(_config_upgraders[k])


def ensure_config_exists() -> Config:
    if not CONFIG_DIR.exists():
        logger.info("Config directory doesn't exist, creating an empty one.")
        CONFIG_DIR.mkdir()
    try:
        conf = Config.load_from_file()
    except FileNotFoundError:
        logger.info("Config file doesn't exist, creating a default one.")
        conf = Config.create_default()
        conf.write_to_file()
    return conf


def _main():
    import aggregators
    parser = argparse.ArgumentParser(description="Access the config file.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("ensure_config_exists")
    subparsers.add_parser("write_env_file")
    subparsers.add_parser("as_json")
    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("key_path")
    get_parser.add_argument("--default")
    set_parser = subparsers.add_parser("set")
    set_parser.add_argument("key_path")
    set_parser.add_argument("value")
    args = parser.parse_args()
    with system.System() as sys_:
        conf = ensure_config_exists()
        # Init the aggregators, which are needed for the generated Ultrafeeder
        # config setting.
        aggregators.init_aggregators(conf, sys_)
        _run_command(conf, args)


def _run_command(conf: Config, args):
    if args.command == "ensure_config_exists":
        # This already happened in _main(), nothing to do.
        pass
    elif args.command == "write_env_file":
        conf.write_env_file()
    elif args.command == "as_json":
        print(json.dumps(_compound_setting_as_dict(conf)))
    elif args.command == "get":
        _get(conf, args.key_path, args.default)
    elif args.command == "set":
        _set(conf, args.key_path, args.value)
    else:
        logger.error(f"Unknown command {args.command}.")
        sys.exit(1)


def _compound_setting_as_dict(
        compound_setting: CompoundSetting) -> dict[str, Any]:
    d = {}
    for key, setting in compound_setting:
        if isinstance(setting, CompoundSetting):
            d[key] = _compound_setting_as_dict(setting)
        else:
            d[key] = setting.get("")
    return d


def _get(conf: Config, key_path: str, default: Any):
    print(conf.get(key_path, default=default))


def _set(conf: Config, key_path: str, value: Any) -> None:
    setting = conf.get_setting(key_path)
    if isinstance(setting, BoolSetting):
        if value not in ["True", "False"]:
            raise ValueError("Value must be True or False.")
        value = value == "True"
    elif isinstance(setting, RealNumberSetting):
        value = float(value)
    elif isinstance(setting, IntSetting):
        value = int(value)
    setting.set("", value)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    _main()
