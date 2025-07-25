import logging
import re
import subprocess

from .system import System
from .util import is_email, make_int


class Aggregator:
    def __init__(
        self,
        name: str,
        system: System,
        tags: list = None,
    ):
        self._name = name
        self._tags = tags
        self._system = system
        self._d = system._d
        self._idx = 0
        self._logger = logging.getLogger(type(self).__name__)

    @property
    def name(self):
        return self._name

    @property
    def tags(self):
        return self._tags

    @property
    def _key_tags(self):
        return ["key"] + self.tags

    @property
    def _enabled_tags(self):
        return ["is_enabled", "other_aggregator"] + self.tags

    @property
    def lat(self):
        return self._d.env_by_tags("lat").list_get(self._idx)

    @property
    def lon(self):
        return self._d.env_by_tags("lon").list_get(self._idx)

    @property
    def alt(self):
        return self._d.env_by_tags("alt").list_get(self._idx)

    @property
    def alt_ft(self):
        return int(int(self.alt) / 0.308)

    @property
    def container(self):
        return self._d.env_by_tags(self.tags + ["container"]).value

    @property
    def is_enabled(self, idx=0):
        return self._d.env_by_tags(self._enabled_tags).list_get(self._idx)

    def _activate(self, user_input: str, idx: 0):
        raise NotImplementedError

    def _deactivate(self):
        raise NotImplementedError

    def _download_docker_container(self, container: str) -> bool:
        self._logger.info(f"download_docker_container {container}")
        cmdline = f"docker pull {container}"
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

    # the default case is straight forward. Remember the key and enable the aggregator
    def _simple_activate(self, user_input: str, idx=0):
        if not user_input:
            return False
        self._d.env_by_tags(self._key_tags).list_set(idx, user_input)
        self._d.env_by_tags(self._enabled_tags).list_set(idx, True)
        return True


class ADSBHub(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="ADSBHub",
            tags=["adsb_hub"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        return self._simple_activate(user_input, idx)


class FlightRadar24(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="FlightRadar24",
            tags=["flightradar"],
            system=system,
        )

    def _request_fr24_sharing_key(self, email: str):
        if not self._download_docker_container(self.container):
            self._logger.error(
                "Failed to download the FR24 docker image.",
                flash_message=True)
            return None

        lat = float(self.lat)
        lon = float(self.lon)

        if abs(lat) < 0.5 and abs(lon) < 0.5:
            # this is at null island, just fail for this
            self._logger.error(
                "FR24 cannot handle 'null island'", flash_message=True)
            return None

        # so this signup doesn't work for latitude / longitude <0.1, work around that by just setting longitude 0.11 in that case
        # we don't do FR24 mlat anyhow ... if people want to fix it they can do so on the fr24 homepage
        if abs(lat) < 0.11:
            lat = 0.11
        if abs(lon) < 0.11:
            lon = 0.11

        adsb_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{lat}" -e FEEDER_LONG="{lon}" -e FEEDER_ALT_FT="{self.alt_ft}" '
            f'-e FR24_EMAIL="{email}" {self.container} '
            f'-c "apt update && apt install -y expect && $(cat handsoff_signup_expect.sh)"'
        )
        open("/opt/adsb/handsoff_signup.sh", "w").write(f"#!/bin/bash\n{adsb_signup_command}")
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

        sharing_key_match = re.search("Your sharing key \\(([a-zA-Z0-9]*)\\) has been", output)
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
        if not self._download_docker_container(self.container):
            self._logger.error(
                "Failed to download the FR24 docker image.",
                flash_message=True)
            return None

        uat_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{self.lat}" -e FEEDER_LONG="{self.lon}" -e FEEDER_ALT_FT="{self.alt_ft}" '
            f'-e FR24_EMAIL="{email}" {self.container} '
            f'-c "apt update && apt install -y expect && $(cat handsoff_signup_expect_uat.sh)"'
        )
        open("/opt/adsb/handsoff_signup_uat.sh", "w").write(f"#!/bin/bash\n{uat_signup_command}")
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
        sharing_key_match = re.search("Your sharing key \\(([a-zA-Z0-9]*)\\) has been", output)
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

    def _activate(self, user_input: str, idx=0):
        if not user_input:
            return False
        input_values = user_input.count("::")
        if input_values > 1:
            return False
        elif input_values == 1:
            adsb_sharing_key, uat_sharing_key = user_input.split("::")
        else:
            adsb_sharing_key = user_input
            uat_sharing_key = None
        if not adsb_sharing_key and not uat_sharing_key:
            return False
        self._idx = make_int(idx)  # this way the properties work correctly
        self._logger.info(
            f"FR_activate adsb |{adsb_sharing_key}| uat |{uat_sharing_key}| idx |{idx}|")

        if is_email(adsb_sharing_key):
            # that's an email address, so we are looking to get a sharing key
            adsb_sharing_key = self._request_fr24_sharing_key(adsb_sharing_key)
            self._logger.info(f"got back sharing_key |{adsb_sharing_key}|")
        if adsb_sharing_key and not re.match("[0-9a-zA-Z]+", adsb_sharing_key):
            adsb_sharing_key = None
            self._logger.error("invalid FR24 sharing key", flash_message=True)

        if is_email(uat_sharing_key):
            # that's an email address, so we are looking to get a sharing key
            uat_sharing_key = self._request_fr24_uat_sharing_key(uat_sharing_key)
            self._logger.info(f"got back uat_sharing_key |{uat_sharing_key}|")
        if uat_sharing_key and not re.match("[0-9a-zA-Z]+", uat_sharing_key):
            uat_sharing_key = None
            self._logger.error(
                "invalid FR24 UAT sharing key", flash_message=True)

        # overwrite email in config so that the container is not started with the email as sharing key if failed
        # otherwise just set sharing key as appropriate
        self._d.env_by_tags(["flightradar", "key"]).list_set(idx, adsb_sharing_key or "")
        self._d.env_by_tags(["flightradar_uat", "key"]).list_set(idx, uat_sharing_key or "")

        if adsb_sharing_key or uat_sharing_key:
            # we have at least one sharing key, let's just enable the container
            self._d.env_by_tags(self._enabled_tags).list_set(idx, True)
            return True
        else:
            self._d.env_by_tags(self._enabled_tags).list_set(idx, False)
            return False


class PlaneWatch(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="PlaneWatch",
            tags=["planewatch"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        return self._simple_activate(user_input, idx)


class FlightAware(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="FlightAware",
            tags=["flightaware"],
            system=system,
        )

    def _request_fa_feeder_id(self):
        if not self._download_docker_container(self.container):
            self._logger.error(
                "failed to download the piaware docker image",
                flash_message=True)
            return None

        cmdline = f"--rm {self.container}"
        output = self._docker_run_with_timeout(cmdline, 45.0)
        feeder_id_match = re.search(" feeder ID is ([-a-zA-Z0-9]*)", output)
        if feeder_id_match:
            return feeder_id_match.group(1)
        self._logger.error(
            f"couldn't find a feeder ID in the container output: {output}",
            flash_message="FlightAware: couldn't find a feeder ID in server "
            "response")
        return None

    def _activate(self, user_input: str, idx=0):
        self._idx = make_int(idx)
        if re.match("[0-9a-zA-Z]+", user_input):
            # that might be a valid key
            feeder_id = user_input
        else:
            feeder_id = self._request_fa_feeder_id()
            self._logger.info(f"got back feeder_id |{feeder_id}|")
        if not feeder_id:
            return False

        self._d.env_by_tags(self._key_tags).list_set(idx, feeder_id)
        self._d.env_by_tags(self._enabled_tags).list_set(idx, True)
        return True


class RadarBox(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="AirNav Radar",
            tags=["radarbox"],
            system=system,
        )

    def _request_rb_sharing_key(self, idx):
        docker_image = self._d.env_by_tags(["radarbox", "container"]).value

        if not self._download_docker_container(docker_image):
            self._logger.error(
                "failed to download the AirNav Radar docker image",
                flash_message=True)
            return None

        suffix = f"_{idx}" if idx else ""
        # make sure we correctly enable the hacks
        extra_env = f"-v /opt/adsb/rb/cpuinfo{suffix}:/proc/cpuinfo "
        if self._d.env_by_tags("rbthermalhack").value != "":
            extra_env += "-v /opt/adsb/rb:/sys/class/thermal:ro "

        cmdline = (
            f"--rm -i --network config_default -e BEASTHOST=ultrafeeder -e LAT={self.lat} "
            f"-e LONG={self.lon} -e ALT={self.alt} {extra_env} {docker_image}"
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

    def _activate(self, user_input: str, idx=0):
        self._idx = make_int(idx)
        if re.match("[0-9a-zA-Z]+", user_input):
            # that might be a valid key
            sharing_key = user_input
        else:
            # try to get a key
            sharing_key = self._request_rb_sharing_key(idx)
        if not sharing_key:
            return False

        self._d.env_by_tags(self._key_tags).list_set(idx, sharing_key)
        self._d.env_by_tags(self._enabled_tags).list_set(idx, True)
        return True


class OpenSky(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="OpenSky Network",
            tags=["opensky"],
            system=system,
        )

    def _request_fr_serial(self, user):
        docker_image = self._d.env_by_tags(["opensky", "container"]).value

        if not self._download_docker_container(docker_image):
            self._logger.error(
                "failed to download the OpenSky docker image",
                flash_message=True)
            return None

        cmdline = (
            f"--rm -i --network config_default -e BEASTHOST=ultrafeeder -e LAT={self.lat} "
            f"-e LONG={self.lon} -e ALT={self.alt} -e OPENSKY_USERNAME={user} {docker_image}"
        )
        output = self._docker_run_with_timeout(cmdline, 60.0)
        serial_match = re.search("Got a new serial number: ([-a-zA-Z0-9]*)", output)
        if not serial_match:
            self._logger.error(
                "couldn't find a serial number in the container output: "
                f"{output}",
                flash_message="OpenSky: couldn't find a serial number in "
                "server response")
            return None

        return serial_match.group(1)

    def _activate(self, user_input: str, idx=0):
        self._idx = make_int(idx)
        serial, user = user_input.split("::")
        self._logger.info(f"passed in {user_input} seeing user |{user}| and serial |{serial}|")
        if not user:
            self._logger.error(f"missing user name for OpenSky")
            return False
        if not serial:
            self._logger.error(f"need to request serial for OpenSky")
            serial = self._request_fr_serial(user)
            if not serial:
                self._logger.error("failed to get OpenSky serial")
                return False
        self._d.env_by_tags(self.tags + ["user"]).list_set(idx, user)
        self._d.env_by_tags(self.tags + ["key"]).list_set(idx, serial)
        self._d.env_by_tags(self.tags + ["is_enabled"]).list_set(idx, True)
        return True


class RadarVirtuel(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="RadarVirtuel",
            tags=["radarvirtuel"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        return self._simple_activate(user_input, idx)


class PlaneFinder(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="PlaneFinder",
            tags=["planefinder"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        return self._simple_activate(user_input, idx)


class Uk1090(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="1090Mhz UK",
            tags=["1090uk"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        return self._simple_activate(user_input, idx)


class Sdrmap(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="sdrmap",
            tags=["sdrmap"],
            system=system,
        )

    def _activate(self, user_input: str, idx=0):
        self._idx = make_int(idx)
        password, user = user_input.split("::")
        self._logger.error(
            f"passed in {user_input} seeing user |{user}| and password |{password}|")
        if not user:
            self._logger.error(f"missing user name for sdrmap")
            return False
        if not password:
            self._logger.error(f"missing password for sdrmap")
            return False
        self._d.env_by_tags(self.tags + ["user"]).list_set(idx, user)
        self._d.env_by_tags(self.tags + ["key"]).list_set(idx, password)
        self._d.env_by_tags(self.tags + ["is_enabled"]).list_set(idx, True)
        return True


class Porttracker(Aggregator):
    def __init__(self, system: System):
        super().__init__(
            name="Porttracker",
            tags=["porttracker"],
            system=system,
        )
        self._station_id = None

    def __str__(self):
        return f"Porttracker aggregator for station ID {self._station_id}"

    def _activate(
            self, station_id: int, data_sharing_key: str, mqtt_protocol: str,
            mqtt_host: str, mqtt_port: str, mqtt_username: str,
            mqtt_password: str, mqtt_topic: str, site_num=0):
        mqtt_url = "{}://{}:{}@{}:{}".format(
            mqtt_protocol, mqtt_username, mqtt_password, mqtt_host, mqtt_port)
        client_id = f"{mqtt_username}-{station_id}"
        self._d.env_by_tags(self.tags + ["station_id"]).list_set(
            site_num, station_id)
        self._d.env_by_tags(self.tags + ["data_sharing_key"]).list_set(
            site_num, data_sharing_key)
        self._d.env_by_tags(self.tags + ["mqtt_url"]).list_set(
            site_num, mqtt_url)
        self._d.env_by_tags(self.tags + ["mqtt_client_id"]).list_set(
            site_num, client_id)
        self._d.env_by_tags(self.tags + ["mqtt_qos"]).list_set(site_num, "0")
        self._d.env_by_tags(self.tags + ["mqtt_topic"]).list_set(
            site_num, mqtt_topic)
        self._d.env_by_tags(self.tags + ["mqtt_msgformat"]).list_set(
            site_num, "JSON_NMEA")
        self._d.env_by_tags(self._enabled_tags).list_set(site_num, True)
        self._station_id = station_id
        return True

    def _deactivate(self, site_num=0):
        self._d.env_by_tags(self._enabled_tags).list_set(site_num, False)
        return True
