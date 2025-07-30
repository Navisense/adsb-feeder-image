import logging
import re
import subprocess
from typing import Optional

import utils.system
import utils.util


class ConfigureError(Exception):
    pass


class Aggregator:
    def __init__(
            self, name: str, system: utils.system.System, tags: list[str]):
        self._logger = logging.getLogger(type(self).__name__)
        self._system = system
        self._name = name
        self._tags = tags
        self._d = system._d

    @property
    def name(self):
        return self._name

    @property
    def tags(self):
        return self._tags

    def _lat(self):
        return self._d.env_by_tags("lat").list_get(0)

    def _lon(self):
        return self._d.env_by_tags("lon").list_get(0)

    def _alt(self):
        return self._d.env_by_tags("alt").list_get(0)

    def _alt_ft(self):
        return int(int(self._alt()) / 0.308)

    @property
    def container(self):
        return self._d.env_by_tags(self.tags + ["container"]).value

    def configure(self, enabled: bool, key: str, *args) -> None:
        if not enabled:
            self._d.env_by_tags(self.tags + ["enabled"]).list_set(0, False)
            self._logger.info("Disabled.")
            return
        if not key:
            raise ConfigureError("No key provided.")
        self._d.env_by_tags(self.tags + ["key"]).list_set(0, key)
        self._d.env_by_tags(self.tags + ["enabled"]).list_set(0, True)
        self._logger.info("Enabled.")

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


class ADSBHub(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="ADSBHub", tags=["adsbhub"])


class FlightRadar24(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="FlightRadar24", tags=["flightradar"])

    def configure(
            self, enabled: bool, adsb_sharing_key_or_email: str,
            uat_sharing_key_or_email: Optional[str]) -> None:
        if not enabled:
            super().configure(enabled, adsb_sharing_key_or_email)
        if not adsb_sharing_key_or_email:
            raise ConfigureError("No sharing key or email provided.")
        uat_sharing_key_or_email = uat_sharing_key_or_email or ""
        self._logger.info(
            f"FR_activate adsb |{adsb_sharing_key_or_email}| uat |{uat_sharing_key_or_email}|"
        )

        if utils.util.is_email(adsb_sharing_key_or_email):
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

        if utils.util.is_email(uat_sharing_key_or_email):
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
            self._d.env_by_tags(["flightradar_uat",
                                 "key"]).list_set(0, uat_sharing_key)
            super().configure(enabled, adsb_sharing_key)
        else:
            raise ConfigureError("Couldn't get any sharing key.")

    def _request_fr24_sharing_key(self, email: str):
        if not self._download_docker_container(self.container):
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

        # so this signup doesn't work for latitude / longitude <0.1, work around that by just setting longitude 0.11 in that case
        # we don't do FR24 mlat anyhow ... if people want to fix it they can do so on the fr24 homepage
        if abs(lat) < 0.11:
            lat = 0.11
        if abs(lon) < 0.11:
            lon = 0.11

        adsb_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{lat}" -e FEEDER_LONG="{lon}" -e FEEDER_ALT_FT="{self._alt_ft()}" '
            f'-e FR24_EMAIL="{email}" {self.container} '
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
        if not self._download_docker_container(self.container):
            self._logger.error(
                "Failed to download the FR24 docker image.",
                flash_message=True)
            return None

        uat_signup_command = (
            f"docker run --entrypoint /bin/bash --rm "
            f'-e FEEDER_LAT="{self._lat()}" -e FEEDER_LONG="{self._lon()}" -e FEEDER_ALT_FT="{self._alt_ft()}" '
            f'-e FR24_EMAIL="{email}" {self.container} '
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


class PlaneWatch(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="PlaneWatch", tags=["planewatch"])


class FlightAware(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="FlightAware", tags=["flightaware"])

    def configure(self, enabled: bool, feeder_id: Optional[str]) -> None:
        if not feeder_id:
            feeder_id = self._request_fa_feeder_id()
            self._logger.info(f"got back feeder_id |{feeder_id}|")
        if not feeder_id:
            raise ConfigureError("Couldn't get a new feeder ID.")
        super().configure(enabled, feeder_id)

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


class RadarBox(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="AirNav Radar", tags=["radarbox"])

    def configure(self, enabled: bool, sharing_key: Optional[str]) -> None:
        if not sharing_key:
            sharing_key = self._request_rb_sharing_key()
        if not sharing_key:
            raise ConfigureError("Couldn't get a new sharing key.")
        super().configure(enabled, sharing_key)

    def _request_rb_sharing_key(self):
        docker_image = self._d.env_by_tags(["radarbox", "container"]).value

        if not self._download_docker_container(docker_image):
            self._logger.error(
                "failed to download the AirNav Radar docker image",
                flash_message=True)
            return None

        # make sure we correctly enable the hacks
        extra_env = f"-v /opt/adsb/rb/cpuinfo:/proc/cpuinfo "
        if self._d.env_by_tags("rbthermalhack").value != "":
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


class OpenSky(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="OpenSky Network", tags=["opensky"])

    def configure(
            self, enabled: bool, user: str, serial: Optional[str]) -> None:
        if not enabled:
            super().configure(enabled, serial)
        if not user:
            raise ConfigureError("missing user name")
        if not serial:
            self._logger.info(f"need to request serial for OpenSky")
            serial = self._request_fr_serial(user)
            if not serial:
                raise ConfigureError("failed to get OpenSky serial")
        self._d.env_by_tags(self.tags + ["user"]).list_set(0, user)
        super().configure(enabled, serial)

    def _request_fr_serial(self, user):
        docker_image = self._d.env_by_tags(["opensky", "container"]).value

        if not self._download_docker_container(docker_image):
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


class RadarVirtuel(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="RadarVirtuel", tags=["radarvirtuel"])


class PlaneFinder(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="PlaneFinder", tags=["planefinder"])


class Uk1090(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="1090Mhz UK", tags=["1090uk"])


class Sdrmap(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="sdrmap", tags=["sdrmap"])

    def configure(self, enabled: bool, user: str, password: str) -> None:
        if not enabled:
            super().configure(enabled, password)
        if not user:
            raise ConfigureError("missing user")
        if not password:
            raise ConfigureError("missing password")
        self._d.env_by_tags(self.tags + ["user"]).list_set(0, user)
        super().configure(enabled, password)


class Porttracker(Aggregator):
    def __init__(self, system: utils.system.System):
        super().__init__(system, name="Porttracker", tags=["porttracker"])
        self._station_id = None

    def __str__(self):
        return f"Porttracker aggregator for station ID {self._station_id}"

    def configure(
            self, enabled: bool, station_id: int, data_sharing_key: str,
            mqtt_protocol: str, mqtt_host: str, mqtt_port: str,
            mqtt_username: str, mqtt_password: str, mqtt_topic: str) -> None:
        if not enabled:
            super().configure(enabled, data_sharing_key)
        if not all([station_id, data_sharing_key, mqtt_protocol, mqtt_host,
                    mqtt_port, mqtt_username, mqtt_password, mqtt_topic]):
            raise ConfigureError("Missing setting.")
        mqtt_url = "{}://{}:{}@{}:{}".format(
            mqtt_protocol, mqtt_username, mqtt_password, mqtt_host, mqtt_port)
        client_id = f"{mqtt_username}-{station_id}"
        self._d.env_by_tags(self.tags + ["station_id"]).list_set(0, station_id)
        self._d.env_by_tags(self.tags + ["mqtt_url"]).list_set(0, mqtt_url)
        self._d.env_by_tags(self.tags + ["mqtt_client_id"]).list_set(
            0, client_id)
        self._d.env_by_tags(self.tags + ["mqtt_qos"]).list_set(0, "0")
        self._d.env_by_tags(self.tags + ["mqtt_topic"]).list_set(0, mqtt_topic)
        self._d.env_by_tags(self.tags + ["mqtt_msgformat"]).list_set(
            0, "JSON_NMEA")
        super().configure(enabled, data_sharing_key)
