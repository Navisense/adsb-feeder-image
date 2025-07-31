from uuid import uuid4
from utils.util import is_true, print_err


class NetConfig:
    def __init__(self, adsb_config: str, mlat_config: str, has_policy: bool):
        self.adsb_config = adsb_config
        self.mlat_config = mlat_config
        self._has_policy = has_policy

    def generate(self, mlat_privacy: bool = True, uuid: str = None, mlat_enable: bool = True):
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
            return f"{adsb_line}"

    @property
    def has_policy(self):
        return self._has_policy


class UltrafeederConfig:
    def __init__(self, data, micro=0):
        assert micro == 0
        # 0means this is either standalone or the aggregator Ultrafeeder
        self._micro = micro
        self._d = data

    @property
    def enabled_aggregators(self):
        ret = {}
        aggregator_selection = self._d.env_by_tags("aggregator_choice").value
        print_err(
            f"enabled_aggregators for {self._micro} with agg_sel {aggregator_selection}",
            level=8,
        )
        # be careful to set the correct values for the individual aggregators;
        # these values are used in the main landing page for the feeder to provide
        # additional links for the enabled aggregators

        for name, value in self._d.netconfigs.items():
            aggregator_env = self._d.env_by_tags([name, "ultrafeeder", "is_enabled"])
            if not aggregator_env:
                print_err(f"netconfigs references tag {name} with no associated env")
                continue
            elif aggregator_selection == "all":
                aggregator_env.list_set(self._micro, True)
            elif aggregator_selection == "privacy":
                aggregator_env.list_set(
                    self._micro,
                    self._d.netconfigs[name].has_policy,
                )
            if is_true(aggregator_env.list_get(self._micro)):
                ret[name] = value
        return ret

    def generate(self):
        print_err("generating netconfigs for Ultrafeeder")
        mlat_privacy = self._d.list_is_enabled("mlat_privacy", self._micro)
        mlat_enable = self._d.list_is_enabled("mlat_enable", self._micro)
        ret = set()
        # let's grab the values, depending on the mode
        for name, netconfig in self.enabled_aggregators.items():
            uuid_tag = "adsblol_uuid" if name == "adsblol" else "ultrafeeder_uuid"
            uuid = self._d.env_by_tags(uuid_tag).list_get(self._micro)
            if not uuid:
                uuid = str(uuid4())
                self._d.env_by_tags(uuid_tag).list_set(self._micro, uuid)
            ret.add(netconfig.generate(mlat_privacy=mlat_privacy, uuid=uuid, mlat_enable=mlat_enable))
        ret.discard("")

        if self._d.list_is_enabled("uat978", self._micro):
            # the dump978 container if this is an integrated feeder
            ret.add("adsb,dump978,30978,uat_in")

        remote_sdr = self._d.env_by_tags("remote_sdr").value
        # make sure we only ever use 1 SDR / network input for ultrafeeder
        if self._d.env_by_tags("readsb_device_type").value != "":
            pass
        elif self._d.is_enabled("airspy"):
            ret.add("adsb,airspy_adsb,30005,beast_in")
        elif self._d.is_enabled("sdrplay"):
            ret.add("adsb,sdrplay-beast1090,30005,beast_in")
        elif remote_sdr:
            if remote_sdr.find(",") == -1:
                remote_sdr += ",30005"
            ret.add(f"adsb,{remote_sdr.replace(' ', '')},beast_in")

        # finally, add user provided things
        ultrafeeder_extra_args = self._d.env_by_tags("ultrafeeder_extra_args").value
        if ultrafeeder_extra_args:
            ret.add(ultrafeeder_extra_args)

        if self._d.is_enabled("use_gpsd"):
            ret.add("gpsd,host.docker.internal,2947")

        # generate sorted listed for deterministic env var (avoid unnecessary container recreation by docker compose)
        ret = sorted(ret)

        print_err(f"ended up with Ultrafeeder args {ret}")

        return ";".join(ret)
