import uuid

import aggregators
import config
from util import is_true, print_err


class UltrafeederConfig:
    def __init__(self, conf: config.Config, all_aggregators: dict[str, aggregators.Aggregator]):
        self._conf = conf
        self._all_aggregators = all_aggregators

    def generate(self):
        args = set()
        # let's grab the values, depending on the mode
        for agg_key, aggregator in self._all_aggregators.items():
            if not isinstance(aggregator, aggregators.UltrafeederAggregator):
                continue
            if agg_key == "adsblol":
                uuid_setting_path = "adsblol_uuid"
            else:
                uuid_setting_path = "ultrafeeder_uuid"
            agg_uuid = self._conf.get(uuid_setting_path)
            if not agg_uuid:
                agg_uuid = str(uuid.uuid4())
                self._conf.set(uuid_setting_path, agg_uuid)
            args.add(aggregator.netconfig.generate(mlat_privacy=self._conf.get("mlat_privacy"), uuid=agg_uuid, mlat_enable=self._conf.get("mlat_enable")))
        args.discard("")

        if self._conf.get("uat978"):
            # the dump978 container if this is an integrated feeder
            args.add("adsb,dump978,30978,uat_in")

        remote_sdr = self._conf.get("remote_sdr")
        # make sure we only ever use 1 SDR / network input for ultrafeeder
        if self._conf.get("readsb_device_type"):
            pass
        elif self._conf.get("airspy"):
            args.add("adsb,airspy_adsb,30005,beast_in")
        elif self._conf.get("sdrplay"):
            args.add("adsb,sdrplay-beast1090,30005,beast_in")
        elif remote_sdr:
            if remote_sdr.find(",") == -1:
                remote_sdr += ",30005"
            args.add(f"adsb,{remote_sdr.replace(' ', '')},beast_in")

        # finally, add user provided things
        ultrafeeder_extra_args = self._conf.get("ultrafeeder_extra_args")
        if ultrafeeder_extra_args:
            args.add(ultrafeeder_extra_args)

        if self._conf.get("use_gpsd"):
            args.add("gpsd,host.docker.internal,2947")

        # generate sorted listed for deterministic env var (avoid unnecessary
        # container recreation by docker compose)
        args = sorted(args)

        print_err(f"ended up with Ultrafeeder args {args}")

        return ";".join(args)
