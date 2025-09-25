import dataclasses as dc
import logging
import re
import subprocess
import threading
import time
from typing import Optional


@dc.dataclass
class SDRInfo:
    serial: str
    vendor: str
    product: str


class SDR:
    def __init__(self, type_: str, address: str):
        self._logger = logging.getLogger(type(self).__name__)
        self._type = type_
        self._address = address
        self.lsusb_output = ""
        self._info = self._probe_info()

    @property
    def type(self) -> str:
        return self._type

    @property
    def serial(self) -> str:
        self._info = self._info or self._probe_info()
        if not self._info:
            return ""
        return self._info.serial

    @property
    def vendor(self) -> str:
        self._info = self._info or self._probe_info()
        if not self._info:
            return ""
        return self._info.vendor

    @property
    def product(self) -> str:
        self._info = self._info or self._probe_info()
        if not self._info:
            return ""
        return self._info.product

    def _probe_info(self) -> Optional[SDRInfo]:
        cmdline = f"lsusb -s {self._address} -v"
        try:
            result = subprocess.run(cmdline, shell=True, capture_output=True)
        except subprocess.SubprocessError:
            self._logger.exception(f"Error running {cmdline}")
            return None
        output = result.stdout.decode()
        self.lsusb_output = f"lsusb -s {self._address}: {output}"
        serial = vendor = product = ""
        for line in output.splitlines():
            serial = serial or self._extract_serial(line)
            vendor = vendor or self._extract_vendor(line)
            product = product or self._extract_product(line)
        if not serial:
            if self._type == "stratuxv3":
                serial = "stratuxv3 w/o serial"
            elif self._type == "modesbeast":
                serial = "Mode-S Beast w/o serial"
            elif self._type == "sdrplay":
                serial = "SDRplay w/o serial"
        return SDRInfo(serial=serial, vendor=vendor, product=product)

    def _extract_serial(self, line):
        match = re.search(r"iSerial\s+\d+\s+(.+)$", line)
        if not match:
            return ""
        serial = match.group(1).strip()
        if self._type == "airspy":
            split = serial.split(":")
            if len(split) == 2 and len(split[1]) == 16:
                return split[1]
        return serial

    def _extract_vendor(self, line):
        match = re.search(r"idVendor\s+\S+\s+(.+)$", line)
        if not match:
            return ""
        return match.group(1).strip()

    def _extract_product(self, line):
        match = re.search(r"idProduct\s+\S+\s+(.+)$", line)
        if not match:
            return ""
        return match.group(1).strip()

    @property
    def _json(self):
        return {
            "type": self._type,
            "address": self._address,
            "serial": self.serial,}

    # a magic method to compare two objects
    def __eq__(self, other):
        if isinstance(other, SDR):
            return self._json == other._json
        return False

    def __repr__(self):
        return f"SDR(type: '{self._type}' address: '{self._address}', serial: '{self.serial}')"


class SDRDevices:
    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self.sdrs: list[SDR] = []
        self.duplicate_serials: set[str] = set()
        self.lsusb_output = ""
        self.last_probe = 0
        self.last_debug_out = ""
        self.lock = threading.Lock()

    def __len__(self):
        return len(self.sdrs)

    def __repr__(self):
        return f"SDRDevices({','.join([s for s in self.sdrs])})"

    def purposes(self):
        return (
            "978",
            "1090",
            "ais",
            "other-0",
            "other-1",
            "other-2",
            "other-3",
        )

    def _update_sdrs(self):
        self.debug_out = "_update_sdrs() found:\n"
        try:
            result = subprocess.run("lsusb", shell=True, capture_output=True)
        except subprocess.SubprocessError:
            self._logger.exception("Error running lsusb.")
            return
        lsusb_text = result.stdout.decode()
        self.lsusb_output = f"lsusb: {lsusb_text}"

        output = lsusb_text.split("\n")
        self.sdrs = []

        def check_pidvid(pv_list=[], sdr_type=None):
            if not sdr_type:
                self._logger.warning("Bad code in check_pidvid.")

            for pidvid in pv_list:
                for line in output:
                    address = self._get_address_for_pid_vid(pidvid, line)
                    if address:
                        new_sdr = SDR(sdr_type, address)
                        self.sdrs.append(new_sdr)
                        self.debug_out += f"sdr_info: type: {sdr_type} serial: {new_sdr.serial} address: {address} pidvid: {pidvid}\n"

        # list from rtl-sdr drivers
        # lots of these are likely not gonna work / work well but it's still better
        # for them to be selectable by the user at least so they can see if it works or not
        rtlsdr_pv_list = [
            "0bda:2832",  # Generic RTL2832U
            "0bda:2838",  # Generic RTL2832U OEM
            "0413:6680",  # DigitalNow Quad DVB-T PCI-E card
            "0413:6f0f",  # Leadtek WinFast DTV Dongle mini D
            "0458:707f",  # Genius TVGo DVB-T03 USB dongle (Ver. B)
            "0ccd:00a9",  # Terratec Cinergy T Stick Black (rev 1)
            "0ccd:00b3",  # Terratec NOXON DAB/DAB+ USB dongle (rev 1)
            "0ccd:00b4",  # Terratec Deutschlandradio DAB Stick
            "0ccd:00b5",  # Terratec NOXON DAB Stick - Radio Energy
            "0ccd:00b7",  # Terratec Media Broadcast DAB Stick
            "0ccd:00b8",  # Terratec BR DAB Stick
            "0ccd:00b9",  # Terratec WDR DAB Stick
            "0ccd:00c0",  # Terratec MuellerVerlag DAB Stick
            "0ccd:00c6",  # Terratec Fraunhofer DAB Stick
            "0ccd:00d3",  # Terratec Cinergy T Stick RC (Rev.3)
            "0ccd:00d7",  # Terratec T Stick PLUS
            "0ccd:00e0",  # Terratec NOXON DAB/DAB+ USB dongle (rev 2)
            "1554:5020",  # PixelView PV-DT235U(RN)
            "15f4:0131",  # Astrometa DVB-T/DVB-T2
            "15f4:0133",  # HanfTek DAB+FM+DVB-T
            "185b:0620",  # Compro Videomate U620F
            "185b:0650",  # Compro Videomate U650F
            "185b:0680",  # Compro Videomate U680F
            "1b80:d393",  # GIGABYTE GT-U7300
            "1b80:d394",  # DIKOM USB-DVBT HD
            "1b80:d395",  # Peak 102569AGPK
            "1b80:d397",  # KWorld KW-UB450-T USB DVB-T Pico TV
            "1b80:d398",  # Zaapa ZT-MINDVBZP
            "1b80:d39d",  # SVEON STV20 DVB-T USB & FM
            "1b80:d3a4",  # Twintech UT-40
            "1b80:d3a8",  # ASUS U3100MINI_PLUS_V2
            "1b80:d3af",  # SVEON STV27 DVB-T USB & FM
            "1b80:d3b0",  # SVEON STV21 DVB-T USB & FM
            "1d19:1101",  # Dexatek DK DVB-T Dongle (Logilink VG0002A)
            "1d19:1102",  # Dexatek DK DVB-T Dongle (MSI DigiVox mini II V3.0)
            "1d19:1103",  # Dexatek Technology Ltd. DK 5217 DVB-T Dongle
            "1d19:1104",  # MSI DigiVox Micro HD
            "1f4d:a803",  # Sweex DVB-T USB
            "1f4d:b803",  # GTek T803
            "1f4d:c803",  # Lifeview LV5TDeluxe
            "1f4d:d286",  # MyGica TD312
            "1f4d:d803",  # PROlectrix DV107669
        ]

        check_pidvid(pv_list=rtlsdr_pv_list, sdr_type="rtlsdr")
        check_pidvid(pv_list=["0403:7028"], sdr_type="stratuxv3")
        check_pidvid(pv_list=["1d50:60a1"], sdr_type="airspy")
        check_pidvid(pv_list=["0403:6001"], sdr_type="modesbeast")

        sdrplay_pv_list = [
            "1df7:2500",
            "1df7:3000",
            "1df7:3010",
            "1df7:3020",
            "1df7:3030",
            "1df7:3050",]

        check_pidvid(pv_list=sdrplay_pv_list, sdr_type="sdrplay")

        found_serials = set()
        self.duplicate_serials = set()
        for sdr in self.sdrs:
            self.lsusb_output += f"\nSDR detected with serial: {sdr.serial}\n"
            self.lsusb_output += sdr.lsusb_output
            if sdr.serial in found_serials:
                self.duplicate_serials.add(sdr.serial)
            else:
                found_serials.add(sdr.serial)
        if self.duplicate_serials:
            self._logger.warning(
                f"Duplicate SDR serials {self.duplicate_serials}.")

        if len(self.sdrs) == 0:
            self.debug_out = "_update_sdrs() could not find any SDRs"

        if self.last_debug_out != self.debug_out:
            self.last_debug_out = self.debug_out
            self._logger.info(self.debug_out.rstrip("\n"))

    def ensure_populated(self):
        with self.lock:
            if time.time() - self.last_probe < 1:
                return
            self.last_probe = time.time()
            self._update_sdrs()

    def _get_address_for_pid_vid(self, pidvid: str, line: str):
        address = ""
        match = re.search(
            f"Bus ([0-9a-fA-F]+) Device ([0-9a-fA-F]+): ID {pidvid}", line)
        if match:
            address = f"{match.group(1)}:{match.group(2)}"
        return address

    @property
    def addresses_per_frequency(self, frequencies: list = ["1090", "978", "ais"]):
        self.ensure_populated()
        # - if we find an airspy, that's for 1090
        # - if we find an stratuxv3, that's for 978
        # - if we find an RTL SDR with serial 1090 or 00001090 - well, that's for 1090 (unless it's an airspy)
        # - if we find an RTL SDR with serial 978 or 00000978 - that's for 978 (if you have more than one SDR)
        # - if we find an RTL SDR with a different serial, that's for 1090 (if we don't have one already)
        # - if, at the end, an RTL SDR is unassigned, that's for AIS
        # Make sure one SDR is used per frequency at most...
        assignment = {}
        for sdr in self.sdrs:
            if sdr.type in ["airspy", "modesbeast", "sdrplay"]:
                assignment.setdefault("1090", sdr.serial)
            elif sdr.type == "stratuxv3":
                assignment.setdefault("978", sdr.serial)
            elif sdr.type == "rtlsdr":
                if "1090" in sdr.serial:
                    assignment.setdefault("1090", sdr.serial)
                elif "978" in sdr.serial and len(self.sdrs) > 1:
                    assignment.setdefault("978", sdr.serial)
                else:
                    assignment.setdefault("1090", sdr.serial)
            else:
                self._logger.warning(f"Unknown SDR type {sdr.type}.")
        if not assignment and self.sdrs:
            # Nothing is assigned, but we have devices. Use the first one for
            # 1090.
            assignment["1090"] = self.sdrs[0].serial
        try:
            unassigned_rtlsdr = next(
                sdr for sdr in self.sdrs if sdr.type == "rtlsdr"
                and sdr.serial not in assignment.values())
            # This one isn't assigned yet, use it for AIS.
            assignment.setdefault("ais", unassigned_rtlsdr.serial)
        except StopIteration:
            pass
        for frequency in frequencies:
            # Make sure all frequencies exist.
            assignment.setdefault(frequency, "")
        return assignment
