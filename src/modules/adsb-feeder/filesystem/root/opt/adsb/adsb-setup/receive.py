import abc
import dataclasses as dc
import logging
import re
import subprocess
import threading
import time
from typing import Literal, Optional

PURPOSES = frozenset(["978", "1090", "ais"])
"""Possible purposes for which a receiver can be used."""


class Receiver(abc.ABC):
    @property
    @abc.abstractmethod
    def type(self) -> str:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def serial(self) -> str:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def vendor(self) -> str:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def product(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_best_guess_assignments(self) -> list[Literal[*PURPOSES]]:
        """
        Guess what this device should be used for.

        The returned list of purposes is ordered by descending likelihood. The
        list may be empty if we can't figure out what to do with this device.
        """
        raise NotImplementedError


class SdrReceiver(Receiver):
    @dc.dataclass
    class SdrInfo:
        serial: str
        vendor: str
        product: str

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

    def __eq__(self, other):
        return (
            isinstance(other, SdrReceiver) and self._type == other._type
            and self._address == other._address
            and self.serial == other.serial)

    def __repr__(self):
        return (
            f"SdrReceiver(type: '{self._type}' address: '{self._address}', "
            f"serial: '{self.serial}')")

    def _probe_info(self) -> Optional[SdrInfo]:
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
        return self.SdrInfo(serial=serial, vendor=vendor, product=product)

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

    def get_best_guess_assignments(self) -> list[Literal[*PURPOSES]]:
        """
        Guess what this device should be used for.

        The returned list of purposes is ordered by descending likelihood. The
        list may be empty if we can't figure out what to do with this device.
        """
        if self.type in ["airspy", "modesbeast", "sdrplay"]:
            # These only support ADS-B (1090).
            return ["1090"]
        elif self.type == "stratuxv3":
            # This only supports UAT (978).
            return ["978"]
        elif self.type == "rtlsdr":
            if "1090" in self.serial:
                # If it has 1090 in the serial, it's probably for ADS-B.
                return ["1090", "ais", "978"]
            elif "978" in self.serial:
                # If it has 978 in the serial, it's probably for UAT.
                return ["978", "ais", "1090"]
            else:
                return ["ais", "1090", "978"]
        else:
            self._logger.warning(f"Unknown SDR type {self.type}.")
            return []


class ReceiverDevices:
    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)
        self._sdrs = []
        self.lsusb_output = ""
        self._last_probe = 0
        self._last_debug_out = ""
        self._sdr_lock = threading.Lock()

    def __len__(self):
        return len(self.sdrs)

    def __repr__(self):
        return f"ReceiverDevices({','.join([s for s in self.sdrs])})"

    @property
    def sdrs(self) -> list[SdrReceiver]:
        with self._sdr_lock:
            if time.monotonic() - self._last_probe > 1:
                self._last_probe = time.monotonic()
                self._sdrs = self._get_sdrs()
            return self._sdrs

    def _get_sdrs(self):
        debug_out = "_get_sdrs() found:\n"
        try:
            result = subprocess.run("lsusb", shell=True, capture_output=True)
        except subprocess.SubprocessError:
            self._logger.exception("Error running lsusb.")
            return
        lsusb_text = result.stdout.decode()
        self.lsusb_output = f"lsusb: {lsusb_text}"

        output = lsusb_text.split("\n")
        sdrs = []

        def check_pidvid(pv_list=[], sdr_type=None):
            nonlocal debug_out
            if not sdr_type:
                self._logger.warning("Bad code in check_pidvid.")

            for pidvid in pv_list:
                for line in output:
                    address = self._get_address_for_pid_vid(pidvid, line)
                    if address:
                        new_sdr = SdrReceiver(sdr_type, address)
                        sdrs.append(new_sdr)
                        debug_out += (
                            f"sdr_info: type: {sdr_type} "
                            f"serial: {new_sdr.serial} address: {address} "
                            f"pidvid: {pidvid}\n")

        # List of rtl-sdr drivers. Lots of these are likely not gonna work or
        # work well, but it's still better for them to be selectable by the
        # user. At least so they can see if it works or not.
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
        duplicate_serials = set()
        for sdr in sdrs:
            self.lsusb_output += f"\nSDR detected with serial: {sdr.serial}\n"
            self.lsusb_output += sdr.lsusb_output
            if sdr.serial in found_serials:
                duplicate_serials.add(sdr.serial)
            found_serials.add(sdr.serial)
        if duplicate_serials:
            self._logger.warning(f"Duplicate SDR serials {duplicate_serials}.")

        if len(sdrs) == 0:
            debug_out = "_get_sdrs() could not find any SDRs"

        if self._last_debug_out != debug_out:
            self._last_debug_out = debug_out
            self._logger.info(debug_out.rstrip("\n"))
        return sdrs

    def _get_address_for_pid_vid(self, pidvid: str, line: str):
        address = ""
        match = re.search(
            f"Bus ([0-9a-fA-F]+) Device ([0-9a-fA-F]+): ID {pidvid}", line)
        if match:
            address = f"{match.group(1)}:{match.group(2)}"
        return address
