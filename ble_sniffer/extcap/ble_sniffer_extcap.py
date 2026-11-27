#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wireshark extcap for the Bbo BLE Sniffer over USB CDC.

Each matching COM port is one interface, the same way the older nRF sniffer
lists boards. Capture reads that port and writes DLT 256 to the extcap fifo.
"""

import sys
import os
import re
import time
import struct
import argparse
import queue
import threading

EXTCAP_VERSION = "2.0.0"

# Wireshark BLE DLT 256
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256

# Binary frame headers. v2 (0x53BF): magic(2) type(1) flags(1) ch(1) rssi(1) len(2) seq(2)
# ts_us(8) aa(4) pdu_hdr(1) cte_info(1) = 24 B. v1 (0x53BE): 18 B with 32-bit ts, no seq.
SNIFFER_BIN_MAGIC = 0x53BF
SNIFFER_BIN_MAGIC_V1 = 0x53BE
BIN_HDR_FORMAT = "<HBBBbHHQIBB"
BIN_HDR_SIZE = 24
BIN_HDR_V1_FORMAT = "<HBBBbHIIBB"
BIN_HDR_V1_SIZE = 18
FLAG_CTE = 0x20
MAX_PKT_TYPE = 11

SNIFFER_CMD_NAME_MAX = 31

# Old RPA is treated as gone after this quiet period; then follow the new address.
RPA_STALE_SEC = 5.0
# Ignore further RPA switches for a while after one update.
RPA_COOLDOWN_SEC = 10.0
# A same-name address is "live" if seen within this window.
RPA_LIVE_SEC = 2.0
# Pause RPA follow while a connection is up. Resume after LL_TERMINATE_IND,
# the peer advertising again, or one supervision timeout with no PDU.
# Mid-connection name/addr rediscovery leaves the link and drops ATT.
UNKNOWN_SUP_US = 6_000_000
SUP_TIMEOUT_MIN, SUP_TIMEOUT_MAX = 0x000A, 0x0C80
LL_CONNECTION_UPDATE_IND = 0x00
LL_TERMINATE_IND = 0x02
ADV_ACCESS_ADDRESS = 0x8E89BED6

# CDC ACM identities this sniffer enumerates as.
# 2FE3:0001 is the Zephyr sample default; 1915:BB01 is nrf54lm20dk_nrf54lm20a_cpuapp.conf.
USB_CDC_IDS = (
    (0x2FE3, 0x0001),
    (0x1915, 0xBB01),
)

# Wireshark extcap toolbar. Same packet layout as nrf_sniffer_ble.py.
CTRL_CMD_INIT = 0
CTRL_CMD_SET = 1
CTRL_CMD_ADD = 2
CTRL_CMD_REMOVE = 3
CTRL_CMD_ENABLE = 4
CTRL_CMD_INFO_MSG = 7
CTRL_CMD_WARN_MSG = 8
CTRL_CMD_ERROR_MSG = 9
CTRL_ARG_DEVICE = 0
CTRL_ARG_KEY = 1
CTRL_ARG_VALUE = 2
CTRL_ARG_RSSI = 3
CTRL_ARG_CLEAR = 4
CTRL_ARG_LOG = 5
CTRL_ARG_NONE = 255
DEVICE_ALL = "all"
KEY_LTK = "ltk"
KEY_IRK = "irk"
KEY_BCODE = "bcode"

# Legacy PDU types whose first address is the advertiser.
_ADV_A_AT_0 = (0x00, 0x01, 0x02, 0x04, 0x06)
# SCAN_REQ / CONNECT_IND: AdvA is the second address. RxAdd is header bit 7.
_ADV_A_AT_6 = (0x03, 0x05)


def parse_bin_frame(buf):
    """Return (frame, consumed). frame is None with consumed=0 when more bytes are needed,
    or None with consumed>0 when bytes must be dropped to resync."""
    if len(buf) < 2:
        return None, 0
    magic = struct.unpack_from("<H", buf, 0)[0]
    if magic == SNIFFER_BIN_MAGIC:
        if len(buf) < BIN_HDR_SIZE:
            return None, 0
        _m, pkt_type, flags, ch, rssi, p_len, seq, ts_us, aa, pdu_hdr, cte_info = \
            struct.unpack_from(BIN_HDR_FORMAT, buf, 0)
        hdr_size = BIN_HDR_SIZE
    elif magic == SNIFFER_BIN_MAGIC_V1:
        if len(buf) < BIN_HDR_V1_SIZE:
            return None, 0
        _m, pkt_type, flags, ch, rssi, p_len, ts_us, aa, pdu_hdr, _r = \
            struct.unpack_from(BIN_HDR_V1_FORMAT, buf, 0)
        seq, cte_info, hdr_size = None, 0, BIN_HDR_V1_SIZE
    else:
        return None, 1
    if p_len > 260 or pkt_type > MAX_PKT_TYPE or ch > 39:
        return None, 1
    # PCAP seconds are uint32. A torn USB read can look like a header whose
    # timestamp does not fit; drop one byte and resync instead of aborting.
    if ts_us // 1000000 > 0xFFFFFFFF:
        return None, 1
    if len(buf) < hdr_size + p_len:
        return None, 0
    frame = dict(pkt_type=pkt_type, flags=flags, ch=ch, rssi=rssi, seq=seq, ts_us=ts_us,
                 aa=aa, pdu_hdr=pdu_hdr, cte_info=cte_info,
                 payload=bytes(buf[hdr_size:hdr_size + p_len]))
    return frame, hdr_size + p_len


def build_ll_body(frame):
    """DLT 256 body: AA [+ CI] + header(2) [+ CTEInfo] + payload + CRC(3)."""
    body = struct.pack("<I", frame["aa"])
    if (frame["flags"] & 0x0C) == 0x08:
        # Wireshark expects the Coding Indicator on LE Coded; firmware doesn't report it, assume S=8
        body += b"\x00"
    body += struct.pack("<BB", frame["pdu_hdr"], len(frame["payload"]))
    if frame["flags"] & FLAG_CTE:
        body += struct.pack("<B", frame["cte_info"])
    return body + frame["payload"] + b"\x00\x00\x00"

def ble_ch_to_rf_ch(ble_ch):
    """Convert Bluetooth Low Energy logical channel index (0-39) to RF physical channel index (0-39)."""
    if ble_ch == 37:
        return 0
    elif 0 <= ble_ch <= 10:
        return ble_ch + 1
    elif ble_ch == 38:
        return 12
    elif 11 <= ble_ch <= 36:
        return ble_ch + 2
    elif ble_ch == 39:
        return 39
    return ble_ch & 0xFF

def build_ble_pseudo_header(ble_channel, rssi, pkt_type=1, access_address=0x8E89BED6, crc_ok=True, phy=1, direction=None, is_decrypted=False):
    rf_channel = ble_ch_to_rf_ch(ble_channel)
    if isinstance(rssi, int):
        signal_power = max(-128, min(127, rssi))
    else:
        signal_power = 127
    noise_power = 127
    aa_offenses = 0
    ref_aa = access_address

    flags = 0x0001 | 0x0002 | 0x0010 | 0x0400
    if crc_ok:
        flags |= 0x0800
    if is_decrypted:
        flags |= 0x0008

    # Set PHY (bits 14..15)
    if phy == 2:
        flags |= (1 << 14) # LE 2M
    elif phy == 3:
        flags |= (2 << 14) # LE Coded

    # Set PDU Type (bits 7..9)
    if pkt_type in (1, 6, 11): # SNIFFER_TYPE_ADV / AUX / ADV_DECISION
        flags |= (1 << 7)
    elif pkt_type == 3: # SNIFFER_TYPE_ISO_CIS
        flags |= (4 << 7) if direction == "M2S" else (5 << 7)
    elif pkt_type == 4: # SNIFFER_TYPE_ISO_BIS
        flags |= (6 << 7)
    elif pkt_type in (2, 5, 8, 9, 10): # SNIFFER_TYPE_CONN / DECRYPTED / CS / FRAME_SPACE / CONN_RATE
        flags |= (2 << 7) if direction == "M2S" else (3 << 7)
    else:
        # Legacy ADV / CONNECT_IND / Default (0x0000)
        flags |= (0 << 7)

    header = struct.pack("<BbBBIH", rf_channel, signal_power, noise_power, aa_offenses, ref_aa, flags)
    return header

def write_pcap_global_header(stream):
    # Magic: 0xa1b2c3d4 (microsecond PCAP), Major: 2, Minor: 4, DLT: 256
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
    stream.write(hdr)
    stream.flush()

class CaptureStopped(Exception):
    """Wireshark closed the extcap fifo. This is a normal stop, not a fault."""


def _pipe_closed(exc):
    winerror = getattr(exc, "winerror", None)
    # 109 ERROR_BROKEN_PIPE, 232 ERROR_NO_DATA (pipe closing). 22/32 are EPIPE/EINVAL.
    return isinstance(exc, (BrokenPipeError, OSError)) and (
        exc.errno in (22, 32) or winerror in (109, 232))


class HostTimebase:
    """Map the device uptime onto the computer clock.

    The firmware timestamp counts microseconds since boot. Nordic's extcap
    anchors the first packet at time.time() and keeps later packets spaced by
    the firmware delta, so Wireshark shows the capture in local time.
    """

    def __init__(self):
        self.origin_host = None
        self.origin_dev = None
        self.last_dev = None

    def map(self, dev_us):
        if self.origin_host is None or (
                self.last_dev is not None and dev_us + 1000000 < self.last_dev):
            self.origin_host = int(time.time() * 1000000)
            self.origin_dev = dev_us
        self.last_dev = dev_us
        return self.origin_host + (dev_us - self.origin_dev)


def write_pcap_packet(stream, ts_us, raw_packet, flush=True):
    """Write one DLT 256 record. flush=False lets the caller batch pipe flushes."""
    ts_us = int(ts_us)
    if ts_us < 0:
        ts_us = 0
    ts_sec = ts_us // 1000000
    ts_usec = ts_us % 1000000
    if ts_sec > 0xFFFFFFFF:
        ts_sec = 0xFFFFFFFF
        ts_usec = 999999
    pkt_len = len(raw_packet)
    hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
    try:
        stream.write(hdr)
        stream.write(raw_packet)
        if flush:
            stream.flush()
    except OSError as exc:
        if _pipe_closed(exc):
            raise CaptureStopped from exc
        raise
    return True

def _extcap_text(text):
    return str(text).replace("{", "").replace("}", "")


def extcap_interfaces():
    # control=1 tells Wireshark to open the toolbar pipes. Without it the
    # Device selector is created but stays disabled.
    print(f"extcap {{version={EXTCAP_VERSION}}}{{display=Bbo BLE Sniffer}}"
          f"{{help=https://www.nordicsemi.com}}{{control=1}}")
    try:
        ports = find_usb_ports()
    except Exception as exc:
        sys.stderr.write(f"[BLE_SNIFFER_EXTCAP] {exc}\n")
        ports = []
    for port in ports:
        # Port name only. The Windows description is localized and breaks the extcap line.
        print("interface {value=%s}{display=Bbo BLE Sniffer %s}{control=1}"
              % (_extcap_text(port.device), _extcap_text(port.device)))
    print("control {number=%d}{type=selector}{display=Device}"
          "{tooltip=Advertisers heard since capture started. Pick one to follow it.}"
          % CTRL_ARG_DEVICE)
    print("control {number=%d}{type=selector}{display=Key}"
          "{tooltip=Which key Value is. Applied when Value is submitted.}"
          % CTRL_ARG_KEY)
    print("control {number=%d}{type=string}{display=Value}"
          "{tooltip=LTK / IRK: 32 hex digits, HCI byte order. "
          "Broadcast Code: 32 hex digits, or 1 to 16 text bytes. "
          "Press Enter to send it during capture.}"
          "{placeholder=32 hex digits or broadcast code}"
          % CTRL_ARG_VALUE)
    print("control {number=%d}{type=string}{display=RSSI}"
          "{tooltip=Minimum RSSI in dBm for the Device list, for example -70. "
          "Weaker advertisers are not listed; captured packets are not filtered. Empty disables it. "
          "A capture filter rssi >= -70 does the same.}"
          % CTRL_ARG_RSSI)
    print("control {number=%d}{type=button}{display=Clear}"
          "{tooltip=Clear the device list and follow every advertiser again}"
          % CTRL_ARG_CLEAR)
    print("control {number=%d}{type=button}{role=logger}{display=Log}"
          "{tooltip=Capture log (sequence gaps, USB status). Avoids stderr extcap errors.}"
          % CTRL_ARG_LOG)
    print("value {control=%d}{value=%s}{display=All advertising devices}{default=true}"
          % (CTRL_ARG_DEVICE, DEVICE_ALL))
    print("value {control=%d}{value=%s}{display=Long Term Key}{default=true}"
          % (CTRL_ARG_KEY, KEY_LTK))
    # print("value {control=%d}{value=%s}{display=Identity Resolving Key}"
    #       % (CTRL_ARG_KEY, KEY_IRK))
    print("value {control=%d}{value=%s}{display=Broadcast Code}"
          % (CTRL_ARG_KEY, KEY_BCODE))
    _print_dlt()


def extcap_dlts(interface):
    if interface:
        _print_dlt()


def _print_dlt():
    print(f"dlt {{number={DLT_BLUETOOTH_LE_LL_WITH_PHDR}}}"
          f"{{name=LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR}}"
          f"{{display=Bluetooth Low Energy with pseudo-header}}")

def normalize_mac(text):
    """AA:BB:CC:DD:EE:FF, with ':' or '-', or 12 hex digits. None if invalid."""
    hexpart = re.sub(r"[:\-\s]", "", text.strip())
    if len(hexpart) != 12 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
        return None
    return ":".join(hexpart[i:i + 2].upper() for i in range(0, 12, 2))


def mac_from_air(raw):
    """On-air AdvA is LSB first. The firmware addr command wants display order."""
    return ":".join(f"{b:02X}" for b in reversed(raw))


def ad_local_name(data):
    """Broadcast Name (0x30), otherwise Complete Local Name (0x09), otherwise Shortened (0x08)."""
    broadcast = complete = shortened = None
    i = 0
    while i + 1 < len(data):
        length = data[i]
        if length == 0 or i + 1 + length > len(data):
            break
        ad_type = data[i + 1]
        value = data[i + 2:i + 1 + length]
        text = value.decode("utf-8", "replace").strip("\x00").strip()
        if ad_type == 0x30 and broadcast is None:
            broadcast = text
        elif ad_type == 0x09 and complete is None:
            complete = text
        elif ad_type == 0x08 and shortened is None:
            shortened = text
        i += 1 + length
    return broadcast or complete or shortened


# SNIFFER_TYPE_ADV / AUX / CONNECT_IND / ADV_DECISION
_ADV_PKT_TYPES = (1, 6, 7, 11)


def is_adv_frame(frame):
    return frame["pkt_type"] in _ADV_PKT_TYPES or frame["ch"] >= 37


def advertiser_from_frame(frame):
    """(display MAC, local name or None) for an advertising PDU, else None."""
    # A data PDU header (LLID/NESN/SN) has the same low bits as ADV PDU types.
    if not is_adv_frame(frame):
        return None
    payload = frame["payload"]
    pdu = frame["pdu_hdr"] & 0x0F
    if pdu in _ADV_A_AT_0 and len(payload) >= 6:
        return mac_from_air(payload[:6]), ad_local_name(payload[6:])
    if pdu in _ADV_A_AT_6 and len(payload) >= 12:
        return mac_from_air(payload[6:12]), None
    if pdu in (0x07, 0x09) and len(payload) >= 2:
        hdr_len = payload[0] & 0x3F
        if hdr_len == 0 or len(payload) < 1 + hdr_len:
            return None
        flags = payload[1]
        if flags & 0x01 and 2 + 6 <= 1 + hdr_len:
            return mac_from_air(payload[2:8]), ad_local_name(payload[1 + hdr_len:])
    return None


def parse_rssi_limit(text):
    """Inclusive minimum dBm, None if the filter is off, or 'invalid'."""
    text = (text or "").strip()
    if not text:
        return None
    match = re.fullmatch(r"(?:rssi\s*>=?\s*)?(-?\d+)", text, flags=re.IGNORECASE)
    if match is None:
        return "invalid"
    value = int(match.group(1))
    if value < -128 or value > 20:
        return "invalid"
    return value


def parse_capture_rssi(capture_filter):
    """Nordic capture-filter form: rssi >= -70. None when the filter is empty or absent."""
    text = (capture_filter or "").strip()
    if not text:
        return None
    match = re.fullmatch(r"rssi\s*(>=?)\s*(-?\d+)", text, flags=re.IGNORECASE)
    if match is None:
        sys.stderr.write("[BLE_SNIFFER_EXTCAP] filter syntax: rssi >= -70\n")
        return None
    value = int(match.group(2))
    if match.group(1) == ">":
        value += 1
    if value < -128 or value > 20:
        sys.stderr.write("[BLE_SNIFFER_EXTCAP] RSSI must be from -128 to 20\n")
        return None
    return value


def is_rpa(mac):
    """True when the displayed MAC looks like a Resolvable Private Address (MSB 0b01)."""
    parts = (mac or "").strip().split(":")
    if len(parts) != 6:
        return False
    try:
        msb = int(parts[0], 16)
    except ValueError:
        return False
    return (msb & 0xC0) == 0x40


def filter_command(target_name, target_mac):
    """One firmware command, or None when Wireshark left both fields empty."""
    name = (target_name or "").strip()
    mac = (target_mac or "").strip()
    if mac:
        formatted = normalize_mac(mac)
        if formatted is None:
            sys.stderr.write("[BLE_SNIFFER_EXTCAP] invalid target address, expect AA:BB:CC:DD:EE:FF\n")
            return None
        return f"addr {formatted}\n"
    if name:
        if any(c in name for c in "\r\n") or len(name.encode("utf-8")) > SNIFFER_CMD_NAME_MAX:
            sys.stderr.write("[BLE_SNIFFER_EXTCAP] invalid target name\n")
            return None
        return f"name {name}\n"
    return None


def startup_filter_commands(target_name, target_mac):
    """Firmware filters for capture start.

    Name + RPA prefers name on the wire so address rotation stays visible.
    """
    name = (target_name or "").strip()
    mac = (target_mac or "").strip()
    formatted = normalize_mac(mac) if mac else None
    if mac and formatted is None:
        sys.stderr.write("[BLE_SNIFFER_EXTCAP] invalid target address, expect AA:BB:CC:DD:EE:FF\n")
        return []
    if formatted and name and is_rpa(formatted):
        command = filter_command(name, "")
        if command:
            return [command]
        return []
    command = filter_command(name, formatted or mac)
    return [command] if command else []


def _hex_key_command(prefix, key, label):
    """Firmware '<prefix> <32 hex>' line. Hex is HCI / LSO-first."""
    text = (key or "").strip()
    if not text:
        return None
    hexpart = re.sub(r"0x", "", text, flags=re.IGNORECASE)
    hexpart = re.sub(r"[:\-\s,]", "", hexpart)
    if len(hexpart) != 32 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
        sys.stderr.write(f"[BLE_SNIFFER_EXTCAP] invalid {label}, expect 32 hex digits\n")
        return None
    return f"{prefix} {hexpart.lower()}\n"


def ltk_command(ltk):
    return _hex_key_command("ltk", ltk, "LTK")


def irk_command(irk):
    return _hex_key_command("irk", irk, "IRK")


def bcode_command(code):
    """Firmware 'bcode' line. 32 hex digits, or an ASCII Broadcast Code of 1..16 bytes."""
    text = (code or "").strip()
    if not text:
        return None
    hexpart = re.sub(r"0x", "", text, flags=re.IGNORECASE)
    hexpart = re.sub(r"[:\-\s,]", "", hexpart)
    if len(hexpart) == 32 and all(c in "0123456789abcdefABCDEF" for c in hexpart):
        return f"bcode {hexpart.lower()}\n"
    raw = text.encode("utf-8")
    if 1 <= len(raw) <= 16 and b"\r" not in raw and b"\n" not in raw:
        return f"bcode {text}\n"
    sys.stderr.write("[BLE_SNIFFER_EXTCAP] invalid Broadcast Code, expect 32 hex digits or 1..16 text bytes\n")
    return None


def _load_serial():
    """pyserial from this interpreter, or the copy shipped in tool/pydeps.

    Wireshark starts extcap with its own Python, which often has no site packages.
    The old nRF sniffer expects that dependency beside the extcap script.
    """
    try:
        import serial
        from serial.tools import list_ports
        return serial, list_ports
    except ImportError:
        bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pydeps")
        if os.path.isdir(bundled) and bundled not in sys.path:
            sys.path.insert(0, bundled)
        try:
            import serial
            from serial.tools import list_ports
        except ImportError as e:
            raise RuntimeError(
                "USB CDC needs pyserial. Expected it in tool/pydeps next to this script") from e
        return serial, list_ports


def find_usb_ports():
    """COM ports of the sniffer CDC device, same role as UART.find_sniffer()."""
    _, list_ports = _load_serial()
    return [p for p in list_ports.comports() if (p.vid, p.pid) in USB_CDC_IDS]


def port_from_interface(interface):
    """Wireshark passes the interface value, which is the COM port name."""
    if not interface:
        return None
    name = interface.strip()
    # Older listings appended "-<version>" after the port name.
    head = name.split("-", 1)[0]
    if head.upper().startswith("COM") or head.startswith("/dev/"):
        return head
    return name


def open_usb_cdc(port=None, baud=1000000):
    """Open the sniffer CDC ACM port. Firmware waits in sniffer_uart_init() until DTR is set."""
    serial, _list_ports = _load_serial()

    if not port:
        matches = [p.device for p in find_usb_ports()]
        if len(matches) == 1:
            port = matches[0]
        elif not matches:
            raise RuntimeError("USB CDC port not found (VID:PID 2FE3:0001 or 1915:BB01)")
        else:
            raise RuntimeError("Multiple USB CDC ports: " + ", ".join(matches))

    # exclusive=True matches Nordic UART.py — avoid two processes on one CDC port.
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=0.05, exclusive=True)
    except TypeError:
        ser = serial.Serial(port, baudrate=baud, timeout=0.05)
    # Grow the host RX buffer so a brief Wireshark stall does not drop CDC data.
    try:
        ser.set_buffer_size(rx_size=1024 * 1024, tx_size=16 * 1024)
    except Exception:
        pass
    ser.dtr = True
    time.sleep(0.2)
    try:
        ser.reset_input_buffer()
    except Exception:
        pass
    return ser


def send_usb_down(ser, command):
    """Write one firmware command line on the CDC port."""
    payload = command.encode("utf-8")
    written = ser.write(payload)
    ser.flush()
    if written == len(payload):
        return True
    sys.stderr.write("[BLE_SNIFFER_EXTCAP] USB command write failed\n")
    return False


def extcap_config(interface):
    if not interface:
        return
    print("arg {number=0}{call=--target-name}{display=Target Device Name}{type=string}"
          "{tooltip=Optional BLE local name, sent on the USB CDC port (e.g. qqq). "
          "With an RPA address, name is preferred so the filter can follow address rotation.}")
    print("arg {number=1}{call=--target-mac}{display=Target Address}{type=string}"
          "{tooltip=Optional BLE address, sent on the USB CDC port (e.g. C0:11:22:33:44:55). "
          "If this is an RPA and a name is set, the script updates the addr filter when the RPA rotates.}")
    print("arg {number=2}{call=--ltk}{display=Long Term Key}{type=string}"
          "{tooltip=Optional 16-byte LTK in HCI byte order (32 hex digits). "
          "Sent when capture starts. The toolbar Key and Value fields can replace it later.}")
    # print("arg {number=3}{call=--irk}{display=Identity Resolving Key}{type=string}"
    #       "{tooltip=Optional 16-byte peer IRK in HCI byte order (32 hex digits). "
    #       "Resolves RPAs when the advertiser rotates its private address.}")
    print("arg {number=4}{call=--bcode}{display=Broadcast Code}{type=string}"
          "{tooltip=BIS Broadcast Code. 32 hex digits, or a text code of 1..16 bytes (zero-padded). "
          "Sent when capture starts. The toolbar can replace it later.}")

class CaptureUi:
    """Toolbar device list (RSSI gated) and firmware filter commands. Frames are not filtered here."""

    def __init__(self, ser, ctrl_out, rssi_min):
        self.ser = ser
        self.ctrl_out = ctrl_out
        self.rssi_min = rssi_min
        self.follow_mac = None
        self.follow_name = None
        self.key_type = KEY_LTK
        self._devices = {}
        self._device_seen = {}
        self._rpa_rediscovering = False
        self._rpa_frozen = False
        self._last_rpa_check = 0.0
        self._rpa_switch_at = 0.0
        self._links = {}
        self._link_hold = False
        self._device_select_armed = False
        self._active = True
        self._ready = False
        self._lock = threading.Lock()
        self._state = threading.Lock()

    def note_connection(self, frame):
        """Pause RPA follow while this connection is up. Resume after it ends."""
        started, ended = self._track_link(frame)
        if started:
            self.log("connection traffic seen; RPA follow paused")
        elif ended:
            self.log("connection ended; RPA follow resumed")

    def _supervision_us(self, timeout_units):
        if not timeout_units:
            return UNKNOWN_SUP_US
        units = min(max(int(timeout_units), SUP_TIMEOUT_MIN), SUP_TIMEOUT_MAX)
        return units * 10_000

    def _links_up_locked(self, now):
        """True when any recorded connection is still inside its supervision window."""
        up = False
        for link in self._links.values():
            if link["down"]:
                continue
            last = link["last_mono"]
            sup = link["sup_us"] or UNKNOWN_SUP_US
            if last is not None and now - last > sup / 1_000_000.0:
                link["down"] = True
                continue
            up = True
        return up

    def _rpa_pause_locked(self, now):
        """Caller holds _state. (paused, just_paused, just_resumed)."""
        if self._rpa_frozen:
            return True, False, False
        up = self._links_up_locked(now)
        if up and self.follow_mac:
            # Keep the followed RPA fresh so a live link is not treated as rotation.
            self._device_seen[self.follow_mac] = now
        just_paused = up and not self._link_hold
        just_resumed = (not up) and self._link_hold
        self._link_hold = up
        if just_paused:
            self._rpa_rediscovering = False
        return up, just_paused, just_resumed

    def _track_link(self, frame):
        """Update connection lifetime. Returns (just_paused, just_resumed)."""
        pkt_type = frame.get("pkt_type")
        ch = frame.get("ch", 39)
        payload = frame.get("payload") or b""
        crc_ok = bool(frame.get("flags", 0) & 0x01)
        now = time.monotonic()
        with self._state:
            if not self._active:
                return False, False
            # Only the firmware CONNECT_IND type. A data PDU header can also
            # have low nibble 0x05 (LLID + SN) and must not be parsed as one.
            if pkt_type == 7 and crc_ok and len(payload) >= 34:
                aa = struct.unpack_from("<I", payload, 12)[0]
                _interval, _latency, timeout = struct.unpack_from("<HHH", payload, 22)
                peer = mac_from_air(payload[6:12])
                link = self._links.get(aa)
                if link is None or link["down"]:
                    self._links[aa] = {
                        "peer": peer,
                        "sup_us": self._supervision_us(timeout),
                        "last_mono": now,
                        "down": False,
                    }
                else:
                    link["peer"] = peer or link["peer"]
                    link["sup_us"] = self._supervision_us(timeout)
                    link["last_mono"] = now
                    link["down"] = False
                _paused, started, ended = self._rpa_pause_locked(now)
                return started, ended
            is_conn = pkt_type in (2, 5, 8, 9, 10) or (
                pkt_type not in (1, 6, 7, 11) and ch < 37)
            if not is_conn:
                _paused, started, ended = self._rpa_pause_locked(now)
                return started, ended
            aa = frame.get("aa")
            if aa in (None, ADV_ACCESS_ADDRESS):
                _paused, started, ended = self._rpa_pause_locked(now)
                return started, ended
            link = self._links.get(aa)
            if link is None or link["down"]:
                # ISO/CS alone must not invent a link that pauses RPA follow.
                if pkt_type not in (2, 5):
                    _paused, started, ended = self._rpa_pause_locked(now)
                    return started, ended
                if not crc_ok and link is None:
                    _paused, started, ended = self._rpa_pause_locked(now)
                    return started, ended
                link = self._links[aa] = {
                    "peer": "",
                    "sup_us": UNKNOWN_SUP_US,
                    "last_mono": now,
                    "down": False,
                }
            link["last_mono"] = now
            link["down"] = False
            if crc_ok and (frame.get("pdu_hdr", 0) & 0x03) == 0x03 and payload:
                opcode = payload[0]
                if opcode == LL_TERMINATE_IND:
                    link["down"] = True
                elif opcode == LL_CONNECTION_UPDATE_IND and len(payload) >= 10:
                    _interval, _latency, timeout = struct.unpack_from("<HHH", payload, 4)
                    link["sup_us"] = self._supervision_us(timeout)
            _paused, started, ended = self._rpa_pause_locked(now)
            return started, ended

    def send(self, command):
        with self._lock:
            if self.ser is not None:
                send_usb_down(self.ser, command)

    def control_write(self, arg, typ, message):
        if self.ctrl_out is None:
            return
        payload = message.encode("utf-8")
        packet = struct.pack(">BBHBB", ord("T"), 0, len(payload) + 2, arg, typ) + payload
        with self._lock:
            try:
                self.ctrl_out.write(packet)
                self.ctrl_out.flush()
            except OSError:
                self.ctrl_out = None

    def log(self, message, level="info"):
        """Send a line to the toolbar Log (Nordic-style). Avoid stderr during capture."""
        text = (message or "").strip()
        if not text:
            return
        if self.ctrl_out is not None:
            if level == "error":
                self.control_write(CTRL_ARG_NONE, CTRL_CMD_ERROR_MSG, text)
            elif level == "warn":
                self.control_write(CTRL_ARG_NONE, CTRL_CMD_WARN_MSG, text)
            else:
                self.control_write(CTRL_ARG_LOG, CTRL_CMD_ADD, text)
            return
        # No toolbar pipe yet (interfaces listing / early failure).
        try:
            sys.stderr.write(text + "\n")
        except Exception:
            pass

    def configure_follow(self, target_name, target_mac):
        """Remember name/address filters used for RPA follow across the capture."""
        name = (target_name or "").strip() or None
        mac = normalize_mac(target_mac) if (target_mac or "").strip() else None
        with self._state:
            self.follow_name = name
            self.follow_mac = mac
            self._rpa_rediscovering = False
            self._rpa_frozen = False
            self._rpa_switch_at = 0.0
            self._links.clear()
            self._link_hold = False

    def stop_follow(self):
        """Capture is ending; do not send more RPA follow commands."""
        with self._state:
            self._active = False
            self._rpa_frozen = True

    def _live_same_name_rpas(self, name, now, exclude=None):
        """RPAs with this local name seen recently (held under _state)."""
        live = []
        for mac, info in self._devices.items():
            if info[0] != name or not is_rpa(mac):
                continue
            if exclude is not None and mac == exclude:
                continue
            last = self._device_seen.get(mac)
            if last is not None and now - last <= RPA_LIVE_SEC:
                live.append(mac)
        return live

    def note_advertiser(self, frame):
        if not self._active:
            return
        if not (frame["flags"] & 0x01):
            return
        if self.rssi_min is not None and frame["rssi"] < self.rssi_min:
            return
        found = advertiser_from_frame(frame)
        if found is None:
            return
        mac, name = found
        now = time.monotonic()
        rotated = None
        publish = False
        previous = None
        shown_name = ""
        just_paused = False
        just_resumed = False
        with self._state:
            if not self._active:
                return
            # SCAN_REQ / CONNECT_IND carry the target in AdvA. Only an
            # advertisement from the peer means that connection is over.
            pdu = frame["pdu_hdr"] & 0x0F
            if frame["pkt_type"] != 7 and pdu not in _ADV_A_AT_6:
                for link in self._links.values():
                    if link["peer"] and link["peer"] == mac:
                        link["down"] = True
            self._device_seen[mac] = now
            previous = self._devices.get(mac)
            shown_name = name or (previous[0] if previous else "")
            if shown_name:
                self._devices[mac] = (shown_name, frame["rssi"] if previous is None else previous[1])
            follow_name = self.follow_name
            follow_mac = self.follow_mac
            rpa_paused, just_paused, just_resumed = self._rpa_pause_locked(now)
            if (
                not rpa_paused
                and follow_name
                and follow_mac
                and shown_name == follow_name
                and mac != follow_mac
                and is_rpa(follow_mac)
                and is_rpa(mac)
                and now - self._rpa_switch_at >= RPA_COOLDOWN_SEC
            ):
                last = self._device_seen.get(follow_mac)
                if last is not None and now - last >= RPA_STALE_SEC:
                    # Only follow when this is the sole live same-name RPA.
                    # Avoid hopping across multiple devices that share a name.
                    live = self._live_same_name_rpas(follow_name, now, exclude=follow_mac)
                    if live == [mac]:
                        rotated = (follow_mac, mac)
                        self.follow_mac = mac
                        self._rpa_switch_at = now
                        self._rpa_rediscovering = False
            quiet = (
                previous is not None
                and shown_name == previous[0]
                and abs(previous[1] - frame["rssi"]) < 10
            )
            if not quiet:
                self._devices[mac] = (shown_name, frame["rssi"])
                publish = True
        if publish:
            # Toolbar updates go over another pipe; rate-limit so they cannot stall USB.
            last_pub = getattr(self, "_last_toolbar_pub", 0.0)
            if now - last_pub >= 0.2 or previous is None:
                self._last_toolbar_pub = now
                label = shown_name if shown_name else mac
                display = "%s  %d dBm  %s" % (extcap_label(label), frame["rssi"], mac)
                self._publish(mac, display, previous is not None)
        if just_paused:
            self.log("connection traffic seen; RPA follow paused")
        elif just_resumed:
            self.log("connection ended; RPA follow resumed")
        if rotated is not None:
            self._apply_rpa_follow(rotated[0], rotated[1], shown_name)

    def _apply_rpa_follow(self, old_mac, new_mac, shown_name):
        """Old filtered RPA went quiet; lock onto the new address and push addr."""
        with self._state:
            if not self._active:
                return
            self.follow_mac = new_mac
            self._rpa_rediscovering = False
            name = self.follow_name or shown_name or None
            if name and not self.follow_name:
                self.follow_name = name
            info = self._devices.get(new_mac)
            rssi = info[1] if info else 0
            label = (info[0] if info and info[0] else None) or name or new_mac
        display = "%s  %d dBm  %s" % (extcap_label(label), rssi, new_mac)
        self._publish(new_mac, display, True)
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, new_mac)
        # Addr-only: name filter would keep every same-name peer visible and thrash.
        self.send("addr %s\n" % new_mac)

    def check_rpa_stale(self):
        """If the filtered RPA went quiet, fall back to name filter to rediscover it.

        Skip while a connection is up: advertising stops on purpose and a name
        rediscover would leave the link. Resume after the connection ends.
        """
        if not self._active:
            return
        now = time.monotonic()
        if now - self._last_rpa_check < 1.0:
            return
        self._last_rpa_check = now
        stale_name = None
        with self._state:
            if not self._active:
                return
            paused, just_paused, just_resumed = self._rpa_pause_locked(now)
            if (
                not paused
                and not self._rpa_rediscovering
                and now - self._rpa_switch_at >= RPA_COOLDOWN_SEC
            ):
                name = self.follow_name
                addr = self.follow_mac
                last = self._device_seen.get(addr) if addr else None
                if name and addr and is_rpa(addr) and last is not None and now - last >= RPA_STALE_SEC:
                    self._rpa_rediscovering = True
                    stale_name = name
        if just_paused:
            self.log("connection traffic seen; RPA follow paused")
        elif just_resumed:
            self.log("connection ended; RPA follow resumed")
        if not stale_name:
            return
        command = filter_command(stale_name, "")
        if not command:
            self._rpa_rediscovering = False
            return
        self.log("RPA quiet; rediscover by name (%s)" % stale_name)
        self.send(command)

    def _publish(self, mac, display, replace):
        if replace:
            self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_REMOVE, mac)
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD, mac + "\0" + display)
        with self._state:
            followed = self.follow_mac == mac
        if followed:
            self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, mac)

    def reset_device_selector(self):
        """Show the unselected device entry. Does not change the firmware filter."""
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_REMOVE, "")
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD,
                           DEVICE_ALL + "\0" + "All advertising devices")
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, DEVICE_ALL)

    def toolbar_ready(self):
        with self._state:
            if self._ready:
                return
            self._ready = True
        for arg in (CTRL_ARG_DEVICE, CTRL_ARG_KEY, CTRL_ARG_VALUE, CTRL_ARG_RSSI,
                    CTRL_ARG_CLEAR, CTRL_ARG_LOG):
            self.control_write(arg, CTRL_CMD_ENABLE, "")
        self.reset_device_selector()

    def follow_all(self):
        with self._state:
            self.follow_mac = None
            self.follow_name = None
            self._rpa_frozen = False
            self._rpa_rediscovering = False
            self._devices.clear()
            self._device_seen.clear()
            self._links.clear()
            self._link_hold = False
            self._rpa_rediscovering = False
            self._rpa_switch_at = 0.0
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_REMOVE, "")
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD,
                           DEVICE_ALL + "\0" + "All advertising devices")
        self.control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, DEVICE_ALL)
        self.send("clear\n")

    def follow(self, mac):
        with self._state:
            self.follow_mac = mac
            info = self._devices.get(mac)
            if info and info[0]:
                self.follow_name = info[0]
            self._rpa_rediscovering = False
            self._rpa_switch_at = time.monotonic()
        self.send("addr %s\n" % mac)

    def set_key_type(self, text):
        if text in (KEY_LTK, KEY_BCODE):
            with self._state:
                self.key_type = text

    def apply_key_value(self, text):
        with self._state:
            key_type = self.key_type
        if key_type == KEY_BCODE:
            command = bcode_command(text)
            what = "Broadcast Code: 32 hex digits, or 1..16 text bytes"
        elif key_type == KEY_IRK:
            command = irk_command(text)
            what = "IRK: 32 hex digits"
        else:
            command = ltk_command(text)
            what = "LTK: 32 hex digits"
        if command is None:
            self.control_write(CTRL_ARG_NONE, CTRL_CMD_ERROR_MSG, "Invalid " + what)
            return
        self.send(command)

    def show_key(self, key_type, text):
        self.set_key_type(key_type)
        self.control_write(CTRL_ARG_KEY, CTRL_CMD_SET, key_type)
        self.control_write(CTRL_ARG_VALUE, CTRL_CMD_SET, text)

    def set_rssi(self, text):
        limit = parse_rssi_limit(text)
        if limit == "invalid":
            self.control_write(CTRL_ARG_NONE, CTRL_CMD_ERROR_MSG,
                               "RSSI must be an integer from -128 to 20, or empty")
            return
        with self._state:
            self.rssi_min = limit

    def on_control(self, arg, typ, payload):
        if typ == CTRL_CMD_INIT:
            self.toolbar_ready()
            # Wireshark restores the previous Device choice before this message.
            # Put the selector back to All advertising devices for this capture.
            self.reset_device_selector()
            with self._state:
                self._device_select_armed = True
        if typ not in (CTRL_CMD_INIT, CTRL_CMD_SET):
            return
        text = payload.decode("utf-8", "replace").strip("\x00")
        if arg == CTRL_ARG_DEVICE:
            mac = normalize_mac(text)
            with self._state:
                armed = self._device_select_armed
            if not armed:
                return
            if mac:
                self.follow(mac)
            elif text in ("", DEVICE_ALL) and typ == CTRL_CMD_SET:
                self.follow_all()
        elif arg == CTRL_ARG_KEY and text:
            self.set_key_type(text)
        elif arg == CTRL_ARG_VALUE and typ == CTRL_CMD_SET and text:
            self.apply_key_value(text)
        elif arg == CTRL_ARG_RSSI and (typ == CTRL_CMD_SET or text):
            self.set_rssi(text)
        elif arg == CTRL_ARG_CLEAR and typ == CTRL_CMD_SET:
            self.follow_all()


def extcap_label(text):
    cleaned = "".join(ch for ch in text if ch.isprintable() and ch not in "{}\x00")
    return cleaned[:40] or "device"


def control_read(pipe):
    """One toolbar message, or (None, None, None) when Wireshark closed the pipe."""
    header = pipe.read(6)
    if len(header) < 6:
        return None, None, None
    _sync, _version, length, arg, typ = struct.unpack(">BBHBB", header)
    payload = b""
    remain = max(0, length - 2)
    while len(payload) < remain:
        chunk = pipe.read(remain - len(payload))
        if not chunk:
            return None, None, None
        payload += chunk
    return arg, typ, payload


def control_loop(pipe, ui, stop):
    try:
        while not stop.is_set():
            arg, typ, payload = control_read(pipe)
            if arg is None:
                break
            ui.on_control(arg, typ, payload)
    except OSError:
        pass


# Flush the Wireshark pipe at most this often while draining a USB chunk.
_PCAP_FLUSH_EVERY = 64


def emit_pcap_frames(fifo_out, recv_buf, clock, ui, seq_state):
    """Write every complete frame in recv_buf. Leave a partial frame in the buffer.

    Resync matches AuTerm live_pcap/iter_frames: never wipe a trailing partial
    frame when the next magic is not in the buffer yet.

    Batches fifo flushes — per-packet flush to the Wireshark named pipe blocks the
    USB reader and is the main cause of realtime ATT loss vs offline file capture.
    """
    written = 0
    while True:
        frame, consumed = parse_bin_frame(recv_buf)
        if frame is None:
            if consumed == 0:
                break
            idx = min((i for i in (recv_buf.find(struct.pack("<H", m), 1)
                                   for m in (SNIFFER_BIN_MAGIC, SNIFFER_BIN_MAGIC_V1))
                       if i != -1), default=-1)
            # Keep the last byte when no magic is found so a split 0x53BF can complete.
            del recv_buf[:idx if idx != -1 else max(len(recv_buf) - 1, 0)]
            continue
        del recv_buf[:consumed]

        seq = frame.get("seq")
        if seq is not None:
            last_seq = seq_state[0]
            if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                seq_state[1] += (seq - last_seq - 1) & 0xFFFF
            seq_state[0] = seq

        ui.note_advertiser(frame)
        ui.note_connection(frame)

        pkt_type, flags, ch = frame["pkt_type"], frame["flags"], frame["ch"]
        is_adv = is_adv_frame(frame)
        direction = None if is_adv else ("M2S" if (flags & 0x02) else "S2M")
        crc_ok = bool(flags & 0x01)
        phy = ((flags >> 2) & 0x03) + 1
        is_decrypted = bool(flags & 0x10)
        # Periodic AUX_SYNC_IND carries its own AA; only primary channels force the adv AA
        if ch >= 37:
            frame["aa"] = 0x8E89BED6

        try:
            phdr = build_ble_pseudo_header(ch, frame["rssi"], pkt_type=pkt_type, access_address=frame["aa"], crc_ok=crc_ok, phy=phy, direction=direction, is_decrypted=is_decrypted)
            written += 1
            write_pcap_packet(
                fifo_out, clock.map(frame["ts_us"]), phdr + build_ll_body(frame),
                flush=(written % _PCAP_FLUSH_EVERY == 0))
        except struct.error:
            # One bad frame must not tear down the capture session.
            continue
    if written:
        try:
            fifo_out.flush()
        except OSError as exc:
            if _pipe_closed(exc):
                raise CaptureStopped from exc
            raise

def _open_pipe(path, mode):
    if not path:
        return None
    try:
        return open(path, mode, buffering=0)
    except OSError as exc:
        sys.stderr.write(f"[BLE_SNIFFER_EXTCAP] control pipe open failed ({exc})\n")
        return None


def capture_stream(fifo_path, port, target_mac=None, target_name=None, ltk=None, irk=None,
                   bcode=None, control_in=None, control_out=None, capture_filter=None):
    fifo_out = open(fifo_path, "wb")
    write_pcap_global_header(fifo_out)
    try:
        ser = open_usb_cdc(port)
    except Exception as exc:
        sys.stderr.write(f"[BLE_SNIFFER_EXTCAP] USB CDC open failed ({exc})\n")
        fifo_out.close()
        return
    # Open the pipe Wireshark reads before the pipe we read. On Windows the
    # second open can block if this order is reversed, and the toolbar never
    # receives Enable or device names.
    ctrl_out = _open_pipe(control_out, "wb")
    ctrl_in = _open_pipe(control_in, "rb")
    ui = CaptureUi(ser, ctrl_out, parse_capture_rssi(capture_filter))
    ui.configure_follow(target_name, target_mac)
    stop = threading.Event()
    ctrl_thread = None
    if ctrl_in is not None:
        ctrl_thread = threading.Thread(target=control_loop, args=(ctrl_in, ui, stop), daemon=True)
        ctrl_thread.start()
    if ctrl_out is not None:
        ui.toolbar_ready()
    seq_state = [None, 0]
    try:
        filters = startup_filter_commands(target_name, target_mac)
        if not filters:
            # stop does not clear the firmware target. Drop the previous filter
            # before capture starts when this session set neither name nor address.
            ui.send("clear\n")
            ui.log("no name or address filter; cleared previous target")
        ui.send("start\n")
        for command in filters:
            ui.send(command)
        for command in (ltk_command(ltk), irk_command(irk), bcode_command(bcode)):
            if command:
                ui.send(command)
        if ltk_command(ltk):
            ui.show_key(KEY_LTK, ltk.strip())
        elif irk_command(irk):
            ui.show_key(KEY_IRK, irk.strip())
        elif bcode_command(bcode):
            ui.show_key(KEY_BCODE, bcode.strip())
        if ui.rssi_min is not None:
            ui.control_write(CTRL_ARG_RSSI, CTRL_CMD_SET, str(ui.rssi_min))
        recv_buf = bytearray()
        clock = HostTimebase()
        # Dedicated USB reader: Wireshark pipe flush must never stop CDC reads.
        # Unbounded: dropping a USB chunk loses frames and tears the byte stream.
        usb_q = queue.Queue()
        usb_err = []

        def _usb_reader():
            # Nordic UART._read_worker: drain whatever is waiting, never block on Wireshark.
            try:
                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass
                while not stop.is_set():
                    try:
                        waiting = getattr(ser, "in_waiting", None)
                        n = waiting() if callable(waiting) else waiting
                        raw_read = ser.read(n or 1)
                    except Exception as exc:
                        usb_err.append(exc)
                        break
                    if raw_read:
                        usb_q.put(raw_read)
            finally:
                try:
                    usb_q.put(None, timeout=0.1)
                except Exception:
                    pass

        reader = threading.Thread(target=_usb_reader, name="ble-usb-reader", daemon=True)
        reader.start()
        try:
            while True:
                try:
                    chunk = usb_q.get(timeout=0.05)
                except queue.Empty:
                    ui.check_rpa_stale()
                    if usb_err:
                        break
                    if not reader.is_alive() and usb_q.empty():
                        break
                    continue
                if chunk is None:
                    break
                recv_buf.extend(chunk)
                # Collapse queued USB chunks before talking to Wireshark.
                while True:
                    try:
                        more = usb_q.get_nowait()
                    except queue.Empty:
                        break
                    if more is None:
                        try:
                            emit_pcap_frames(fifo_out, recv_buf, clock, ui, seq_state)
                        except CaptureStopped:
                            pass
                        chunk = None
                        break
                    recv_buf.extend(more)
                if chunk is None:
                    break
                try:
                    emit_pcap_frames(fifo_out, recv_buf, clock, ui, seq_state)
                except CaptureStopped:
                    break
                ui.check_rpa_stale()
            if usb_err and not isinstance(usb_err[0], CaptureStopped):
                exc = usb_err[0]
                if not (isinstance(exc, OSError) and _pipe_closed(exc)):
                    ui.log("USB read failed: %s" % usb_err[0], level="error")
        finally:
            stop.set()
            reader.join(timeout=1.0)
    finally:
        lost = seq_state[1] if seq_state[0] is not None or seq_state[1] else 0
        if lost:
            # Toolbar Log / warn dialog — not stderr (Nordic avoids extcap pipe errors).
            ui.log("%d sniffer frame(s) missing by sequence" % lost, level="warn")
        ui.stop_follow()
        stop.set()
        if ctrl_in is not None:
            try:
                ctrl_in.close()
            except OSError:
                pass
        if ctrl_thread is not None:
            ctrl_thread.join(timeout=0.5)
        try:
            ui.send("stop\n")
            # Main loop polls commands every 50 ms. Leave the port open until stop is read.
            time.sleep(0.15)
        except OSError:
            pass
        try:
            ser.close()
        except OSError:
            pass
        ui.ser = None
        if ctrl_out is not None:
            try:
                # Leave the toolbar on the unselected entry so the next capture
                # does not restore the device followed in this session.
                ui.reset_device_selector()
                ctrl_out.close()
            except OSError:
                pass
        try:
            fifo_out.close()
        except OSError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bbo BLE Sniffer USB CDC extcap")
    parser.add_argument("--extcap-interfaces", action="store_true", help="List extcap interfaces")
    parser.add_argument("--extcap-dlts", action="store_true", help="List DLTs for interface")
    parser.add_argument("--extcap-config", action="store_true", help="List configuration options")
    parser.add_argument("--extcap-interface", type=str, help="Selected COM port")
    parser.add_argument("--capture", action="store_true", help="Start capturing packets")
    parser.add_argument("--fifo", type=str, help="Output FIFO / Pipe path")
    parser.add_argument("--target-mac", type=str, help="Target BLE address, sent on the USB CDC port")
    parser.add_argument("--target-name", type=str, help="Target BLE local name, sent on the USB CDC port")
    parser.add_argument("--ltk", type=str, help="16-byte LTK, 32 hex digits, sent on the USB CDC port")
    parser.add_argument("--irk", type=str, help="16-byte peer IRK, 32 hex digits, resolves RPAs")
    parser.add_argument("--bcode", type=str, help="BIS Broadcast Code, 32 hex digits or 1..16 text bytes")
    parser.add_argument("--extcap-control-in", type=str, help="Toolbar control pipe from Wireshark")
    parser.add_argument("--extcap-control-out", type=str, help="Toolbar control pipe to Wireshark")
    parser.add_argument("--extcap-capture-filter", type=str, default="",
                        help="Capture filter, rssi >= -70")

    args, _unknown = parser.parse_known_args()

    if args.extcap_interfaces:
        extcap_interfaces()
    elif args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
    elif args.extcap_config:
        extcap_config(args.extcap_interface)
    elif args.capture and args.fifo:
        capture_stream(args.fifo, port_from_interface(args.extcap_interface),
                       args.target_mac, args.target_name, args.ltk, args.irk, args.bcode,
                       args.extcap_control_in, args.extcap_control_out,
                       args.extcap_capture_filter)
    else:
        parser.print_help()
