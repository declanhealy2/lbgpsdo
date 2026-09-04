#!/bin/env python

#
# Configuration Utility für Leo Bodnar GPSDO
#
# Copyright (C) 2020-2026  Mario Haustein
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import csv
import json
import sys
import time
from contextlib import ExitStack
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

import hid
import serial
from serial.tools.list_ports import comports

from lbe142x_protocol import (
    REPORT_LENGTH,
    STATUS_FEATURE_REPORT_ID,
    decode_status,
    format_frequency,
    frequency_command,
    quantize_frequency,
    ubx_poll_message_rate_command,
    ubx_set_message_rates_command,
    validate_frequency,
)
from lbe142x_ubx import (
    NAV_CLASS,
    NAV_CLOCK_ID,
    NAV_PVT_ID,
    NAV_SAT_ID,
    UBX_SYNC_1,
    UBX_SYNC_2,
    NavPvt,
    NavSat,
    UbxMessage,
    UbxReassembler,
    build_cfg_msg_set,
    decode_nav_clock,
    decode_nav_pvt,
    decode_nav_sat,
    itow_gap_exceeds,
)

USBIDS = \
[
    ( 0x1dd2, 0x2444 ),     # LBE 1421
]

STATUS_INTERVAL_S = 1.0
# CFG-MSG rate is a navigation-epoch divisor, not hertz. This receiver produces
# roughly 10 navigation solutions per second, so 10 gives roughly 1 Hz output.
UBX_NAV_EPOCH_INTERVAL = 10
UBX_NAV_MESSAGE_IDS = (NAV_PVT_ID, NAV_SAT_ID, NAV_CLOCK_ID)
UBX_POLL_TIMEOUT_S = 5.0
UBX_POLL_ATTEMPTS = 3
UBX_POLL_WARMUP_S = 0.5
UBX_STREAM_VERIFY_S = 5.0
UBX_HID_INPUT_REPORT_IDS = (0x76, 0x6e)
LEO_BODNAR_UBX_SLOT = 62
HID_INPUT_READ_SIZE = 65
UBX_DEFAULT_CFG_MSG_RATES = (0, 0, 0, 0, 0, 0)
UBX_CACHE_SIZE = 64

HID_RAW_HEADER = (
    "timestamp_utc", "monotonic_ns", "report_hex", "length", "payload_hex",
)
UBX_HEADER = (
    "timestamp_utc", "monotonic_ns", "message_class_hex", "message_id_hex",
    "length", "checksum_valid", "payload_hex",
)
NAV_CLOCK_HEADER = (
    "timestamp_utc", "monotonic_ns", "itow_ms", "fix_type", "gnss_fix_ok",
    "valid_time", "fully_resolved", "valid_date", "valid_mag", "diff_soln",
    "psm_state", "num_satellites", "clock_bias_ns", "clock_drift_ns_per_s",
    "time_accuracy_ns", "freq_accuracy_ps_per_s", "valid_clock", "gap",
    "pvt_itow_match", "sat_itow_match",
)

TimedUbxMessage = tuple[UbxMessage, str, int]

__all__ = ("GPSDODevice", "main")


def utc_timestamp():
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def open_serial_port(target_serial: str | None = None):
    """Open the CDC port used for UBX configuration on Windows."""

    ports = [port for port in comports() if port.vid == 0x1DD2]
    if target_serial is not None:
        ports = [port for port in ports if port.serial_number == target_serial]
    if not ports:
        suffix = f" with S/N {target_serial}" if target_serial is not None else ""
        sys.stderr.write(
            f"Warning: no Leo Bodnar serial port{suffix} found\n"
        )
        return None
    if len(ports) > 1:
        names = ", ".join(port.device for port in ports)
        suffix = f" with S/N {target_serial}" if target_serial is not None else ""
        raise ValueError(f"More than one Leo Bodnar serial port{suffix}: {names}")
    try:
        return serial.Serial(ports[0].device, 115200, timeout=0.1)
    except serial.SerialException as error:
        sys.stderr.write(f"Warning: cannot open serial port: {error}\n")
        return None


def capture_status(device):
    device.read()
    return (
        utc_timestamp(), time.monotonic_ns(), device.serial, device.path,
        *device.status[:-1], device.status.unverified_tail.hex(),
    )


def open_csv_log(resources, path, header):
    stream = resources.enter_context(path.open("w", newline="", buffering=1))
    writer = csv.writer(stream)
    writer.writerow(header)
    return stream, writer


def hid_input_read(hid_device, timeout_ms=0) -> bytes:
    """Read one HID input report; timeout_ms>0 waits up to that many milliseconds."""

    return bytes(hid_device.read(HID_INPUT_READ_SIZE, timeout_ms))


def ubx_hid_send_methods(hid_device):
    """Return HID send callables to try for one UBX wrap report, in order."""

    if sys.platform == "win32":
        return (hid_device.send_feature_report, hid_device.write)
    return (hid_device.send_feature_report,)


def send_ubx_hid_report(hid_device, report: bytes) -> None:
    """Send one UBX wrap report using the platform-appropriate HID transfer."""

    errors = []
    sent = False
    for send in ubx_hid_send_methods(hid_device):
        name = getattr(send, "__name__", repr(send))
        try:
            send(report)
        except OSError as error:
            errors.append(f"{name}: {error}")
            continue
        sent = True
    if sent:
        return
    raise OSError(
        f"UBX HID report not sent ({report[0]:#04x}): {'; '.join(errors)}"
    )


def normalize_hid_read(raw: bytes) -> bytes:
    """Narrow UTF-16-LE HID reads from Windows hidapi to raw bytes."""

    if bytes((UBX_SYNC_1, UBX_SYNC_2)) in raw:
        return raw
    if len(raw) < 4:
        return raw
    for offset in (0, 1):
        if len(raw) <= offset + 3:
            continue
        probe_end = min(len(raw) - offset, 20)
        if not all(raw[offset + i] == 0 for i in range(1, probe_end, 2)):
            continue
        narrowed = raw[offset::2].lstrip(b"\x00")
        if not narrowed:
            continue
        if (
            bytes((UBX_SYNC_1, UBX_SYNC_2)) in narrowed
            or narrowed[0] in (*UBX_HID_INPUT_REPORT_IDS, STATUS_FEATURE_REPORT_ID)
        ):
            return narrowed
    return raw


def strip_trailing_ff(data: bytes) -> bytes:
    end = len(data)
    while end > 0 and data[end - 1] == 0xFF:
        end -= 1
    return data[:end]


def leo_bodnar_hid_payload_view(raw: bytes) -> bytes:
    """Extract UBX bytes from one candidate HID buffer view."""

    if len(raw) < 4:
        return b""
    length = raw[1]
    if length > 0 and len(raw) >= 2 + length:
        payload = raw[2:2 + length]
        if payload and not all(b == 0xFF for b in payload):
            return payload
    if raw[0] in UBX_HID_INPUT_REPORT_IDS and len(raw) >= 2 + LEO_BODNAR_UBX_SLOT:
        slot = raw[2:2 + LEO_BODNAR_UBX_SLOT]
        if not all(b == 0xFF for b in slot):
            return slot
    if len(raw) >= 3 and raw[1] == UBX_SYNC_1 and raw[2] == UBX_SYNC_2:
        return strip_trailing_ff(raw[1:])
    sync = raw.find(bytes((UBX_SYNC_1, UBX_SYNC_2)))
    if sync >= 0:
        return strip_trailing_ff(raw[sync:])
    tail = strip_trailing_ff(raw[2:])
    if tail and not all(b == 0xFF for b in tail):
        return tail
    return b""


def leo_bodnar_hid_payload(raw: bytes) -> bytes:
    """Extract the Leo Bodnar UBX byte run from one HID input report."""

    normalized = normalize_hid_read(raw)
    if normalized is not raw:
        payload = leo_bodnar_hid_payload_view(normalized)
        if payload:
            return payload
    return leo_bodnar_hid_payload_view(raw)


def hid_report_is_empty(raw: bytes) -> bool:
    """True for Leo Bodnar padding reports with no payload."""

    return not leo_bodnar_hid_payload(raw)


def hid_ubx_report_view(raw: bytes) -> bytes | None:
    """Return the buffer view if this interrupt read is a UBX input report."""

    normalized = normalize_hid_read(raw)
    for view in (normalized, raw):
        if view and view[0] in UBX_HID_INPUT_REPORT_IDS:
            return view
    return None


def hid_get_input_report(hid_device, report_id: int) -> bytes:
    """Read one numbered UBX input report (Windows needs the +1 byte buffer)."""

    for size in (HID_INPUT_READ_SIZE + 1, HID_INPUT_READ_SIZE):
        try:
            raw = bytes(hid_device.get_input_report(report_id, size))
        except OSError:
            continue
        if not raw:
            continue
        if raw[0] == report_id:
            return raw
        return bytes([report_id]) + raw.lstrip(b"\x00")
    return b""


def probe_windows_hid_read(hid_device) -> str:
    """Describe one timed interrupt read for startup diagnostics."""

    raw = bytes(hid_device.read(HID_INPUT_READ_SIZE, 200))
    if not raw:
        return "interrupt read() returned no bytes"
    return (
        f"interrupt read() returned report 0x{raw[0]:02x}, "
        f"{len(raw)} bytes, head={raw[:8].hex()}"
    )


def hid_collect_reports(hid_device, timeout_ms=0) -> list[bytes]:
    """Read every pending UBX-bearing HID input report from the interrupt IN queue."""

    reports = []
    if sys.platform == "win32":
        for report_id in UBX_HID_INPUT_REPORT_IDS:
            raw = hid_get_input_report(hid_device, report_id)
            view = hid_ubx_report_view(raw)
            if view is not None and not hid_report_is_empty(view):
                reports.append(view)
    if timeout_ms == 0:
        while raw := bytes(hid_device.read(HID_INPUT_READ_SIZE, 0)):
            view = hid_ubx_report_view(raw)
            if view is not None and not hid_report_is_empty(view):
                reports.append(view)
        return reports
    raw = bytes(hid_device.read(HID_INPUT_READ_SIZE, timeout_ms))
    view = hid_ubx_report_view(raw)
    if view is not None and not hid_report_is_empty(view):
        reports.append(view)
    return reports


def append_hid_ubx_report(
    raw, reassembler, hid_raw_writer, ubx_writer,
) -> list[TimedUbxMessage]:
    """Decode one HID input report and append ledger rows."""

    timestamp = utc_timestamp()
    monotonic_ns = time.monotonic_ns()
    payload = leo_bodnar_hid_payload(raw)
    hid_raw_writer.writerow(
        (timestamp, monotonic_ns, raw.hex(), len(payload), payload.hex())
    )
    timed_messages = []
    for message in reassembler.feed(payload):
        ubx_writer.writerow((
            timestamp, monotonic_ns,
            f"0x{message.message_class:02x}", f"0x{message.message_id:02x}",
            len(message.payload), message.checksum_valid, message.payload.hex(),
        ))
        timed_messages.append((message, timestamp, monotonic_ns))
    return timed_messages


def drain_ubx_messages(
    device, reassembler, hid_raw_writer, ubx_writer, timeout_ms=0,
) -> list[TimedUbxMessage]:
    """Log every queued HID report and return its complete UBX messages."""

    timed_messages = []
    for raw in hid_collect_reports(device.device, 0):
        timed_messages.extend(append_hid_ubx_report(
            raw, reassembler, hid_raw_writer, ubx_writer
        ))
    if timeout_ms:
        for raw in hid_collect_reports(device.device, timeout_ms):
            timed_messages.extend(append_hid_ubx_report(
                raw, reassembler, hid_raw_writer, ubx_writer
            ))
    return timed_messages


def count_nav_stream_messages(messages) -> int:
    return sum(
        1 for message, _, _ in messages
        if message.message_class == NAV_CLASS
        and message.message_id in (NAV_PVT_ID, NAV_SAT_ID, NAV_CLOCK_ID)
    )


def verify_ubx_hid_stream(
    device, reassembler, hid_raw_writer, ubx_writer,
) -> tuple[int, int]:
    """Wait briefly and count NAV frames and raw HID reports received."""

    nav_messages = 0
    raw_reports = 0
    deadline = time.monotonic() + UBX_STREAM_VERIFY_S
    while time.monotonic() < deadline:
        reports = hid_collect_reports(device.device, 200)
        raw_reports += len(reports)
        for raw in reports:
            messages = append_hid_ubx_report(
                raw, reassembler, hid_raw_writer, ubx_writer
            )
            nav_messages += count_nav_stream_messages(messages)
        if nav_messages:
            break
        time.sleep(0.02)
    return nav_messages, raw_reports


def cfg_msg_poll_response(message, message_id):
    """Return the six CFG-MSG rates if message is a poll response for message_id."""

    if (
        message.message_class == 0x06
        and message.message_id == 0x01
        and len(message.payload) == 8
        and message.payload[:2] == bytes((NAV_CLASS, message_id))
        and message.checksum_valid
    ):
        return tuple(message.payload[2:])
    return None


def poll_ubx_rates(
    device, reassembler, hid_raw_writer, ubx_writer, message_id,
):
    """Poll and return all six CFG-MSG rates for one NAV message."""

    poll = ubx_poll_message_rate_command(message_id)
    send_methods = ubx_hid_send_methods(device.device)
    method_timeout_s = UBX_POLL_TIMEOUT_S / len(send_methods)
    last_error = None
    for _attempt in range(UBX_POLL_ATTEMPTS):
        for send in send_methods:
            try:
                send(poll)
            except OSError as error:
                last_error = error
                continue
            if sys.platform == "win32":
                time.sleep(0.05)
            deadline = time.monotonic() + method_timeout_s
            while time.monotonic() < deadline:
                for message, _, _ in drain_ubx_messages(
                    device, reassembler, hid_raw_writer, ubx_writer
                ):
                    rates = cfg_msg_poll_response(message, message_id)
                    if rates is not None:
                        return rates
                for raw in hid_collect_reports(device.device, 200):
                    for message, _, _ in append_hid_ubx_report(
                        raw, reassembler, hid_raw_writer, ubx_writer
                    ):
                        rates = cfg_msg_poll_response(message, message_id)
                        if rates is not None:
                            return rates
        last_error = TimeoutError(
            f"No CFG-MSG poll response for NAV 0x{message_id:02x} "
            f"within {UBX_POLL_TIMEOUT_S}s"
        )
    raise last_error


def restore_ubx_rates(device, snapshot):
    """Best-effort restore of a complete per-port CFG-MSG snapshot."""

    for message_id, rates in snapshot.items():
        try:
            device.set_ubx_message_rates(message_id, rates)
        except OSError as error:
            sys.stderr.write(
                f"Warning: failed to restore UBX message 0x{message_id:02x}: {error}\n"
            )


def configure_ubx_logging(
    device, resources, reassembler, hid_raw_writer, ubx_writer,
):
    """Enable UBX logging transactionally and arrange exact restoration."""

    sys.stderr.write("Configuring UBX logging...\n")
    device.device.set_nonblocking(1)
    try:
        warmup_deadline = time.monotonic() + UBX_POLL_WARMUP_S
        while time.monotonic() < warmup_deadline:
            drain_ubx_messages(
                device, reassembler, hid_raw_writer, ubx_writer
            )
            time.sleep(0.02)
        snapshot = {
            message_id: poll_ubx_rates(
                device, reassembler, hid_raw_writer, ubx_writer, message_id
            )
            for message_id in UBX_NAV_MESSAGE_IDS
        }
    except (OSError, TimeoutError) as error:
        if sys.platform != "win32":
            sys.stderr.write(
                f"Warning: UBX snapshot failed: {error}; no CFG-MSG rates changed\n"
            )
            return False
        sys.stderr.write(
            "Warning: UBX poll failed on Windows; enabling with observed "
            f"default rates ({error})\n"
        )
        snapshot = {
            message_id: UBX_DEFAULT_CFG_MSG_RATES
            for message_id in UBX_NAV_MESSAGE_IDS
        }

    resources.callback(restore_ubx_rates, device, snapshot)
    try:
        for message_id, original in snapshot.items():
            rates = (UBX_NAV_EPOCH_INTERVAL, *original[1:])
            device.set_ubx_message_rates(message_id, rates)
    except OSError as error:
        sys.stderr.write(f"Warning: UBX enable failed: {error}; restoring rates\n")
        restore_ubx_rates(device, snapshot)
        return False

    if sys.platform == "win32":
        nav_messages, raw_reports = verify_ubx_hid_stream(
            device, reassembler, hid_raw_writer, ubx_writer
        )
        if nav_messages:
            sys.stderr.write(
                f"UBX NAV stream confirmed ({nav_messages} frames in "
                f"{UBX_STREAM_VERIFY_S:.0f}s)\n"
            )
        elif raw_reports:
            sys.stderr.write(
                f"Warning: {raw_reports} HID reports in "
                f"{UBX_STREAM_VERIFY_S:.0f}s but no NAV frames yet; "
                "continuing — nav_clock.csv should grow within ~30s\n"
            )
        else:
            sys.stderr.write(
                "Warning: no UBX HID input during verify; "
                f"{probe_windows_hid_read(device.device)}; "
                "nav_clock needs COM port UBX if HID stays empty\n"
            )
    return True


def configure_ubx_serial(serial_device) -> None:
    """Enable UBX NAV messages on the CDC serial port (Windows fallback)."""

    sys.stderr.write("Enabling UBX NAV messages on serial port...\n")
    serial_device.reset_input_buffer()
    for message_id in UBX_NAV_MESSAGE_IDS:
        for rates in (
            (UBX_NAV_EPOCH_INTERVAL, 0, 0, 0, 0, 0),
            (0, UBX_NAV_EPOCH_INTERVAL, 0, 0, 0, 0),
            (0, 0, 0, UBX_NAV_EPOCH_INTERVAL, 0, 0),
        ):
            serial_device.write(build_cfg_msg_set(message_id, rates))
            time.sleep(0.05)
    time.sleep(0.2)


def analyze_hid_csv(hid_raw_path):
    """Summarize hid_raw.csv byte layout for parser debugging."""

    report_ids: dict[str, int] = {}
    length_col: dict[str, int] = {}
    total = 0
    sync_in_raw = 0
    sync_in_hex = 0
    wide_in_hex = 0
    with_payload = 0
    samples = []
    with hid_raw_path.open(newline="") as stream:
        for row in csv.DictReader(stream):
            total += 1
            hexstr = row["report_hex"]
            lower = hexstr.lower()
            if "b562" in lower:
                sync_in_hex += 1
            if "b5006200" in lower:
                wide_in_hex += 1
            raw = bytes.fromhex(hexstr)
            if bytes((UBX_SYNC_1, UBX_SYNC_2)) in raw:
                sync_in_raw += 1
            if raw:
                report_ids[f"0x{raw[0]:02x}"] = report_ids.get(f"0x{raw[0]:02x}", 0) + 1
            length_col[row.get("length", "?")] = length_col.get(row.get("length", "?"), 0) + 1
            payload = leo_bodnar_hid_payload(raw)
            if payload:
                with_payload += 1
            if len(samples) < 5 and raw:
                normalized = normalize_hid_read(raw)
                samples.append(
                    f"  raw[0:12]={raw[:12].hex()} "
                    f"norm[0:12]={normalized[:12].hex()} "
                    f"payload[0:12]={payload[:12].hex() if payload else '(empty)'}"
                )
    return {
        "path": hid_raw_path,
        "total": total,
        "sync_in_hex": sync_in_hex,
        "wide_in_hex": wide_in_hex,
        "sync_in_raw": sync_in_raw,
        "with_payload": with_payload,
        "report_ids": report_ids,
        "length_col": length_col,
        "samples": samples,
    }


def format_hid_analysis(stats):
    """Render analyze_hid_csv() output for the terminal."""

    lines = [
        f"hid_raw.csv analysis for {stats['path']}",
        f"  reports:              {stats['total']}",
        f"  b562 in hex string:   {stats['sync_in_hex']}",
        f"  b5006200 in hex:      {stats['wide_in_hex']}",
        f"  b562 in raw bytes:    {stats['sync_in_raw']}",
        f"  non-empty payloads:   {stats['with_payload']}",
        "  report_id counts:     "
        + ", ".join(
            f"{key}={value}"
            for key, value in sorted(stats["report_ids"].items())
        ),
        "  length column top:    "
        + ", ".join(
            f"{key}={value}"
            for key, value in sorted(
                stats["length_col"].items(), key=lambda item: -item[1]
            )[:6]
        ),
    ]
    if stats["samples"]:
        lines.append("  sample rows:")
        lines.extend(stats["samples"])
    if stats["total"] and stats["sync_in_hex"] == 0:
        lines.append(
            "  → No UBX sync in captured HID bytes; reprocess cannot produce "
            "nav_clock. On Windows, close PuTTY and re-run `log` so serial "
            "UBX enable can run, or capture on Mac/Linux."
        )
    return "\n".join(lines) + "\n"


def nav_clock_row(
    timed_message: TimedUbxMessage,
    clock,
    pvt: NavPvt | None,
    sat: NavSat | None,
    gap: bool,
):
    """Build the stable, analysis-facing NAV-CLOCK CSV row."""

    _, timestamp, monotonic_ns = timed_message
    if pvt is None:
        pvt_fields = ("", "", "", "", "", "", "", "")
        num_satellites = sat.num_satellites if sat is not None else ""
        valid_clock = False
    else:
        pvt_fields = (
            pvt.fix_type, int(pvt.gnss_fix_ok), int(pvt.valid_time),
            int(pvt.fully_resolved), int(pvt.valid_date), int(pvt.valid_mag),
            int(pvt.diff_soln), pvt.psm_state,
        )
        num_satellites = pvt.num_satellites
        valid_clock = (
            pvt.gnss_fix_ok
            and pvt.valid_date
            and pvt.valid_time
            and pvt.fully_resolved
            and pvt.fix_type >= 2
            and clock.time_accuracy_ns is not None
            and clock.freq_accuracy_ps_per_s is not None
        )
    return (
        timestamp, monotonic_ns, clock.itow_ms, *pvt_fields, num_satellites,
        clock.clock_bias_ns, clock.clock_drift_ns_per_s,
        clock.time_accuracy_ns if clock.time_accuracy_ns is not None else "",
        clock.freq_accuracy_ps_per_s
        if clock.freq_accuracy_ps_per_s is not None else "",
        int(valid_clock), int(gap), int(pvt is not None), int(sat is not None),
    )


def write_nav_clock_rows(
    messages, nav_clock_writer, pvt_by_itow, sat_by_itow, last_itow_ms,
):
    """Decode navigation messages and write complete clock epochs."""

    for timed_message in messages:
        message = timed_message[0]
        if not message.checksum_valid or message.message_class != NAV_CLASS:
            continue
        try:
            if message.message_id == NAV_PVT_ID:
                pvt = decode_nav_pvt(message.payload)
                pvt_by_itow[pvt.itow_ms] = pvt
            elif message.message_id == NAV_SAT_ID:
                sat = decode_nav_sat(message.payload)
                sat_by_itow[sat.itow_ms] = sat
            elif message.message_id == NAV_CLOCK_ID:
                clock = decode_nav_clock(message.payload)
                gap = last_itow_ms is not None and itow_gap_exceeds(
                    last_itow_ms, clock.itow_ms
                )
                nav_clock_writer.writerow(nav_clock_row(
                    timed_message, clock, pvt_by_itow.get(clock.itow_ms),
                    sat_by_itow.get(clock.itow_ms), gap,
                ))
                last_itow_ms = clock.itow_ms
        except ValueError as error:
            sys.stderr.write(
                f"Warning: malformed UBX-NAV 0x{message.message_id:02x}: {error}\n"
            )
    for cache in (pvt_by_itow, sat_by_itow):
        while len(cache) > UBX_CACHE_SIZE:
            del cache[next(iter(cache))]
    return last_itow_ms


def open_ubx_logs(device, resources, output, serial_device=None):
    """Open UBX logs, then enable the receiver stream transactionally."""

    hid_raw_stream, hid_raw_writer = open_csv_log(
        resources, output / "hid_raw.csv", HID_RAW_HEADER
    )
    ubx_stream, ubx_writer = open_csv_log(
        resources, output / "ubx.csv", UBX_HEADER
    )
    nav_clock_stream, nav_clock_writer = open_csv_log(
        resources, output / "nav_clock.csv", NAV_CLOCK_HEADER
    )
    reassembler = UbxReassembler()
    if sys.platform == "win32" and serial_device is not None:
        configure_ubx_serial(serial_device)
    enabled = configure_ubx_logging(
        device, resources, reassembler, hid_raw_writer, ubx_writer
    )
    hid_raw_stream.flush()
    ubx_stream.flush()
    if not enabled:
        return None
    return (
        reassembler, hid_raw_stream, hid_raw_writer,
        ubx_stream, ubx_writer, nav_clock_stream, nav_clock_writer,
    )


def run_log_loop(device, output, status_logs, ubx_logs):
    """Acquire status and UBX streams until interrupted."""

    status_stream, status_writer = status_logs
    pvt_by_itow: dict[int, NavPvt] = {}
    sat_by_itow: dict[int, NavSat] = {}
    last_itow_ms = None
    next_status = time.monotonic() + STATUS_INTERVAL_S
    suffix = (
        f" (UBX NAV messages enabled, epoch interval {UBX_NAV_EPOCH_INTERVAL})"
        if ubx_logs is not None
        else ""
    )
    sys.stdout.write(f"Logging to {output}{suffix}; press Ctrl-C to stop\n")
    try:
        while True:
            if time.monotonic() >= next_status:
                status_writer.writerow(capture_status(device))
                status_stream.flush()
                missed = int((time.monotonic() - next_status) // STATUS_INTERVAL_S)
                next_status += (missed + 1) * STATUS_INTERVAL_S

            if ubx_logs is not None:
                (
                    reassembler, hid_raw_stream, hid_raw_writer,
                    ubx_stream, ubx_writer, nav_clock_stream, nav_clock_writer,
                ) = ubx_logs
                try:
                    ubx_timeout_ms = 200 if sys.platform == "win32" else 0
                    messages = drain_ubx_messages(
                        device, reassembler, hid_raw_writer, ubx_writer,
                        timeout_ms=ubx_timeout_ms,
                    )
                except OSError as error:
                    sys.stderr.write(f"Warning: UBX logging stopped: {error}\n")
                    ubx_logs = None
                    messages = []
                last_itow_ms = write_nav_clock_rows(
                    messages, nav_clock_writer, pvt_by_itow,
                    sat_by_itow, last_itow_ms,
                )
                if messages:
                    ubx_stream.flush()
                    nav_clock_stream.flush()
                    hid_raw_stream.flush()

            time.sleep(min(0.1, max(0.0, next_status - time.monotonic())))
    except KeyboardInterrupt:
        sys.stdout.write("Logging stopped\n")



class GPSDODevice:
    """
    GPSDO device bound to an USB device.
    """

    @classmethod
    def enumerate(cls):
        """
        Returns USB device information descriptors.

        The method returns the USB device information descriptors of all
        detected GPSDO devices as they are returned by the HID library.

        :returns: USB device information descriptors
        :rtype: list of dict
        """

        for d in hid.enumerate():
            if ( d['vendor_id'], d['product_id'] ) in USBIDS:
                yield d


    @classmethod
    def filter(cls, serial = None, device = None):
        """
        Filters the result of the `enumerate()`.

        The method filters the detected devices by serial number or device
        path. Only devices which math all parameters are returned. If a
        parameter is `None` it will not be treated as filter criteria.

        :param serial: Serial Number of the device
        :type serial: str | None
        :param device: Device path
        :type device: str | None

        :returns: USB device information descriptors
        :rtype: list of dict
        """

        for d in cls.enumerate():
            if serial is not None and serial != d['serial_number']:
                continue
            device_path = d['path'].decode() if isinstance(d['path'], bytes) else d['path']
            if device is not None and device != device_path:
                continue
            yield d


    @classmethod
    def open(cls, serial = None, device = None):
        """
        Opens a device and returns an instance.

        This method opens an USB device. The parameters are the same like for
        the `filter()` method. If, after applying the filter, no or more than
        one device was found, an exception is raised.

        :param serial: Serial Number of the device
        :type serial: str | None
        :param device: Device path
        :type device: str | None

        :raises: :class:`ValueError`: Filter criterias are not unique.

        :returns: Device instance
        :rtype: GPSDODevice
        """

        ds = list(cls.filter(serial = serial, device = device))
        if len(ds) == 0:
            raise ValueError("No GPSDO device found")
        elif len(ds) > 1:
            raise ValueError("More than one GPSDO device found. Please specifiy device path or serial number.")

        return cls(ds[0])


    @classmethod
    def openall(cls, serial = None, device = None):
        """
        Opens all devices mathing the filter and return a list of instances.

        This method opens all devices matching the specified filter. The
        parameters are the same like for the `filter()` method.

        :param serial: Serial Number of the device
        :type serial: str | None
        :param device: Device path
        :type device: str | None

        :returns: List of device instance
        :rtype: list of GPSDODevice
        """

        ds = list(cls.filter(serial = serial, device = device))
        for dinfo in ds:
            yield cls(dinfo)


    def __init__(self, dinfo):
        """
        Opens a device.

        DO NOT USE THIS METHOD DIRECTLY! Use the methods `open()` or
        `openall()` instead.

        :param dinfo: USB device information descriptor
        :type dinfo: dict

        :returns: Device instance
        :rtype: GPSDODevice
        """

        self.device = None
        super().__init__()

        # Open device.
        self.path          =  dinfo['path'].decode()
        self.vid           =  dinfo['vendor_id']
        self.pid           =  dinfo['product_id']
        self.manufacturer  =  dinfo['manufacturer_string']
        self.product       =  dinfo['product_string']
        self.serial        =  dinfo['serial_number']
        self.version_major = (dinfo['release_number'] & 0xff00) >> 8
        self.version_minor =  dinfo['release_number'] & 0x00ff

        self.device = hid.device()
        self.device.open_path(dinfo['path'])
        self.read()


    def __del__(self):
        if self.device is not None:
            self.device.close()


    def read(self):
        """
        Read status and configuration from the device.
        """

        raw = bytes(self.device.get_feature_report(STATUS_FEATURE_REPORT_ID, REPORT_LENGTH + 1))
        if raw[0] == STATUS_FEATURE_REPORT_ID:
            raw = raw[1:]
        self.status = decode_status(raw[:REPORT_LENGTH])
        self.loss_count = self.status.loss_count
        self.sat_lock = self.status.gps_locked
        self.pll_lock = self.status.pll_locked
        self.ant_ok = self.status.antenna_ok
        self.led1 = self.status.led1
        self.led2 = self.status.led2
        self.out1 = self.status.out1_enabled
        self.out2 = self.status.out2_enabled
        self.pps1 = self.status.pps_enabled
        self.f1 = self.status.out1_frequency_hz
        self.f2 = self.status.out2_frequency_hz
        self.fll = self.status.fll_mode
        self.out1low = self.status.out1_low_power
        self.out2low = self.status.out2_low_power
        self.unverified_status_tail = self.status.unverified_tail


    def enable(self, out1, out2):
        """
        Enable or disable outputs.

        This method enables or disables output drivers for the first channel
        (`out1`) and second channel (`out2`). The driver will be enabled when
        the parameter is set to `True` and disabled when `False`. If the
        parameter is `None`, the state is not changed.

        The 1-PPS-mode takes precedence over this setting. Enabling the
        1-PPS-mode provides the clock pulse even with a disabled driver.

        :param out1: configuration for output 1
        :type out1: bool | None
        :param out2: configuration for output 2
        :type out2: bool | None
        """

        buf = 60 * [ 0 ]
        buf[0] = 1

        # As of firmware version 1.9 the flags are swapped in regards of output
        # assignment. 0x02 will configure output 1, but sets LED 2. 0x01 will
        # configure output 2, but sets LED 1.
        if out1 is None and self.out1 or out1:
            buf[1] |= 0x02
        if out2 is None and self.out2 or out2:
            buf[1] |= 0x01

        self.device.send_feature_report(bytes(buf))


    def identify(self):
        """
        Identify device.

        Blink LEDs of the device.
        """

        buf = 60 * [ 0 ]
        buf[0] = 2
        self.device.send_feature_report(bytes(buf))


    def set_freq(self, chann, f, save):
        """
        Set channel frequency.

        Sets frequency of channel `chann` (0 for first channel, 1 for second
        channel) to value `f` in Hz. When `f` is `None`, the function returns
        without doing anything.

        If `save` is true, the frequency is saved into the flash. Otherwise the
        setting is temporary until poweroff.

        :param chann: channel number
        :type chann: int
        :param f: frequency
        :type f: Decimal | None
        :param save: save to flash
        :type save: bool

        :raises: :class:`ValueError`: frequency out of range.
        """

        if f is None:
            return None
        report = frequency_command(chann, f, save)
        written = self.device.send_feature_report(report)
        if written != len(report):
            raise OSError(
                f"Short HID feature-report write: wrote {written} of {len(report)} bytes"
            )
        return written


    def set_pll(self, pll):
        """
        Set PLL mode.

        When `pll` evaluates to true, the device operates in PLL mode (phase
        locked loop), otherwise in FLL mode (frequency locked loop).

        :param pll: PLL mode
        :type pll: bool
        """

        if pll is None:
            return

        buf = 60 * [ 0 ]

        buf[0] = 11
        buf[1] = 0 if pll else 1

        self.device.send_feature_report(bytes(buf))


    def set_pps(self, pps):
        """
        Enable 1-PPS-mode on first channel.

        When `pps` evaluates to true, the 1-PPS-mode is enabled. In 1-PPS-mode
        the device provides a 1 Hz pulse at the start of every UTC second on
        the first channel. The 1-PPS-mode takes precedence over frequency
        mode.

        :param pps: 1-PPS-mode
        :type pps: bool
        """

        if pps is None:
            return

        buf = 60 * [ 0 ]

        buf[0] = 12
        buf[1] = 1 if pps else 0

        self.device.send_feature_report(bytes(buf))


    def set_level(self, chann, lowlevel):
        """
        Set drive level.

        This method sets the drive level of channel `chann` (0 for first
        channel, 1 for second channel). When `level` evaluates to true, the
        driver is set to low level, otherwise to normal power level.

        :param chann: channel number
        :type chann: int
        :param lowlevel: driver level
        :type lowlevel: bool
        """

        if lowlevel is None:
            return

        buf = 60 * [ 0 ]

        if chann == 0:
            # TODO: 1420 7
            buf[0] = 13
        elif chann == 1:
            buf[0] = 14
        else:
            return

        buf[1] = 1 if lowlevel else 0

        self.device.send_feature_report(bytes(buf))


    def set_ubx_message_rates(self, message_id, rates):
        """
        Set the six per-port CFG-MSG rates for a UBX-NAV message.

        The LBE-1421 forwards this as UBX-CFG-MSG (opcode 0x08 is a
        generic UBX wrap: firmware adds B5 62 and Fletcher-8). ``rates``
        is ``rate[6]`` where ``rate[i]`` is the navigation-epoch divisor
        for port i (0=DDC/I2C, 1=UART1, 2=UART2, 3=USB, 4=SPI,
        5=reserved per u-blox spec); zero disables that message on that
        port. The LBE-1421's HID stream has been observed to follow
        ``rate[0]``. Use the exact tuple previously returned by polling
        to restore.

        :param message_id: UBX NAV message ID (e.g. NAV_CLOCK_ID)
        :type message_id: int
        :param rates: six per-port rates
        :type rates: tuple[int, ...]
        """

        report = ubx_set_message_rates_command(message_id, rates)
        send_ubx_hid_report(self.device, report)
        return len(report)

    def infotext(self):
        """
        Returns current device status and configuration as formatted text.

        :returns: Status
        :rtype: str
        """

        result = ""

        result += "Device information\n"
        result += "------------------\n"
        result += f"VID, PID:     0x{self.vid:04x}:0x{self.pid:04x}\n"
        result += f"Device:       {self.path}\n"
        result += f"Product:      {self.product}\n"
        result += f"Manufacturer: {self.manufacturer}\n"
        result += f"S/N:          {self.serial}\n"
        result += f"Firmware:     {self.version_major}.{self.version_minor}\n"
        result += "\n"

        result += "Device status\n"
        result += "-------------\n"
        # result += "Loss count:   %d\n" % self.loss_count
        result += f"SAT lock:     {'LOCKED' if self.sat_lock else 'unlocked'}\n"
        result += f"Loss count:   {self.loss_count}\n"
        result += f"PLL lock:     {'LOCKED' if self.pll_lock else 'unlocked'}\n"
        result += f"Antenna:      {'OK' if self.ant_ok else 'short-circuit'}\n"
        result += f"Mode:         {'FLL' if self.fll else 'PLL'}\n"
        result += f"Status tail:  {self.unverified_status_tail.hex(' ')} (unverified)\n"
        result += "\n"

        result += "Output settings\n"
        result += "---------------\n"

        result += "Output 1:    "
        if self.pps1:
            result += "1 PPS"
        elif not self.out1:
            result += "       ---   "
        else:
            result += f"{format_frequency(self.f1):>10} Hz"
        result += f"  level: {'LOW' if self.out1low else 'NORMAL'}\n"

        result += "Output 2:    "
        if not self.out2:
            result += "       ---   "
        else:
            result += f"{format_frequency(self.f2):>10} Hz"
        result += f"  level: {'LOW' if self.out2low else 'NORMAL'}\n"

        result += "\n"

        result = result.strip("\n")
        if result:
            result += "\n"

        return result



#
# Command Callbacks
#

def command_list(args):
    for d in GPSDODevice.enumerate():
        sys.stdout.write(
            f"{d['vendor_id']:04x}:{d['product_id']:04x} "
            f"{d['path'].decode():<16}  {d['serial_number']}  {d['product_string']}\n"
        )


def command_detail(args):
    if args.json:
        devices = list(GPSDODevice.openall(serial=args.serial, device=args.device))
        try:
            results = [
                {
                    "schema": "lbgpsdo.inspect.v1",
                    "serial": device.serial,
                    "device_path": device.path,
                    "out1_frequency_hz": format(device.status.out1_frequency_hz, "f"),
                    "out2_frequency_hz": format(device.status.out2_frequency_hz, "f"),
                    "gps_locked": device.status.gps_locked,
                    "pll_locked": device.status.pll_locked,
                    "antenna_ok": device.status.antenna_ok,
                }
                for device in devices
            ]
        finally:
            for device in devices:
                device.device.close()
                device.device = None
        sys.stdout.write(json.dumps(results[0] if len(results) == 1 else results, separators=(",", ":")) + "\n")
        return

    first = True
    for d in GPSDODevice.openall(serial = args.serial, device = args.device):
        if first:
            first = False
        else:
            sys.stdout.write("\n\n")
        sys.stdout.write(d.infotext())


def command_modify(args):
    if args.f1 is not None:
        validate_frequency(0, args.f1)
    if args.f2 is not None:
        validate_frequency(1, args.f2)

    d = GPSDODevice.open(serial = args.serial, device = args.device)

    d.enable(args.out1, args.out2)
    d.set_freq(0, args.f1, args.save)
    d.set_freq(1, args.f2, args.save)
    d.set_pll(args.pll)
    d.set_pps(args.pps)
    d.set_level(0, args.out1low)
    d.set_level(1, args.out2low)


def frequency_write_result(device, output, requested_hz, save, bytes_written):
    encoded_hz = quantize_frequency(requested_hz)
    wire_value = frequency_command(output - 1, requested_hz, save)[1:9]
    fractional_word = int.from_bytes(wire_value[:4], "little")
    integer_word = int.from_bytes(wire_value[4:], "little")
    readback_hz = (
        device.status.out1_frequency_hz
        if output == 1
        else device.status.out2_frequency_hz
    )
    return {
        "schema": "lbgpsdo.set-frequency.v1",
        "serial": device.serial,
        "device_path": device.path,
        "output": output,
        "requested_hz": format(requested_hz, "f"),
        "encoded_hz": format(encoded_hz, "f"),
        "fractional_word_hex": f"0x{fractional_word:08x}",
        "integer_word_hex": f"0x{integer_word:08x}",
        "wire_value_hex": wire_value.hex(),
        "write_mode": "flash" if save else "temporary",
        "bytes_written": bytes_written,
        "configured_readback_hz": format(readback_hz, "f"),
        "configured_readback_matches_encoded": readback_hz == encoded_hz,
        "gps_locked": device.status.gps_locked,
        "pll_locked": device.status.pll_locked,
    }


def command_set_frequency(args):
    output_index = args.output - 1
    validate_frequency(output_index, args.hz)
    if args.readback_delay < 0:
        raise ValueError("readback delay must be non-negative")
    device = GPSDODevice.open(serial=args.serial, device=args.device)
    try:
        bytes_written = device.set_freq(output_index, args.hz, args.persist)
        time.sleep(args.readback_delay)
        device.read()
        result = frequency_write_result(
            device, args.output, args.hz, args.persist, bytes_written
        )
    finally:
        device.device.close()
        device.device = None

    if args.json:
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    else:
        persistence = "saved to flash" if args.persist else "temporary"
        sys.stdout.write(
            f"Output {args.output}: requested {result['requested_hz']} Hz, "
            f"encoded {result['encoded_hz']} Hz, configured readback "
            f"{result['configured_readback_hz']} Hz ({persistence})\n"
        )
    if not result["configured_readback_matches_encoded"]:
        sys.stderr.write(
            "Configured-frequency readback does not match the encoded setpoint\n"
        )
        raise SystemExit(1)


def command_analyze_hid(args):
    """Summarize hid_raw.csv byte layout for parser debugging."""

    hid_raw_path = args.input / "hid_raw.csv"
    if not hid_raw_path.is_file():
        raise ValueError(f"No hid_raw.csv in {args.input}")
    sys.stdout.write(format_hid_analysis(analyze_hid_csv(hid_raw_path)))


def command_reprocess_hid(args):
    """Rebuild ubx.csv and nav_clock.csv from an existing hid_raw.csv ledger."""

    input_log = args.input
    output = args.output
    hid_raw_path = input_log / "hid_raw.csv"
    if not hid_raw_path.is_file():
        raise ValueError(f"No hid_raw.csv in {input_log}")
    if output.exists():
        raise ValueError(f"Output path already exists: {output}")
    output.mkdir(parents=True)
    reports = 0
    ubx_frames = 0
    with ExitStack() as resources:
        ubx_stream, ubx_writer = open_csv_log(
            resources, output / "ubx.csv", UBX_HEADER
        )
        nav_clock_stream, nav_clock_writer = open_csv_log(
            resources, output / "nav_clock.csv", NAV_CLOCK_HEADER
        )
        reassembler = UbxReassembler()
        pvt_by_itow: dict[int, NavPvt] = {}
        sat_by_itow: dict[int, NavSat] = {}
        last_itow_ms = None
        with hid_raw_path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                reports += 1
                raw = bytes.fromhex(row["report_hex"])
                timestamp = row["timestamp_utc"]
                monotonic_ns = int(row["monotonic_ns"])
                payload = leo_bodnar_hid_payload(raw)
                timed_messages = []
                for message in reassembler.feed(payload):
                    ubx_writer.writerow((
                        timestamp, monotonic_ns,
                        f"0x{message.message_class:02x}",
                        f"0x{message.message_id:02x}",
                        len(message.payload), message.checksum_valid,
                        message.payload.hex(),
                    ))
                    timed_messages.append((message, timestamp, monotonic_ns))
                    ubx_frames += 1
                last_itow_ms = write_nav_clock_rows(
                    timed_messages, nav_clock_writer, pvt_by_itow,
                    sat_by_itow, last_itow_ms,
                )
        ubx_stream.flush()
        nav_clock_stream.flush()

    with (output / "nav_clock.csv").open(newline="") as stream:
        nav_clock_data_rows = sum(1 for _ in csv.DictReader(stream))

    sys.stdout.write(
        f"Reprocessed {reports} HID reports from {hid_raw_path}\n"
        f"  ubx frames:     {ubx_frames}\n"
        f"  nav_clock rows: {nav_clock_data_rows}\n"
        f"  output:         {output}\n"
    )
    if ubx_frames == 0:
        sys.stdout.write(format_hid_analysis(analyze_hid_csv(hid_raw_path)))


def command_log(args):
    output = args.output
    if output.exists():
        raise ValueError(f"Output path already exists: {output}")
    device = GPSDODevice.open(serial=args.serial, device=args.device)
    with ExitStack() as resources:
        resources.callback(device.device.close)
        serial_device = open_serial_port(device.serial) if sys.platform == "win32" else None
        if serial_device is not None:
            resources.callback(serial_device.close)
        first_status = capture_status(device)

        output.mkdir(parents=True)
        status_logs = open_csv_log(
            resources,
            output / "status.csv",
            (
                "timestamp_utc", "monotonic_ns", "device_serial", "device_path",
                *device.status._fields,
            ),
        )
        _, status_writer = status_logs
        status_writer.writerow(first_status)

        if sys.platform == "win32" and serial_device is None:
            raise SystemExit(
                "Cannot log UBX on Windows without the CDC serial port — "
                "close PuTTY/other COM clients on OUT33 and retry."
            )

        ubx_logs = open_ubx_logs(device, resources, output, serial_device)
        run_log_loop(device, output, status_logs, ubx_logs)


def command_identify(args):
    d = GPSDODevice.open(serial = args.serial, device = args.device)
    d.identify()


def _command_registry():
    """Return device implementations keyed by the canonical commands."""

    return {
        "list": command_list,
        "inspect": command_detail,
        "configure": command_modify,
        "set": command_set_frequency,
        "identify": command_identify,
        "log": command_log,
        "reprocess-hid": command_reprocess_hid,
        "analyze-hid": command_analyze_hid,
    }


def main(argv=None):
    """Run the original script name through the canonical command parser."""

    from lb import _run

    return _run(argv, _command_registry(), prog="lbe142x.py")


if __name__ == "__main__":
    raise SystemExit(main())
