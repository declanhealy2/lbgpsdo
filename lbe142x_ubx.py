"""Read and write u-blox UBX messages.

This file handles the UBX message format and the navigation messages used by
the logger. It does not open the USB device.
"""

from struct import unpack_from
from typing import NamedTuple

UBX_SYNC_1 = 0xB5
UBX_SYNC_2 = 0x62

NAV_CLASS = 0x01
NAV_PVT_ID = 0x07
NAV_SAT_ID = 0x35
NAV_CLOCK_ID = 0x22

UNKNOWN_ACCURACY = 0xFFFFFFFF

MAX_UBX_PAYLOAD_LENGTH = 4096  # covers NAV-SAT worst case 8+12*255=3068
MAX_BUFFER_LENGTH = MAX_UBX_PAYLOAD_LENGTH + 8  # payload + class/id/len/checksum
GPS_WEEK_MS = 604800000  # 7*24*3600*1000
ITOW_GAP_THRESHOLD_MS = 50


class UbxMessage(NamedTuple):
    message_class: int
    message_id: int
    payload: bytes
    checksum_valid: bool


def build_ubx_frame(message_class: int, message_id: int, payload: bytes) -> bytes:
    body = bytes((message_class, message_id)) + len(payload).to_bytes(2, "little") + payload
    return bytes((UBX_SYNC_1, UBX_SYNC_2)) + body + bytes(fletcher8_checksum(body))


def build_cfg_msg_set(nav_message_id: int, rates: tuple[int, ...]) -> bytes:
    payload = bytes((NAV_CLASS, nav_message_id, *rates))
    return build_ubx_frame(0x06, 0x01, payload)


class NavClock(NamedTuple):
    itow_ms: int
    clock_bias_ns: int
    clock_drift_ns_per_s: int
    time_accuracy_ns: int | None
    freq_accuracy_ps_per_s: int | None


class NavPvt(NamedTuple):
    itow_ms: int
    fix_type: int
    gnss_fix_ok: bool
    diff_soln: bool
    psm_state: int
    valid_date: bool
    valid_time: bool
    fully_resolved: bool
    valid_mag: bool
    num_satellites: int


class NavSat(NamedTuple):
    itow_ms: int
    num_satellites: int


def fletcher8_checksum(data: bytes) -> tuple[int, int]:
    """Compute the UBX 8-bit Fletcher checksum over class..payload."""

    check_a = 0
    check_b = 0
    for byte in data:
        check_a = (check_a + byte) & 0xFF
        check_b = (check_b + check_a) & 0xFF
    return check_a, check_b


class UbxReassembler:
    """Reassembles UBX messages from a stream of raw payload bytes.

    Callers feed in bytes exactly as they arrive from the transport
    (e.g. the LBE-1421's HID input-report payload, already stripped of
    its own [tag][length] framing). Complete messages are yielded as
    they are found, whether or not their checksum is valid; partial
    trailing data is retained for the next call.

    A corrupt candidate is reported once, then the parser resumes its sync
    search one byte later rather than trusting the candidate's length.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[UbxMessage]:
        self._buffer.extend(data)
        buffer = self._buffer
        length = len(buffer)
        messages: list[UbxMessage] = []
        offset = 0
        while offset + 8 <= length:
            if buffer[offset] != UBX_SYNC_1 or buffer[offset + 1] != UBX_SYNC_2:
                offset += 1
                continue
            payload_length = buffer[offset + 4] | (buffer[offset + 5] << 8)
            if payload_length > MAX_UBX_PAYLOAD_LENGTH:
                offset += 1
                continue
            message_end = offset + 6 + payload_length + 2
            if message_end > length:
                break
            message_class = buffer[offset + 2]
            message_id = buffer[offset + 3]
            payload = bytes(buffer[offset + 6 : offset + 6 + payload_length])
            expected = fletcher8_checksum(bytes(buffer[offset + 2 : offset + 6 + payload_length]))
            actual = (
                buffer[offset + 6 + payload_length],
                buffer[offset + 7 + payload_length],
            )
            checksum_valid = expected == actual
            if not checksum_valid:
                messages.append(UbxMessage(message_class, message_id, payload, False))
                offset += 1
                continue
            messages.append(UbxMessage(message_class, message_id, payload, True))
            offset = message_end
        del buffer[:offset]
        if len(buffer) > MAX_BUFFER_LENGTH:
            overflow = len(buffer) - MAX_BUFFER_LENGTH
            del buffer[:overflow]
        return messages


def decode_nav_clock(payload: bytes) -> NavClock:
    """Decode a UBX-NAV-CLOCK (class 0x01, id 0x22) payload.

    Field layout: iTOW (u4, ms), clkBias (i4, ns), clkDrift (i4, ns/s),
    tAcc (u4, ns), fAcc (u4, ps/s). The observed unknown-accuracy value
    ``0xFFFFFFFF`` is represented as ``None``.
    """

    if len(payload) != 20:
        raise ValueError(f"NAV-CLOCK payload must be exactly 20 bytes, got {len(payload)}")
    (
        itow_ms,
        clock_bias_ns,
        clock_drift_ns_per_s,
        time_accuracy_ns,
        freq_accuracy_ps_per_s,
    ) = unpack_from("<IiiII", payload, 0)
    return NavClock(
        itow_ms=itow_ms,
        clock_bias_ns=clock_bias_ns,
        clock_drift_ns_per_s=clock_drift_ns_per_s,
        time_accuracy_ns=(None if time_accuracy_ns == UNKNOWN_ACCURACY else time_accuracy_ns),
        freq_accuracy_ps_per_s=(None if freq_accuracy_ps_per_s == UNKNOWN_ACCURACY else freq_accuracy_ps_per_s),
    )


def decode_nav_pvt(payload: bytes) -> NavPvt:
    """Decode the fields needed for logging context from UBX-NAV-PVT.

    Only the fix and validity fields used by the clock log are decoded. The
    complete 92-byte payload remains available in the raw UBX ledger.
    """

    if len(payload) != 92:
        raise ValueError(f"NAV-PVT payload must be exactly 92 bytes, got {len(payload)}")
    itow_ms = unpack_from("<I", payload, 0)[0]
    valid = payload[11]
    fix_type = payload[20]
    flags = payload[21]
    num_satellites = payload[23]
    gnss_fix_ok = bool(flags & 0x01)
    diff_soln = bool(flags & 0x02)
    psm_state = (flags >> 2) & 0x07
    valid_date = bool(valid & 0x01)
    valid_time = bool(valid & 0x02)
    fully_resolved = bool(valid & 0x04)
    valid_mag = bool(valid & 0x08)
    return NavPvt(
        itow_ms=itow_ms,
        fix_type=fix_type,
        gnss_fix_ok=gnss_fix_ok,
        diff_soln=diff_soln,
        psm_state=psm_state,
        valid_date=valid_date,
        valid_time=valid_time,
        fully_resolved=fully_resolved,
        valid_mag=valid_mag,
        num_satellites=num_satellites,
    )


def decode_nav_sat(payload: bytes) -> NavSat:
    """Decode the satellite count from a UBX-NAV-SAT header.

    Header is 8 bytes; each svInfo block is 12 bytes. Structural length
    must be ``8 + 12*numSvs``. Captures on LBE-1421 show length 8 when
    ``numSvs=0`` and 20 when ``numSvs=1``.
    """

    if len(payload) < 8:
        raise ValueError(f"NAV-SAT payload too short: {len(payload)} bytes")
    itow_ms = unpack_from("<I", payload, 0)[0]
    num_satellites = payload[5]
    expected = 8 + 12 * num_satellites
    if len(payload) != expected:
        raise ValueError(
            f"NAV-SAT length {len(payload)} inconsistent with numSvs {num_satellites} (expected {expected})"
        )
    return NavSat(itow_ms=itow_ms, num_satellites=num_satellites)


def itow_gap_exceeds(a_ms: int, b_ms: int, threshold_ms: int = ITOW_GAP_THRESHOLD_MS) -> bool:
    """Return True if two iTOW values are not consecutive epochs.

    Handles GPS-week rollover (iTOW wraps 604800000 -> 0). ``a_ms`` is the
    earlier, ``b_ms`` the later sample. An iTOW gap larger than
    ``threshold_ms`` around the expected 1000 ms is reported.
    """

    delta = (b_ms - a_ms) % GPS_WEEK_MS
    return abs(delta - 1000) > threshold_ms
