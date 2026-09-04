"""LBE-1421 USB HID report encoding and decoding."""

from decimal import Decimal, InvalidOperation, localcontext
from struct import pack, unpack_from
from typing import NamedTuple

REPORT_LENGTH = 60
STATUS_FEATURE_REPORT_ID = 0x4B
FREQUENCY_SCALE = 1 << 32
MIN_FREQUENCY_HZ = Decimal(1)
MAX_FREQUENCY_HZ = (Decimal(800_000_000), Decimal(1_400_000_000))


class LBE1421Status(NamedTuple):
    loss_count: int
    gps_locked: bool
    pll_locked: bool
    antenna_ok: bool
    led1: bool
    led2: bool
    out1_enabled: bool
    out2_enabled: bool
    pps_enabled: bool
    out1_frequency_hz: Decimal
    out2_frequency_hz: Decimal
    fll_mode: bool
    out1_low_power: bool
    out2_low_power: bool
    unverified_tail: bytes


def decode_frequency(fractional_word: int, integer_word: int) -> Decimal:
    """Decode the device's unsigned Q32.32 frequency representation in hertz."""

    with localcontext() as context:
        context.prec = 50
        return Decimal(integer_word) + Decimal(fractional_word) / FREQUENCY_SCALE


def parse_frequency(value: str) -> Decimal:
    """Parse a finite decimal frequency for argparse."""

    try:
        frequency_hz = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("frequency must be a decimal number") from error
    if not frequency_hz.is_finite():
        raise ValueError("frequency must be finite")
    return frequency_hz


def encode_frequency(frequency_hz: Decimal) -> bytes:
    """Encode hertz as the device's fractional-word-first Q32.32 value."""

    if not frequency_hz.is_finite() or frequency_hz < 0:
        raise ValueError("frequency must be finite and non-negative")
    numerator, denominator = frequency_hz.as_integer_ratio()
    scaled, remainder = divmod(numerator * FREQUENCY_SCALE, denominator)
    if 2 * remainder >= denominator:
        scaled += 1
    integer_word, fractional_word = divmod(scaled, FREQUENCY_SCALE)
    if integer_word >= (1 << 32):
        raise ValueError("frequency too large for Q32.32 representation")
    return pack("<II", fractional_word, integer_word)


def quantize_frequency(frequency_hz: Decimal) -> Decimal:
    """Return the exact frequency represented by the nearest Q32.32 value."""

    fractional_word, integer_word = unpack_from("<II", encode_frequency(frequency_hz))
    return decode_frequency(fractional_word, integer_word)


def format_frequency(frequency_hz: Decimal) -> str:
    """Format frequency at the LBE-1421's documented 1 microhertz resolution."""

    value = frequency_hz.quantize(Decimal("0.000001"))
    formatted = format(value, "f").rstrip("0").rstrip(".")
    return formatted or "0"


def validate_frequency(output: int, frequency_hz: Decimal) -> None:
    if output not in (0, 1):
        raise ValueError(f"Invalid output number {output + 1}")
    if not frequency_hz.is_finite():
        raise ValueError("Frequency must be finite")
    maximum_hz = MAX_FREQUENCY_HZ[output]
    if not MIN_FREQUENCY_HZ <= frequency_hz <= maximum_hz:
        raise ValueError(f"Frequency for output {output + 1} must be between {MIN_FREQUENCY_HZ} and {maximum_hz} Hz")


def frequency_command(output: int, frequency_hz: Decimal, save: bool) -> bytes:
    """Build a complete hidapi feature report for one output frequency."""

    validate_frequency(output, frequency_hz)
    opcodes = ((5, 6), (9, 10))
    report = bytearray(REPORT_LENGTH)
    report[0] = opcodes[output][save]
    report[1:9] = encode_frequency(frequency_hz)
    return bytes(report)


UBX_WRAP_OPCODE = 0x08
UBX_CFG_MSG_CLASS = 0x06
UBX_CFG_MSG_ID = 0x01
UBX_NAV_MESSAGE_CLASS = 0x01  # Kept local to avoid a parsing-module dependency.

# This value selects every Nth receiver update; it is not a frequency in hertz.
# On the LBE-1421, 10 gives about one message per second.
UBX_CFG_MSG_POLL_LENGTH = 0x02
UBX_CFG_MSG_SET_LENGTH = 0x08
UBX_CFG_MSG_RATES_COUNT = 6


def ubx_poll_message_rate_command(nav_message_id: int) -> bytes:
    """Build the HID wrap for a UBX-CFG-MSG poll (2-byte payload).

    The LBE-1421 forwards this as ``B5 62 06 01 02 00 01 <id>`` with
    checksum to its internal GNSS receiver. The receiver replies on the
    HID input-report channel with CFG-MSG containing the six per-port
    rates for that NAV message.
    """

    report = bytearray(REPORT_LENGTH)
    report[0] = UBX_WRAP_OPCODE
    report[1] = UBX_CFG_MSG_CLASS
    report[2] = UBX_CFG_MSG_ID
    report[3] = UBX_CFG_MSG_POLL_LENGTH
    report[4] = 0x00
    report[5] = UBX_NAV_MESSAGE_CLASS
    report[6] = nav_message_id
    return bytes(report)


def ubx_set_message_rates_command(nav_message_id: int, rates: tuple[int, ...]) -> bytes:
    """Build the HID wrap for UBX-CFG-MSG set-rates (8-byte payload).

    Payload layout: ``msgClass msgID rate[6]`` where ``rate[i]`` is the
    navigation-epoch divisor for port ``i`` (0=DDC/I2C, 1=UART1,
    2=UART2, 3=USB, 4=SPI, 5=reserved per u-blox spec). The LBE-1421's
    HID stream has been observed to follow ``rate[0]``; zero disables
    that NAV message on that port. Send ``rates`` exactly as previously
    polled to restore the original configuration.
    """

    if len(rates) != UBX_CFG_MSG_RATES_COUNT:
        raise ValueError(f"CFG-MSG requires {UBX_CFG_MSG_RATES_COUNT} rates")
    for rate in rates:
        if not 0 <= rate <= 255:
            raise ValueError(f"rate {rate} out of range 0..255")
    report = bytearray(REPORT_LENGTH)
    report[0] = UBX_WRAP_OPCODE
    report[1] = UBX_CFG_MSG_CLASS
    report[2] = UBX_CFG_MSG_ID
    report[3] = UBX_CFG_MSG_SET_LENGTH
    report[4] = 0x00
    report[5] = UBX_NAV_MESSAGE_CLASS
    report[6] = nav_message_id
    report[7:13] = bytes(rates)
    return bytes(report)


def decode_status(report: bytes) -> LBE1421Status:
    """Decode one status report while leaving unknown bytes uninterpreted."""

    if len(report) < 21:
        raise ValueError(f"Status report is too short: {len(report)} bytes")
    flags = report[1]
    return LBE1421Status(
        loss_count=report[0],
        gps_locked=bool(flags & 0x01),
        pll_locked=bool(flags & 0x02),
        antenna_ok=bool(flags & 0x04),
        led1=bool(flags & 0x08),
        led2=bool(flags & 0x10),
        out1_enabled=bool(flags & 0x20),
        out2_enabled=bool(flags & 0x40),
        pps_enabled=bool(flags & 0x80),
        out1_frequency_hz=decode_frequency(*unpack_from("<II", report, 2)),
        out2_frequency_hz=decode_frequency(*unpack_from("<II", report, 10)),
        fll_mode=bool(report[18]),
        out1_low_power=bool(report[19]),
        out2_low_power=bool(report[20]),
        unverified_tail=report[21:],
    )
