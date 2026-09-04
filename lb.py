#!/usr/bin/env python3
"""One command line for reusable LBE-1421 device tools."""

import argparse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from lbe142x_protocol import parse_frequency

Command = Callable[[Any], int | None]

__all__ = ("main",)

_DEVICE_ACTIONS = {
    "list": "list",
    "inspect": "detail",
    "configure": "modify",
    "set": "set-frequency",
    "identify": "identify",
    "log": "log",
    "analyze-hid": "analyze-hid",
    "reprocess-hid": "reprocess-hid",
}


def _device_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-s", "--serial", metavar="S/N", help="Serial number of GPS device")
    parser.add_argument("-d", "--device", metavar="PATH", help="USB HID device path")


def _configuration_options(parser: argparse.ArgumentParser) -> None:
    options = parser.add_argument_group(title="Configuration")
    options.add_argument("--f1", metavar="HZ", type=parse_frequency, help="Output 1 frequency")
    options.add_argument("--f2", metavar="HZ", type=parse_frequency, help="Output 2 frequency")
    options.add_argument("--save", action="store_true", help="Save frequency to flash memory")
    options.add_argument("--pll", dest="pll", action="store_const", const=True, help="Set PLL mode")
    options.add_argument("--fll", dest="pll", action="store_const", const=False, help="Set FLL mode")
    for output in (1, 2):
        options.add_argument(
            f"--enable{output}", dest=f"out{output}", action="store_const", const=True, help=f"Enable output {output}"
        )
        options.add_argument(
            f"--disable{output}",
            dest=f"out{output}",
            action="store_const",
            const=False,
            help=f"Disable output {output}",
        )
        options.add_argument(
            f"--level{output}-low",
            dest=f"out{output}low",
            action="store_const",
            const=True,
            help=f"Output {output} drive low level",
        )
        options.add_argument(
            f"--level{output}-normal",
            dest=f"out{output}low",
            action="store_const",
            const=False,
            help=f"Output {output} drive normal level",
        )
    options.add_argument(
        "--pps-enable", dest="pps", action="store_const", const=True, help="Enable PPS signal on output 1"
    )
    options.add_argument(
        "--pps-disable", dest="pps", action="store_const", const=False, help="Disable PPS signal on output 1"
    )


def _command(
    subparsers: Any,
    name: str,
    help_text: str,
    *,
    aliases: Sequence[str] = (),
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(name, aliases=list(aliases), help=help_text)
    parser.set_defaults(action=name)
    return parser


def _build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    commands = parser.add_subparsers(dest="command", title="commands")

    inspect = _command(commands, "inspect", "show identity, lock state, mode and setpoints", aliases=("detail", "d"))
    _device_options(inspect)
    inspect.add_argument("--json", action="store_true", help="emit machine-readable device state")

    log = _command(commands, "log", "record status, raw HID and UBX telemetry")
    _device_options(log)
    log.add_argument("--output", type=Path, required=True, help="new output directory")

    set_frequency = _command(commands, "set", "set and verify one exact output frequency", aliases=("set-frequency",))
    _device_options(set_frequency)
    set_frequency.add_argument("--output", type=int, choices=(1, 2), required=True, help="output number")
    set_frequency.add_argument("--hz", type=parse_frequency, required=True, help="exact decimal frequency in hertz")
    set_frequency.add_argument("--persist", action="store_true", help="save to flash instead of RAM")
    set_frequency.add_argument(
        "--readback-delay", type=float, default=0.0, metavar="SECONDS",
        help="wait before reading back the configured frequency",
    )
    set_frequency.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    configure = _command(commands, "configure", "change device configuration", aliases=("modify", "m"))
    _device_options(configure)
    _configuration_options(configure)

    _command(commands, "list", "list devices", aliases=("l",))
    identify = _command(commands, "identify", "identify a selected device", aliases=("i",))
    _device_options(identify)

    analyze = _command(commands, "analyze-hid", "summarize a captured hid_raw.csv")
    analyze.add_argument("--input", type=Path, required=True, help="log directory containing hid_raw.csv")

    reprocess = _command(commands, "reprocess-hid", "rebuild UBX tables from hid_raw.csv")
    reprocess.add_argument("--input", type=Path, required=True, help="log directory containing hid_raw.csv")
    reprocess.add_argument("--output", type=Path, required=True, help="new output directory")
    return parser


def _resolve(action: str, supplied: Mapping[str, Command]) -> Command:
    if action in supplied:
        return supplied[action]
    if action in _DEVICE_ACTIONS:
        from lbe142x import _command_registry

        return _command_registry()[action]
    raise ValueError(f"no implementation for command {action!r}")


def _invoke(parser: argparse.ArgumentParser, args: Any, supplied: Mapping[str, Command]) -> int:
    try:
        result = _resolve(args.action, supplied)(args)
    except ValueError as error:
        parser.error(str(error))
    return 0 if result is None else result


def _run(
    argv: Sequence[str] | None = None,
    supplied: Mapping[str, Command] | None = None,
    prog: str | None = None,
) -> int:
    parser = _build_parser(prog)
    args = parser.parse_args(argv)
    if not hasattr(args, "action"):
        parser.print_help()
        return 0
    return _invoke(parser, args, {} if supplied is None else supplied)


def main(argv: Sequence[str] | None = None) -> int:
    return _run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
