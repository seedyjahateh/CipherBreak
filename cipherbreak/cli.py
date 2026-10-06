"""Command-line entry point: ``cipherbreak encrypt|decrypt|attack``.

The CLI never prints a key or shift tuple it was not asked to print (FR-8): ``encrypt`` and
``decrypt`` print only the transformed text unless ``--show-shifts`` is given.
"""

from __future__ import annotations

import argparse
import sys
import warnings
from collections.abc import Sequence
from datetime import date

from cipherbreak.alphabet import has_ascii_upper
from cipherbreak.cipher import CaseFoldWarning, Cipher

type _SubParsers = argparse._SubParsersAction[argparse.ArgumentParser]


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid date {value!r}: use YYYY-MM-DD") from exc


def _read_text(value: str) -> str:
    return sys.stdin.read() if value == "-" else value


def _add_cipher_command(sub: _SubParsers, name: str) -> None:
    verb = "Encrypt" if name == "encrypt" else "Decrypt"
    p = sub.add_parser(
        name,
        help=f"{verb} text with a 5-digit key and a date",
        description=f"{verb} TEXT with a 5-digit key and an explicit date.",
    )
    p.add_argument("--key", required=True, help="5-digit key, e.g. 12345")
    p.add_argument(
        "--date", required=True, type=_parse_date, help="date the offsets come from (YYYY-MM-DD)"
    )
    p.add_argument(
        "--show-shifts",
        action="store_true",
        help="also print the derived shift tuple to stderr (off by default)",
    )
    p.add_argument("text", help="text to process, or '-' to read standard input")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherbreak",
        description=(
            "A classical period-4 shift cipher (Vigenere family, not the WWII Enigma machine), "
            "and three attacks that break it."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    _add_cipher_command(sub, "encrypt")
    _add_cipher_command(sub, "decrypt")
    return parser


def _run_cipher(args: argparse.Namespace) -> int:
    try:
        cipher = Cipher(args.key, args.date)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = _read_text(args.text)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CaseFoldWarning)
        result = cipher.encrypt(text) if args.command == "encrypt" else cipher.decrypt(text)
    if has_ascii_upper(text):
        print("warning: uppercase letters were folded to lowercase", file=sys.stderr)
    sys.stdout.write(result if args.text == "-" else result + "\n")
    if args.show_shifts:
        print(f"shifts: {list(cipher.shifts())}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("encrypt", "decrypt"):
        return _run_cipher(args)
    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
