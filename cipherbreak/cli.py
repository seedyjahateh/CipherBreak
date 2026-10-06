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
from pathlib import Path

from cipherbreak.alphabet import has_ascii_upper
from cipherbreak.attacks import (
    brute_force,
    column_analysis,
    known_plaintext,
    known_plaintext_with_date,
)
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
            "and three attacks that break it. Not for real data: use AES-GCM instead."
        ),
        epilog=(
            "examples:\n"
            '  cipherbreak encrypt --key 12345 --date 2026-10-06 "hello world"\n'
            '  cipherbreak decrypt --key 12345 --date 2026-10-06 "kmvvrhfyutn"\n'
            "  cipherbreak attack --method columns --ciphertext ct.txt\n"
            "  cipherbreak attack --method known --ciphertext ct.txt --known-prefix four"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    _add_cipher_command(sub, "encrypt")
    _add_cipher_command(sub, "decrypt")
    a = sub.add_parser(
        "attack",
        help="Recover the shifts and plaintext from a ciphertext file",
        description=(
            "Recover the shift tuple and plaintext. brute: score all 130,321 shift tuples. "
            "columns: break each of the 4 columns as a Caesar cipher (108 trials). "
            "known: subtract a known plaintext prefix; with --date, search the 10,000 key-digit "
            "combinations instead."
        ),
    )
    a.add_argument(
        "--method", required=True, choices=["brute", "columns", "known"], help="attack to run"
    )
    a.add_argument(
        "--ciphertext", required=True, type=Path, metavar="FILE", help="UTF-8 ciphertext file"
    )
    a.add_argument(
        "--known-prefix",
        metavar="TEXT",
        help="known plaintext prefix, at least 4 characters (required for --method known)",
    )
    a.add_argument(
        "--date",
        type=_parse_date,
        help="with --method known: derive offsets from this date (YYYY-MM-DD)",
    )
    return parser


def _run_attack(args: argparse.Namespace) -> int:
    try:
        ciphertext = args.ciphertext.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.ciphertext}: {exc.strerror}", file=sys.stderr)
        return 2
    if args.method != "known" and (args.known_prefix is not None or args.date is not None):
        print("error: --known-prefix and --date only apply to --method known", file=sys.stderr)
        return 2
    try:
        if args.method == "brute":
            result = brute_force(ciphertext)
        elif args.method == "columns":
            result = column_analysis(ciphertext)
        elif args.known_prefix is None:
            print("error: --method known needs --known-prefix", file=sys.stderr)
            return 2
        elif args.date is not None:
            result = known_plaintext_with_date(ciphertext, args.known_prefix, args.date)
        else:
            result = known_plaintext(ciphertext, args.known_prefix)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"method: {args.method}{' (with date)' if args.date is not None else ''}")
    print(f"shifts: {list(result.shifts)}")
    print(f"candidates tried: {result.candidates_tried:,}")
    print(f"time: {result.seconds * 1000:.2f} ms")
    print("plaintext:")
    print(result.plaintext.rstrip("\n"))
    return 0


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
    if args.command == "attack":
        return _run_attack(args)
    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
