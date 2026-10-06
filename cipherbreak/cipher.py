"""The classical shift cipher rebuilt from the 2024 ``enigma.py`` script.

Shift derivation (docs/DECISIONS.md D1, D2):

* the key is 5 decimal digits ``k0..k4``; only ``k0..k3`` are used, exactly as in the original;
* the date offsets are the last 4 digits of ``int(DDMMYY) ** 2``;
* shift ``i`` is ``k_i + offset_i``, a value in 0..18, so there are 19**4 = 130,321 shift tuples.

Character ``j`` of the text (counting every character, including ones outside the alphabet) is
shifted by ``shifts[j % 4]`` modulo 27. Uppercase ASCII letters are folded to lowercase with a
``CaseFoldWarning``; characters outside the alphabet pass through unchanged but still advance the
position (D3).
"""

from __future__ import annotations

import random
import warnings
from collections.abc import Sequence
from datetime import date

from cipherbreak.alphabet import ALPHABET, SIZE, has_ascii_upper, index_of

KEY_LENGTH = 5
PERIOD = 4
MAX_SHIFT = 18
SHIFT_RANGE = MAX_SHIFT + 1  # 19 values per position
KEY_SPACE = SHIFT_RANGE**PERIOD  # 130,321 shift tuples

Shifts = tuple[int, int, int, int]


class CaseFoldWarning(UserWarning):
    """Uppercase input was folded to lowercase; the output will not restore its case."""


def validate_key(key: str) -> str:
    """Return ``key`` if it is exactly 5 ASCII digits, else raise ``ValueError``."""
    if len(key) != KEY_LENGTH or not all(c in "0123456789" for c in key):
        raise ValueError("key must be exactly 5 decimal digits")
    return key


def date_offsets(on: date) -> Shifts:
    """Return the 4 date-derived offsets: the last 4 digits of ``int(DDMMYY) ** 2``."""
    square = int(f"{on.day:02}{on.month:02}{on.year % 100:02}") ** 2
    digits = str(square)[-PERIOD:]
    return (int(digits[0]), int(digits[1]), int(digits[2]), int(digits[3]))


def shifts_for(key: str, on: date) -> Shifts:
    """Return the shift tuple for ``key`` on ``on``. The 5th key digit is ignored (D2)."""
    validate_key(key)
    o = date_offsets(on)
    return (
        int(key[0]) + o[0],
        int(key[1]) + o[1],
        int(key[2]) + o[2],
        int(key[3]) + o[3],
    )


def _shift_text(text: str, shifts: Sequence[int], direction: int) -> str:
    if not shifts:
        raise ValueError("at least one shift is required")
    if has_ascii_upper(text):
        warnings.warn(
            "uppercase letters were folded to lowercase; case is not preserved",
            CaseFoldWarning,
            stacklevel=3,
        )
    period = len(shifts)
    out: list[str] = []
    for pos, ch in enumerate(text):
        i = index_of(ch)
        out.append(ch if i is None else ALPHABET[(i + direction * shifts[pos % period]) % SIZE])
    return "".join(out)


def encrypt_with_shifts(text: str, shifts: Sequence[int]) -> str:
    """Encrypt ``text`` with an explicit shift sequence."""
    return _shift_text(text, shifts, 1)


def decrypt_with_shifts(text: str, shifts: Sequence[int]) -> str:
    """Decrypt ``text`` with an explicit shift sequence."""
    return _shift_text(text, shifts, -1)


class Cipher:
    """The shift cipher for one key on one explicit date. Never reads the system clock."""

    __slots__ = ("_key", "_on", "_shifts")

    def __init__(self, key: str, on: date) -> None:
        self._key = validate_key(key)
        self._on = on
        self._shifts = shifts_for(key, on)

    def __repr__(self) -> str:
        # Never expose the key or shifts in a repr (FR-8 spirit: no accidental key printing).
        return f"Cipher(key=<hidden>, on={self._on.isoformat()})"

    @property
    def on(self) -> date:
        return self._on

    def shifts(self) -> Shifts:
        """Return the 4-shift tuple, each value in 0..18."""
        return self._shifts

    def encrypt(self, text: str) -> str:
        return encrypt_with_shifts(text, self._shifts)

    def decrypt(self, text: str) -> str:
        return decrypt_with_shifts(text, self._shifts)


def keygen(rng: random.Random) -> str:
    """Return a random 5-digit key drawn from the injected generator."""
    return f"{rng.randrange(10**KEY_LENGTH):0{KEY_LENGTH}d}"
