"""The 27-symbol alphabet: ``a``-``z`` then space, with index maps.

Only ASCII letters are part of the alphabet. Uppercase ASCII letters map to the same index as their
lowercase form (the cipher folds them to lowercase, see docs/DECISIONS.md D3); every other character
is outside the alphabet.
"""

from __future__ import annotations

import re

ALPHABET = "abcdefghijklmnopqrstuvwxyz "
SIZE = len(ALPHABET)  # 27
SPACE_INDEX = ALPHABET.index(" ")

INDEX: dict[str, int] = {ch: i for i, ch in enumerate(ALPHABET)}
UPPER_INDEX: dict[str, int] = {ch.upper(): i for i, ch in enumerate(ALPHABET) if ch != " "}

_NON_ALPHA_RUN = re.compile(r"[^a-z]+")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text: str) -> str:
    """Lowercase ASCII ``A``-``Z`` only, leaving every other character untouched."""
    return text.translate(_ASCII_LOWER)


def has_ascii_upper(text: str) -> bool:
    return any(ch in UPPER_INDEX for ch in text)


def index_of(ch: str) -> int | None:
    """Return the alphabet index of ``ch`` (case-insensitive for ASCII letters), or ``None``."""
    i = INDEX.get(ch)
    if i is None:
        i = UPPER_INDEX.get(ch)
    return i


def normalize(text: str) -> str:
    """Lowercase ``text`` and collapse every run of non ``a-z`` characters to a single space.

    The result contains only alphabet symbols and has no leading or trailing space.
    """
    return _NON_ALPHA_RUN.sub(" ", text.lower()).strip()
