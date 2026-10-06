"""Project Gutenberg plain-text helpers: checksum, header/footer stripping, normalising."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from cipherbreak.alphabet import normalize

_START = re.compile(r"^\*\*\* ?START OF (THE|THIS) PROJECT GUTENBERG EBOOK.*$", re.M | re.I)
_END = re.compile(r"^\*\*\* ?END OF (THE|THIS) PROJECT GUTENBERG EBOOK.*$", re.M | re.I)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_gutenberg(text: str) -> str:
    """Return the body of a Gutenberg text, without the licence header and footer."""
    start = _START.search(text)
    end = _END.search(text)
    if start is None or end is None or end.start() <= start.end():
        raise ValueError("could not find the Project Gutenberg START/END markers")
    return text[start.end() : end.start()]


def load_normalized(path: Path) -> str:
    """Read a Gutenberg file, strip header/footer and normalise to the 27-symbol alphabet."""
    raw = path.read_text(encoding="utf-8-sig")
    return normalize(strip_gutenberg(raw))
