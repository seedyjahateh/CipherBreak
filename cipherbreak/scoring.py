"""Chi-squared scoring against English letter-and-space frequencies (FR-9, FR-10, FR-12).

Lower is better: a text whose symbol counts match English closely scores low.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

import numpy as np
import numpy.typing as npt

from cipherbreak.alphabet import ALPHABET, SIZE, index_of

FloatArray = npt.NDArray[np.float64]


@cache
def english_frequencies() -> FloatArray:
    """The 27 English probabilities (a-z, space) from ``data/english_freq.json``, summing to 1."""
    raw = resources.files("cipherbreak").joinpath("data/english_freq.json").read_text("utf-8")
    table = json.loads(raw)["frequencies"]
    freqs = np.array(
        [float(table["space" if ch == " " else ch]) for ch in ALPHABET], dtype=np.float64
    )
    freqs /= freqs.sum()
    freqs.flags.writeable = False
    return freqs


def symbol_counts(text: str) -> FloatArray:
    """Counts of the 27 alphabet symbols in ``text``; other characters are ignored."""
    counts = np.zeros(SIZE, dtype=np.float64)
    for ch in text:
        i = index_of(ch)
        if i is not None:
            counts[i] += 1
    return counts


def chi_squared_counts(counts: FloatArray | Sequence[float]) -> float:
    """Chi-squared statistic of a 27-bin count vector against English. ``inf`` if empty."""
    return float(chi_squared_batch(np.asarray(counts, dtype=np.float64)[None, :])[0])


def chi_squared_batch(counts: FloatArray) -> FloatArray:
    """Chi-squared of every row of an ``(n, 27)`` count matrix against English, vectorised."""
    if counts.ndim != 2 or counts.shape[1] != SIZE:
        raise ValueError(f"expected an (n, {SIZE}) count matrix, got shape {counts.shape}")
    totals = counts.sum(axis=1, keepdims=True)
    expected = totals * english_frequencies()[None, :]
    with np.errstate(divide="ignore", invalid="ignore"):
        stats = ((counts - expected) ** 2 / expected).sum(axis=1)
    stats[totals[:, 0] == 0] = np.inf
    return stats


def chi_squared(text: str) -> float:
    """Chi-squared statistic of ``text`` against English frequencies (lower is more English)."""
    return chi_squared_counts(symbol_counts(text))
