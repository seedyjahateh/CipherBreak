"""Three attacks that recover the shift tuple (FR-9 to FR-11).

* :func:`brute_force` scores all 19**4 = 130,321 shift tuples (ciphertext only).
* :func:`column_analysis` treats the ciphertext as 4 independent Caesar ciphers and tries 27 shifts
  per column: 108 trials (ciphertext only). This is the central result.
* :func:`known_plaintext` subtracts a known prefix from the ciphertext;
  :func:`known_plaintext_with_date` searches the 10**4 key-digit combinations given the date.

Column ``c`` holds the alphabet symbols at raw text positions ``j`` with ``j % 4 == c``; characters
outside the alphabet advance the position but are not counted (docs/DECISIONS.md D3).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

import numpy as np

from cipherbreak.alphabet import SIZE, ascii_lower, index_of
from cipherbreak.cipher import (
    KEY_SPACE,
    PERIOD,
    SHIFT_RANGE,
    Shifts,
    date_offsets,
    decrypt_with_shifts,
)
from cipherbreak.scoring import FloatArray, chi_squared_batch

COLUMN_TRIALS = PERIOD * SIZE  # 108
DATE_KEY_SPACE = 10**PERIOD  # 10,000


@dataclass(frozen=True)
class AttackResult:
    shifts: Shifts
    plaintext: str
    candidates_tried: int
    seconds: float
    rank_of_true_key: int | None = None


def column_counts(ciphertext: str) -> FloatArray:
    """A ``(4, 27)`` matrix: counts of each ciphertext symbol in each of the 4 columns."""
    counts = np.zeros((PERIOD, SIZE), dtype=np.float64)
    for pos, ch in enumerate(ciphertext):
        i = index_of(ch)
        if i is not None:
            counts[pos % PERIOD, i] += 1
    return counts


def _decrypted_column_counts(counts: FloatArray, n_shifts: int) -> FloatArray:
    """``out[c, s]`` = symbol counts of column ``c`` decrypted with shift ``s``.

    Decrypting maps ciphertext symbol ``x`` to ``(x - s) mod 27``, so plaintext symbol ``p`` comes
    from ciphertext symbol ``(p + s) mod 27``: a left rotation of the count vector by ``s``.
    """
    idx = (np.arange(SIZE)[None, :] + np.arange(n_shifts)[:, None]) % SIZE  # (n_shifts, 27)
    return counts[:, idx]  # (4, n_shifts, 27)


def _require_symbols(counts: FloatArray) -> None:
    if counts.sum() == 0:
        raise ValueError("ciphertext contains no alphabet symbols")


def _as_shifts(values: Sequence[int]) -> Shifts:
    return (int(values[0]), int(values[1]), int(values[2]), int(values[3]))


def brute_force_scores(ciphertext: str) -> FloatArray:
    """Chi-squared score of every shift tuple in 0..18, flattened in C order (130,321 values).

    Entry ``np.ravel_multi_index(t, (19,) * 4)`` is the score of ``decrypt_with_shifts(ct, t)``.
    """
    counts = column_counts(ciphertext)
    _require_symbols(counts)
    r = _decrypted_column_counts(counts, SHIFT_RANGE)  # (4, 19, 27)
    totals = (
        r[0][:, None, None, None, :]
        + r[1][None, :, None, None, :]
        + r[2][None, None, :, None, :]
        + r[3][None, None, None, :, :]
    ).reshape(KEY_SPACE, SIZE)
    return chi_squared_batch(totals)


def brute_force(ciphertext: str, true_shifts: Sequence[int] | None = None) -> AttackResult:
    """Score every shift tuple in 0..18 and return the most English-like decryption (FR-9).

    Scores are computed on counts: the decrypted text's symbol counts are the sum of each column's
    rotated counts, which is identical to decrypting and counting (D7) but vectorised.
    If ``true_shifts`` is given, the result includes its 1-based rank (1 + tuples scoring better).
    """
    start = time.perf_counter()
    scores = brute_force_scores(ciphertext)
    flat = int(np.argmin(scores))
    best = _as_shifts(
        [flat // SHIFT_RANGE ** (PERIOD - 1 - i) % SHIFT_RANGE for i in range(PERIOD)]
    )
    rank: int | None = None
    if true_shifts is not None:
        t = [int(s) % SIZE for s in true_shifts]
        if all(s < SHIFT_RANGE for s in t):
            true_score = scores[np.ravel_multi_index(t, (SHIFT_RANGE,) * PERIOD)]
            rank = int(np.count_nonzero(scores < true_score)) + 1
    seconds = time.perf_counter() - start
    return AttackResult(
        best, decrypt_with_shifts(ciphertext, best), KEY_SPACE, seconds, rank_of_true_key=rank
    )


def column_analysis(ciphertext: str) -> AttackResult:
    """Break each of the 4 columns as a Caesar cipher: 27 shifts each, 108 trials (FR-10)."""
    start = time.perf_counter()
    counts = column_counts(ciphertext)
    _require_symbols(counts)
    r = _decrypted_column_counts(counts, SIZE)  # (4, 27, 27)
    scores = chi_squared_batch(r.reshape(PERIOD * SIZE, SIZE)).reshape(PERIOD, SIZE)
    # A column with no symbols scores inf for every shift; argmin then picks shift 0.
    best = _as_shifts([int(np.argmin(scores[c])) for c in range(PERIOD)])
    seconds = time.perf_counter() - start
    return AttackResult(best, decrypt_with_shifts(ciphertext, best), COLUMN_TRIALS, seconds)


def _shifts_from_prefix(ciphertext: str, known_prefix: str) -> list[int | None]:
    """Shift per column from aligned (ciphertext, plaintext) symbol pairs; ``None`` if unseen."""
    if len(known_prefix) > len(ciphertext):
        raise ValueError("known prefix is longer than the ciphertext")
    found: list[int | None] = [None] * PERIOD
    for pos, (c, p) in enumerate(zip(ciphertext, ascii_lower(known_prefix), strict=False)):
        ci, pi = index_of(c), index_of(p)
        if (ci is None) != (pi is None):
            raise ValueError(f"known prefix does not align with the ciphertext at position {pos}")
        if ci is None or pi is None:
            if c != p:
                raise ValueError(f"known prefix does not match pass-through character at {pos}")
            continue
        s = (ci - pi) % SIZE
        col = pos % PERIOD
        if found[col] is None:
            found[col] = s
        elif found[col] != s:
            raise ValueError(f"known prefix is inconsistent with a period-4 shift at {pos}")
    return found


def known_plaintext(ciphertext: str, known_prefix: str) -> AttackResult:
    """Recover each shift by subtraction modulo 27 from a known plaintext prefix (FR-11).

    The prefix must put at least one alphabet symbol in each of the 4 columns; 4 consecutive
    alphabet characters are enough.
    """
    start = time.perf_counter()
    found = _shifts_from_prefix(ciphertext, known_prefix)
    missing = [c for c in range(PERIOD) if found[c] is None]
    if missing:
        raise ValueError(
            f"known prefix gives no symbol for column(s) {missing}; "
            "at least 4 aligned alphabet characters are needed"
        )
    shifts = _as_shifts([s for s in found if s is not None])
    seconds = time.perf_counter() - start
    return AttackResult(shifts, decrypt_with_shifts(ciphertext, shifts), PERIOD, seconds)


def known_plaintext_with_date(ciphertext: str, known_prefix: str, on: date) -> AttackResult:
    """Derive the date offsets, then search the 10**4 key-digit combinations (FR-11 variant).

    Each candidate ``k0..k3`` gives shifts ``k_i + offset_i``; the first candidate consistent with
    every aligned prefix symbol wins. Raises ``ValueError`` if no key fits (wrong date or prefix).
    """
    start = time.perf_counter()
    found = _shifts_from_prefix(ciphertext, known_prefix)
    if all(s is None for s in found):
        raise ValueError("known prefix contains no alphabet symbols")
    offsets = date_offsets(on)
    for tried, n in enumerate(range(DATE_KEY_SPACE), start=1):
        digits = (n // 1000, n // 100 % 10, n // 10 % 10, n % 10)
        candidate = _as_shifts([digits[i] + offsets[i] for i in range(PERIOD)])
        if all(found[i] is None or found[i] == candidate[i] % SIZE for i in range(PERIOD)):
            seconds = time.perf_counter() - start
            return AttackResult(
                candidate, decrypt_with_shifts(ciphertext, candidate), tried, seconds
            )
    raise ValueError("no key is consistent with this prefix and date")
