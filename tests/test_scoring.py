"""Scoring tests.

Chi-squared on single-symbol counts ignores order, so reordering a text never changes its score.
"Shuffled" text here therefore means a random *substitution* of the alphabet (a wrong decryption
looks like that), and shifted text means a Caesar shift of the English sample.
"""

from __future__ import annotations

import json
import random
from importlib import resources

import numpy as np
import pytest

from cipherbreak.alphabet import ALPHABET, SIZE
from cipherbreak.cipher import encrypt_with_shifts
from cipherbreak.scoring import (
    chi_squared,
    chi_squared_batch,
    chi_squared_counts,
    english_frequencies,
    symbol_counts,
)
from tests.conftest import GETTYSBURG


def substitute(text: str, rng: random.Random) -> str:
    perm = list(ALPHABET)
    rng.shuffle(perm)
    return text.translate(str.maketrans(ALPHABET, "".join(perm)))


def test_frequency_table_is_documented_and_valid() -> None:
    raw = resources.files("cipherbreak").joinpath("data/english_freq.json").read_text("utf-8")
    data = json.loads(raw)
    assert data["source_url"].startswith("https://www.gutenberg.org/")
    assert len(data["source_sha256"]) == 64
    assert set(data["frequencies"]) == set("abcdefghijklmnopqrstuvwxyz") | {"space"}
    f = english_frequencies()
    assert f.shape == (SIZE,)
    assert f.sum() == pytest.approx(1.0)
    # space is the most common symbol, then e
    assert int(np.argmax(f)) == ALPHABET.index(" ")
    assert sorted(range(SIZE), key=lambda i: -f[i])[1] == ALPHABET.index("e")


def test_reordering_does_not_change_score() -> None:
    chars = list(GETTYSBURG)
    random.Random(0).shuffle(chars)
    assert chi_squared("".join(chars)) == pytest.approx(chi_squared(GETTYSBURG))


@pytest.mark.parametrize("seed", range(25))
def test_english_scores_better_than_substituted(seed: int) -> None:
    rng = random.Random(seed)
    assert chi_squared(GETTYSBURG) < chi_squared(substitute(GETTYSBURG, rng))


def test_english_scores_better_than_every_caesar_shift() -> None:
    base = chi_squared(GETTYSBURG)
    for s in range(1, SIZE):
        assert base < chi_squared(encrypt_with_shifts(GETTYSBURG, [s]))


def test_uniform_scores_worse_than_english() -> None:
    n = len(GETTYSBURG)
    uniform = np.full(SIZE, n / SIZE)
    assert chi_squared_counts(uniform) > chi_squared(GETTYSBURG)


def test_uniform_scores_worse_than_english_like_distributions() -> None:
    # Uniform is the worst of these English-shaped count vectors drawn from the reference table.
    rng = np.random.default_rng(0)
    n = 1000
    uniform_score = chi_squared_counts(np.full(SIZE, n / SIZE))
    for _ in range(50):
        sample = rng.multinomial(n, english_frequencies()).astype(np.float64)
        assert chi_squared_counts(sample) < uniform_score


def test_uniform_is_not_worse_than_a_shifted_english_text() -> None:
    # Documented caveat: a Caesar shift can move space (~18% of symbols) onto a rare letter such as
    # 'z', which scores far worse than uniform. Uniform is the worst *English-shaped* input only.
    n = len(GETTYSBURG)
    uniform_score = chi_squared_counts(np.full(SIZE, n / SIZE))
    worst_shift = max(chi_squared(encrypt_with_shifts(GETTYSBURG, [s])) for s in range(SIZE))
    assert worst_shift > uniform_score


def test_symbol_counts_ignore_other_characters() -> None:
    counts = symbol_counts("ab, A!")
    assert counts[0] == 2 and counts[1] == 1 and counts[26] == 1 and counts.sum() == 4


def test_empty_text_scores_inf() -> None:
    assert chi_squared("") == float("inf")
    assert chi_squared("123!?") == float("inf")


def test_batch_matches_single() -> None:
    rng = np.random.default_rng(1)
    m = rng.integers(0, 20, size=(30, SIZE)).astype(np.float64)
    batch = chi_squared_batch(m)
    for row, score in zip(m, batch, strict=True):
        assert chi_squared_counts(row) == pytest.approx(score)


def test_batch_rejects_bad_shape() -> None:
    with pytest.raises(ValueError):
        chi_squared_batch(np.zeros((3, 26)))
