from __future__ import annotations

import random
from collections.abc import Callable
from datetime import date

import numpy as np
import pytest

from cipherbreak.attacks import (
    COLUMN_TRIALS,
    AttackResult,
    brute_force,
    brute_force_scores,
    column_analysis,
    column_counts,
    known_plaintext,
    known_plaintext_with_date,
)
from cipherbreak.cipher import (
    KEY_SPACE,
    SHIFT_RANGE,
    Cipher,
    decrypt_with_shifts,
    encrypt_with_shifts,
    keygen,
)
from cipherbreak.scoring import chi_squared
from tests.conftest import SAMPLE_320

SEEDS = range(8)


def random_cipher(seed: int) -> Cipher:
    rng = random.Random(seed)
    on = date(2000, 1, 1).fromordinal(date(2000, 1, 1).toordinal() + rng.randrange(36_500))
    return Cipher(keygen(rng), on)


@pytest.mark.parametrize("seed", SEEDS)
def test_brute_force_recovers_key_on_320_chars(seed: int) -> None:
    c = random_cipher(seed)
    r = brute_force(c.encrypt(SAMPLE_320), true_shifts=c.shifts())
    assert isinstance(r, AttackResult)
    assert r.shifts == c.shifts()
    assert r.plaintext == SAMPLE_320
    assert r.candidates_tried == KEY_SPACE == 130_321
    assert r.rank_of_true_key == 1
    assert r.seconds >= 0


@pytest.mark.parametrize("seed", SEEDS)
def test_column_analysis_recovers_key_on_320_chars(seed: int) -> None:
    c = random_cipher(seed)
    r = column_analysis(c.encrypt(SAMPLE_320))
    assert r.shifts == c.shifts()
    assert r.plaintext == SAMPLE_320
    assert r.candidates_tried == COLUMN_TRIALS == 108
    assert r.rank_of_true_key is None


@pytest.mark.parametrize("seed", SEEDS)
def test_known_plaintext_needs_only_4_characters(seed: int) -> None:
    c = random_cipher(seed)
    ct = c.encrypt(SAMPLE_320)
    r = known_plaintext(ct, SAMPLE_320[:4])
    assert r.shifts == c.shifts()
    assert r.plaintext == SAMPLE_320


@pytest.mark.parametrize("seed", SEEDS)
def test_known_plaintext_with_date(seed: int) -> None:
    c = random_cipher(seed)
    r = known_plaintext_with_date(c.encrypt(SAMPLE_320), SAMPLE_320[:4], c.on)
    assert r.shifts == c.shifts()
    assert r.plaintext == SAMPLE_320
    assert 1 <= r.candidates_tried <= 10_000


def test_known_plaintext_with_date_search_count() -> None:
    # key 12345 on 2026-10-06: shifts (3, 8, 10, 10); the search reaches 1234 after 1235 tries.
    c = Cipher("12345", date(2026, 10, 6))
    r = known_plaintext_with_date(c.encrypt("hello world"), "hell", c.on)
    assert r.shifts == (3, 8, 10, 10)
    assert r.candidates_tried == 1235


def test_known_plaintext_with_wrong_date_finds_no_key() -> None:
    # Offsets for 2026-10-06 are (2, 6, 7, 6). A shift of 0 in column 0 would need key digit -2.
    ct = encrypt_with_shifts("hello world", (0, 0, 0, 0))
    with pytest.raises(ValueError, match="no key"):
        known_plaintext_with_date(ct, "hell", date(2026, 10, 6))


def test_known_plaintext_with_punctuation() -> None:
    c = Cipher("90210", date(2024, 2, 29))
    text = "he,lo world"  # ',' at position 2 is column 2 but passes through
    ct = c.encrypt(text)
    with pytest.raises(ValueError, match=r"column\(s\) \[2\]"):
        known_plaintext(ct, "he,lo")  # columns 0, 1, 3, 0: column 2 never seen
    r = known_plaintext(ct, "he,lo w")  # 'w' at position 6 covers column 2
    assert r.shifts == c.shifts()
    assert r.plaintext == text


def test_known_plaintext_rejects_bad_prefixes() -> None:
    ct = Cipher("12345", date(2026, 10, 6)).encrypt("hello world")
    with pytest.raises(ValueError, match="column"):
        known_plaintext(ct, "hel")
    with pytest.raises(ValueError, match="align"):
        known_plaintext(ct, "hel,")
    with pytest.raises(ValueError, match="longer"):
        known_plaintext(ct, "hello world and more")
    with pytest.raises(ValueError, match="inconsistent"):
        known_plaintext(ct, "hellq")  # 'q' at position 4 contradicts column 0's shift from 'h'


def test_known_plaintext_folds_prefix_case() -> None:
    c = Cipher("12345", date(2026, 10, 6))
    assert known_plaintext(c.encrypt("hello world"), "HELLO").shifts == c.shifts()


# --- brute force internals ----------------------------------------------------------------------


def test_brute_force_scores_equal_decrypt_then_score() -> None:
    """D7: scoring rotated column counts is identical to decrypting and scoring the text."""
    ct = random_cipher(3).encrypt(SAMPLE_320[:57] + ", with punctuation!")
    scores = brute_force_scores(ct)
    assert scores.shape == (KEY_SPACE,)
    rng = random.Random(0)
    for _ in range(200):
        t = tuple(rng.randrange(SHIFT_RANGE) for _ in range(4))
        flat = int(np.ravel_multi_index(t, (SHIFT_RANGE,) * 4))
        assert scores[flat] == pytest.approx(chi_squared(decrypt_with_shifts(ct, t)))


def test_brute_force_rank_counts_better_tuples() -> None:
    c = random_cipher(5)
    ct = c.encrypt(SAMPLE_320[:12])
    r = brute_force(ct, true_shifts=c.shifts())
    scores = brute_force_scores(ct)
    true_score = scores[np.ravel_multi_index(c.shifts(), (SHIFT_RANGE,) * 4)]
    assert r.rank_of_true_key == int((scores < true_score).sum()) + 1


def test_column_counts_skip_pass_through_but_keep_position() -> None:
    counts = column_counts("ab,d e")  # a@0 b@1 ','@2 d@3 ' '@4 e@5
    assert counts.sum() == 5
    assert counts[2].sum() == 0
    assert counts[0, 0] == 1 and counts[0, 26] == 1
    assert counts[1, 1] == 1 and counts[1, 4] == 1
    assert counts[3, 3] == 1


@pytest.mark.parametrize("attack", [brute_force, column_analysis])
def test_ciphertext_only_attacks_reject_empty_text(attack: Callable[[str], AttackResult]) -> None:
    for bad in ["", "1234!?"]:
        with pytest.raises(ValueError, match="no alphabet symbols"):
            attack(bad)


def test_short_ciphertext_does_not_crash() -> None:
    # Fewer than 4 symbols leaves a column empty; the attacks still return a result (likely wrong).
    for text in ["a", "ab", "abc"]:
        assert len(column_analysis(text).shifts) == 4
        assert len(brute_force(text).shifts) == 4
