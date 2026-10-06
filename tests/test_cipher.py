from __future__ import annotations

import importlib
import random
import warnings
from datetime import date

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cipherbreak.alphabet import ALPHABET, SIZE, ascii_lower, has_ascii_upper, index_of, normalize
from cipherbreak.cipher import (
    KEY_SPACE,
    MAX_SHIFT,
    CaseFoldWarning,
    Cipher,
    date_offsets,
    decrypt_with_shifts,
    encrypt_with_shifts,
    keygen,
    shifts_for,
)

ON = date(2026, 10, 6)


def original_encrypt(message: str, key: str, on: date) -> str:
    """A line-for-line port of the 2024 enigma.py encrypt, with the key and date injected."""
    message = message.lower()
    chars = [chr(i) for i in range(ord("a"), ord("z") + 1)] + [" "]
    keys = [int(d) for d in key]
    date_key = int(f"{on.day:02}{on.month:02}{str(on.year)[2:]}") ** 2
    offsets = [int(d) for d in str(date_key)[-4:]]
    shifts = [keys[i] + offsets[i] for i in range(4)]
    out = []
    for i, ch in enumerate(message):
        if ch in chars:
            out.append(chars[(chars.index(ch) + shifts[i % len(shifts)]) % len(chars)])
        else:
            out.append(ch)
    return "".join(out)


# --- fixed vectors ---------------------------------------------------------------------------


def test_date_offsets_vector() -> None:
    # 061026 ** 2 = 3_724_172_676 -> last four digits 2676
    assert date_offsets(ON) == (2, 6, 7, 6)


def test_shifts_vector() -> None:
    assert Cipher("12345", ON).shifts() == (3, 8, 10, 10)


def test_encrypt_vector() -> None:
    assert Cipher("12345", ON).encrypt("hello world") == "kmvvrhfyutn"
    assert Cipher("12345", ON).decrypt("kmvvrhfyutn") == "hello world"


@pytest.mark.parametrize("seed", range(20))
def test_matches_original_script_on_lowercase(seed: int) -> None:
    rng = random.Random(seed)
    key = keygen(rng)
    on = date(2000 + rng.randrange(100), rng.randrange(1, 13), rng.randrange(1, 29))
    text = "".join(rng.choice(ALPHABET + ",.!'") for _ in range(60))
    assert Cipher(key, on).encrypt(text) == original_encrypt(text, key, on)


# --- round trip ------------------------------------------------------------------------------

keys = st.text(alphabet="0123456789", min_size=5, max_size=5)
dates = st.dates(min_value=date(1900, 1, 1), max_value=date(2099, 12, 31))


no_ascii_upper = st.text().filter(lambda t: not has_ascii_upper(t))


@given(text=no_ascii_upper, key=keys, on=dates)
def test_round_trip_exact_without_uppercase(text: str, key: str, on: date) -> None:
    c = Cipher(key, on)
    assert c.decrypt(c.encrypt(text)) == text


@pytest.mark.filterwarnings("ignore::cipherbreak.cipher.CaseFoldWarning")
@given(text=st.text(), key=keys, on=dates)
def test_round_trip_any_text_is_ascii_lowercased(text: str, key: str, on: date) -> None:
    c = Cipher(key, on)
    assert c.decrypt(c.encrypt(text)) == ascii_lower(text)


@given(text=st.text(alphabet=ALPHABET), key=keys, on=dates)
def test_alphabet_text_stays_in_alphabet(text: str, key: str, on: date) -> None:
    ct = Cipher(key, on).encrypt(text)
    assert len(ct) == len(text)
    assert set(ct) <= set(ALPHABET)


@given(text=no_ascii_upper, shifts=st.lists(st.integers(0, 40), min_size=1, max_size=8))
def test_round_trip_explicit_shifts(text: str, shifts: list[int]) -> None:
    assert decrypt_with_shifts(encrypt_with_shifts(text, shifts), shifts) == text


@given(key=keys, on=dates)
def test_shifts_in_range(key: str, on: date) -> None:
    s = Cipher(key, on).shifts()
    assert len(s) == 4
    assert all(0 <= x <= MAX_SHIFT for x in s)


def test_key_space() -> None:
    assert KEY_SPACE == 19**4 == 130_321


# --- pass-through characters ------------------------------------------------------------------


def test_pass_through_characters_unchanged_and_advance_position() -> None:
    c = Cipher("12345", ON)  # shifts (3, 8, 10, 10)
    ct = c.encrypt("a,a.a!a?a")
    assert ct[1::2] == ",.!?"
    # positions 0, 2, 4, 6, 8 use shifts[0], shifts[2], shifts[0], shifts[2], shifts[0]
    assert ct[0::2] == "dkdkd"


def test_non_ascii_passes_through() -> None:
    c = Cipher("12345", ON)
    # includes the Kelvin sign (which str.lower maps to "k") and the dotted capital I
    for ch in ["é", "€", chr(0x212A), chr(0x0130), "\n", "\t", "0", "3"]:
        assert c.encrypt(ch) == ch


# --- case -------------------------------------------------------------------------------------


def test_uppercase_is_folded_with_warning() -> None:
    c = Cipher("12345", ON)
    with pytest.warns(CaseFoldWarning):
        ct = c.encrypt("Hello World")
    assert ct == "kmvvrhfyutn"
    assert c.decrypt(ct) == "hello world"


def test_uppercase_encrypts_like_lowercase() -> None:
    c = Cipher("98765", ON)
    text = "the quick brown fox"
    with pytest.warns(CaseFoldWarning):
        upper = c.encrypt(text.upper())
    assert upper == c.encrypt(text)


def test_lowercase_input_does_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Cipher("12345", ON).encrypt("all lowercase, no warning")


def test_why_case_cannot_be_preserved() -> None:
    # 'q' (16) + 37 = 53 = 26 (mod 27), which is space: it has no case, so an uppercase 'Q' could
    # never be restored on decryption. This is why D3 folds case instead of preserving it.
    assert encrypt_with_shifts("q", [37]) == " "
    assert decrypt_with_shifts(" ", [37]) == "q"


# --- the 5th digit decision ---------------------------------------------------------------------


@given(prefix=st.text(alphabet="0123456789", min_size=4, max_size=4), on=dates)
def test_fifth_digit_is_ignored(prefix: str, on: date) -> None:
    results = {shifts_for(prefix + d, on) for d in "0123456789"}
    assert len(results) == 1


# --- validation, keygen, import side effects ---------------------------------------------------


FULLWIDTH_12345 = "".join(chr(0xFF11 + i) for i in range(5))


@pytest.mark.parametrize("bad", ["", "1234", "123456", "12a45", " 1234", FULLWIDTH_12345])
def test_invalid_key_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        Cipher(bad, ON)


def test_repr_hides_key() -> None:
    r = repr(Cipher("12345", ON))
    assert "12345" not in r
    assert "3, 8" not in r


def test_keygen_is_deterministic_and_valid() -> None:
    a = [keygen(random.Random(7)) for _ in range(3)]
    assert a[0] == a[1] == a[2]
    rng = random.Random(1)
    ks = [keygen(rng) for _ in range(500)]
    assert all(len(k) == 5 and k.isdigit() for k in ks)
    assert len(set(ks)) > 450


def test_import_has_no_side_effects(capsys: pytest.CaptureFixture[str]) -> None:
    import cipherbreak.cipher

    importlib.reload(cipherbreak.cipher)
    assert capsys.readouterr() == ("", "")


# --- alphabet helpers -------------------------------------------------------------------------


def test_alphabet() -> None:
    assert SIZE == 27
    assert index_of("a") == 0 and index_of("A") == 0 and index_of(" ") == 26
    assert index_of(chr(0x212A)) is None  # Kelvin sign


def test_normalize() -> None:
    assert normalize("  Hello,   World!\n It's 1999. ") == "hello world it s"
