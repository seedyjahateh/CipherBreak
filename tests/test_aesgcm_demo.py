from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEMO = Path(__file__).resolve().parent.parent / "examples" / "aesgcm_demo.py"


def load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aesgcm_demo", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = load_demo()
KEY = AESGCM.generate_key(bit_length=256)
AAD = b"header"


def test_round_trip() -> None:
    for pt in [b"", b"x", b"meet me at the old mill at nine" * 100]:
        assert demo.decrypt(KEY, demo.encrypt(KEY, pt, AAD), AAD) == pt


def test_key_is_256_bits_and_nonce_is_96_bits() -> None:
    assert len(KEY) == 32
    msg = demo.encrypt(KEY, b"abc", AAD)
    assert len(msg) == 12 + 3 + 16


def test_fresh_nonce_every_message() -> None:
    nonces = {demo.encrypt(KEY, b"same", AAD)[:12] for _ in range(200)}
    assert len(nonces) == 200


@pytest.mark.parametrize("index", [0, 12, -1])  # nonce, ciphertext, tag
def test_tampering_raises_invalid_tag(index: int) -> None:
    msg = bytearray(demo.encrypt(KEY, b"attack at dawn", AAD))
    msg[index] ^= 0x01
    with pytest.raises(InvalidTag):
        demo.decrypt(KEY, bytes(msg), AAD)


def test_wrong_associated_data_or_key_raises() -> None:
    msg = demo.encrypt(KEY, b"attack at dawn", AAD)
    with pytest.raises(InvalidTag):
        demo.decrypt(KEY, msg, b"other")
    with pytest.raises(InvalidTag):
        demo.decrypt(AESGCM.generate_key(bit_length=256), msg, AAD)


def test_demo_script_runs() -> None:
    proc = subprocess.run([sys.executable, str(DEMO)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "round trip: ok" in proc.stdout
    assert "tampered ciphertext: rejected with InvalidTag" in proc.stdout
    assert "changed associated data: rejected with InvalidTag" in proc.stdout
