"""What to use instead: authenticated encryption with AES-256-GCM (FR-18).

    python examples/aesgcm_demo.py

Rules (FR-19):

* never reuse a nonce with the same key: this demo draws a fresh 96-bit nonce for every message;
* never write your own cipher for real data: use a reviewed library such as ``cryptography``;
* keep keys out of source code: load them from a key manager or the environment, never a literal.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12  # 96 bits, the size GCM is designed for


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Return ``nonce || ciphertext || tag``. A fresh random nonce is drawn for every call."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, message: bytes, associated_data: bytes) -> bytes:
    """Verify and decrypt ``nonce || ciphertext || tag``; ``InvalidTag`` if anything changed."""
    nonce, ciphertext = message[:NONCE_BYTES], message[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def main() -> None:
    # In real code the key comes from a key manager, never from source code or a log line.
    key = AESGCM.generate_key(bit_length=256)
    aad = b"message-id=42;from=alice;to=bob"  # authenticated, not encrypted
    plaintext = b"meet me at the old mill at nine"

    message = encrypt(key, plaintext, aad)
    print(f"ciphertext ({len(message)} bytes, nonce + ciphertext + 16-byte tag): {message.hex()}")
    assert decrypt(key, message, aad) == plaintext
    print("round trip: ok")

    again = encrypt(key, plaintext, aad)
    print(f"same plaintext encrypted twice gives different output: {again != message}")

    tampered = bytearray(message)
    tampered[NONCE_BYTES] ^= 0x01  # flip one bit of the ciphertext
    try:
        decrypt(key, bytes(tampered), aad)
    except InvalidTag:
        print("tampered ciphertext: rejected with InvalidTag")
    else:  # pragma: no cover
        raise SystemExit("tampering was NOT detected")

    try:
        decrypt(key, message, b"message-id=43;from=alice;to=bob")
    except InvalidTag:
        print("changed associated data: rejected with InvalidTag")
    else:  # pragma: no cover
        raise SystemExit("associated-data change was NOT detected")


if __name__ == "__main__":
    main()
