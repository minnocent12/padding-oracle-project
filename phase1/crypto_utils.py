# phase1/crypto_utils.py

"""
crypto_utils.py — AES-CBC encryption/decryption with PKCS#7 padding.

INTENTIONALLY VULNERABLE: decrypt() raises distinct exceptions for:
  - Invalid padding  → PaddingError
  - Valid padding    → returns plaintext

This distinction is exactly what a padding oracle attacker exploits.
"""

import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # AES block size in bytes


# ── Custom Exceptions ─────────────────────────────────────────────────────────

class PaddingError(Exception):
    """Raised when PKCS#7 padding is invalid."""
    pass


# ── PKCS#7 Padding ────────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes) -> bytes:
    """Pad data to a multiple of BLOCK_SIZE using PKCS#7."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove and validate PKCS#7 padding.
    Raises PaddingError if padding is malformed.
    """
    if not data:
        raise PaddingError("Empty data")

    pad_len = data[-1]

    # Padding byte must be between 1 and BLOCK_SIZE
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise PaddingError(f"Invalid padding byte: {pad_len}")

    # All padding bytes must equal pad_len
    padding = data[-pad_len:]
    if padding != bytes([pad_len] * pad_len):
        raise PaddingError("Padding bytes are inconsistent")

    return data[:-pad_len]


# ── AES-CBC Encrypt ───────────────────────────────────────────────────────────

def cbc_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-CBC with a random IV.

    Returns:
        iv         (16 bytes)
        ciphertext (padded, multiple of 16 bytes)
    """
    iv = os.urandom(BLOCK_SIZE)
    padded = pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)
    return iv, ciphertext


# ── AES-CBC Decrypt ───────────────────────────────────────────────────────────

def cbc_decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-CBC ciphertext.

    VULNERABILITY: Raises PaddingError with a DISTINCT response when
    padding is invalid. This leaks oracle information to an attacker.

    Returns:
        plaintext (unpadded)

    Raises:
        PaddingError: if PKCS#7 padding validation fails
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise PaddingError("Ciphertext length is not a multiple of block size")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # ← This is the oracle leak point
    return pkcs7_unpad(padded_plaintext)