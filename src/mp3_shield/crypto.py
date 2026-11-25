"""Cryptographic primitives: stdlib HMAC/SHA-256/MD5 + lazy AES-256-GCM."""

from __future__ import annotations

import hashlib
import hmac
import os

NONCE_SIZE = 12  # 96-bit NIST-recommended GCM nonce
GCM_TAG_SIZE = 16  # 128-bit GCM authentication tag
MIN_BLOB_SIZE = NONCE_SIZE + GCM_TAG_SIZE


class DecryptionError(Exception):
    """Raised when AES-GCM decryption fails due to wrong key, truncation, or tampering."""


def _import_aesgcm():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "Optional package `cryptography` is required for AES-256-GCM encryption/decryption. "
            "Install it with: pip install cryptography (or sudo apt install python3-cryptography)."
        ) from exc
    return AESGCM, InvalidTag


def encrypt_bytes(
    plaintext: bytes,
    enc_key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Encrypt bytes with AES-256-GCM using a fresh 96-bit CSPRNG nonce.

    Output layout: nonce (12 bytes) || ciphertext || auth_tag (16 bytes).
    """
    AESGCM, _ = _import_aesgcm()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(enc_key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt_bytes(
    blob: bytes,
    enc_key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate an AES-256-GCM blob produced by `encrypt_bytes`."""
    AESGCM, InvalidTag = _import_aesgcm()
    if len(blob) < MIN_BLOB_SIZE:
        raise DecryptionError(
            f"Encrypted payload too short ({len(blob)} bytes; minimum {MIN_BLOB_SIZE})."
        )
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:]
    try:
        return AESGCM(enc_key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError(
            "AES-256-GCM authentication failed: wrong key or ciphertext was modified."
        ) from exc


def compute_hmac_sha256(data: bytes, hmac_key: bytes) -> str:
    """Compute a keyed HMAC-SHA256 hex digest for secure DB indexing and deduplication."""
    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()


def verify_hmac_sha256(data: bytes, expected_hex: str, hmac_key: bytes) -> bool:
    """Constant-time verification of a keyed HMAC-SHA256 digest."""
    computed = compute_hmac_sha256(data, hmac_key)
    return hmac.compare_digest(computed, expected_hex.lower())


def sha256_hex(data: bytes) -> str:
    """Unkeyed SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def md5_hex(data: bytes) -> str:
    """Unkeyed MD5 hex digest."""
    return hashlib.md5(data).hexdigest()
