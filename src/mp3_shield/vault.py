"""Option 1: Full AES-256-GCM encryption-at-rest + keyed HMAC-SHA256 SQLite manifest.

Provides mathematically lossless, bit-for-bit identical round-trip protection
against every class of scanner (hash lookup, metadata regex, Whisper/STT, Chromaprint).
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import KeyBundle
from .crypto import (
    compute_hmac_sha256,
    decrypt_bytes,
    encrypt_bytes,
    sha256_hex,
    verify_hmac_sha256,
)
from .mp3_frames import extract_audio_frames


@dataclass(frozen=True, slots=True)
class VaultProtectResult:
    """Report returned after encrypting an MP3 file at rest."""

    input_path: Path
    output_path: Path
    db_hash: str
    audio_hmac_sha256: str
    original_size: int
    encrypted_size: int


@dataclass(frozen=True, slots=True)
class VaultDecryptResult:
    """Report returned after decrypting an encrypted vault file back to MP3."""

    input_path: Path
    output_path: Path
    db_hash: str
    restored_sha256: str
    restored_size: int
    hmac_verified: bool | None


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes atomically using a sibling temporary file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp_path.write_bytes(data)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def protect_mp3(
    input_path: Path,
    output_path: Path,
    keys: KeyBundle,
) -> VaultProtectResult:
    """Encrypt an entire MP3 file at rest using AES-256-GCM and compute keyed HMACs."""
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input MP3 not found: {input_path}")

    raw_mp3 = input_path.read_bytes()
    if not raw_mp3:
        raise ValueError(f"Refusing to encrypt empty file: {input_path}")

    # 1. Keyed HMAC-SHA256 for DB indexing (bots cannot match known MP3 hashes)
    db_hash = compute_hmac_sha256(raw_mp3, keys.hmac_key)

    # 2. Keyed HMAC-SHA256 over strictly the raw MPEG audio frames (cross-mode dedup)
    audio_frames = extract_audio_frames(raw_mp3)
    audio_hmac = compute_hmac_sha256(audio_frames if audio_frames else raw_mp3, keys.hmac_key)

    # 3. Lossless authenticated encryption with unique 96-bit nonce
    encrypted_blob = encrypt_bytes(raw_mp3, keys.enc_key)
    _atomic_write(output_path, encrypted_blob)

    return VaultProtectResult(
        input_path=input_path,
        output_path=output_path,
        db_hash=db_hash,
        audio_hmac_sha256=audio_hmac,
        original_size=len(raw_mp3),
        encrypted_size=len(encrypted_blob),
    )


def decrypt_mp3_bytes(enc_path: Path, keys: KeyBundle) -> bytes:
    """Decrypt an encrypted MP3 blob in memory for authenticated on-the-fly streaming."""
    enc_path = enc_path.resolve()
    if not enc_path.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")
    blob = enc_path.read_bytes()
    return decrypt_bytes(blob, keys.enc_key)


def decrypt_mp3_file(
    enc_path: Path,
    output_path: Path,
    keys: KeyBundle,
    *,
    expected_db_hash: str | None = None,
) -> VaultDecryptResult:
    """Decrypt an encrypted MP3 file back to disk (bit-for-bit identical to original)."""
    output_path = output_path.resolve()
    raw_mp3 = decrypt_mp3_bytes(enc_path, keys)

    hmac_ok: bool | None = None
    if expected_db_hash is not None:
        hmac_ok = verify_hmac_sha256(raw_mp3, expected_db_hash, keys.hmac_key)
        if not hmac_ok:
            raise ValueError(
                f"HMAC mismatch for {enc_path}: decrypted content does not match expected db_hash."
            )

    _atomic_write(output_path, raw_mp3)
    return VaultDecryptResult(
        input_path=enc_path.resolve(),
        output_path=output_path,
        db_hash=compute_hmac_sha256(raw_mp3, keys.hmac_key),
        restored_sha256=sha256_hex(raw_mp3),
        restored_size=len(raw_mp3),
        hmac_verified=hmac_ok,
    )


class ManifestStore:
    """SQLite index storing ONLY keyed HMACs and paths (never keys, flags, or raw hashes)."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS protected_audio (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mode TEXT NOT NULL CHECK (mode IN ('vault', 'playable')),
                    db_hash TEXT NOT NULL,
                    audio_hmac TEXT NOT NULL,
                    stored_path TEXT NOT NULL UNIQUE,
                    original_name TEXT,
                    original_size INTEGER NOT NULL,
                    protected_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audio_hmac ON protected_audio(audio_hmac);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_db_hash ON protected_audio(db_hash);"
            )

    def upsert_record(
        self,
        *,
        mode: str,
        db_hash: str,
        audio_hmac: str,
        stored_path: Path,
        original_name: str | None,
        original_size: int,
        protected_size: int,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO protected_audio (
                    mode, db_hash, audio_hmac, stored_path,
                    original_name, original_size, protected_size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stored_path) DO UPDATE SET
                    mode=excluded.mode,
                    db_hash=excluded.db_hash,
                    audio_hmac=excluded.audio_hmac,
                    original_name=excluded.original_name,
                    original_size=excluded.original_size,
                    protected_size=excluded.protected_size,
                    created_at=excluded.created_at;
                """,
                (
                    mode,
                    db_hash,
                    audio_hmac,
                    str(stored_path),
                    original_name,
                    original_size,
                    protected_size,
                    now,
                ),
            )

    def find_by_audio_hmac(self, audio_hmac: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM protected_audio WHERE audio_hmac = ? ORDER BY id DESC;",
                (audio_hmac,),
            ).fetchall()
            return [dict(row) for row in rows]

    def find_by_stored_path(self, stored_path: Path) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM protected_audio WHERE stored_path = ?;",
                (str(stored_path.resolve()),),
            ).fetchone()
            return dict(row) if row else None

    def list_all(self) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM protected_audio ORDER BY id ASC;").fetchall()
            return [dict(row) for row in rows]
