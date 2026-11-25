"""Zero-dependency Polymorphic MP3 Mutator.

Keeps every output a valid, directly playable .mp3 file with ZERO audio distortion
while mutating bytes throughout the ENTIRE file:
  1. Strips all existing ID3v2, trailing ID3v1, Enhanced ID3v1 (TAG+), and APEv2 tags.
  2. Walks every MPEG Layer III frame by exact calculated length and randomizes
     non-acoustic header bits (Private, Copyright, Original) on every non-CRC frame.
  3. Optionally prepends 1-2 valid silent MPEG boundary frames matched to stream specs.
  4. Prepends a fresh random-length ID3v2.3 header with a random-owner PRIV salt frame
     (and optional AES-256-GCM encrypted flag PRIV frame if `cryptography` is installed).
  5. Mathematically verifies zero acoustic distortion on every single frame before returning.
"""

from __future__ import annotations

import os
import secrets
import string
import struct
from dataclasses import dataclass
from pathlib import Path

from .config import KeyBundle
from .crypto import (
    compute_hmac_sha256,
    decrypt_bytes,
    encrypt_bytes,
    md5_hex,
    sha256_hex,
)
from .mp3_frames import (
    NON_ACOUSTIC_B2_MASK,
    NON_ACOUSTIC_B3_MASK,
    assert_zero_acoustic_distortion,
    build_silent_mpeg_frame,
    canonicalize_acoustic_stream,
    extract_audio_stream,
    is_vbr_header_frame,
    parse_id3v2_frames,
    to_synchsafe,
    walk_mpeg_frames,
)

DEFAULT_MIN_SALT = 32
DEFAULT_MAX_SALT = 287
DEFAULT_FLAG_OWNER = "enc_flag"
_OWNER_ALPHABET = string.ascii_lowercase + string.digits


@dataclass(frozen=True, slots=True)
class MutationResult:
    """Detailed verification report for a polymorphically mutated playable MP3."""

    input_path: Path
    output_path: Path
    total_frames: int
    mutated_frames: int
    crc_skipped_frames: int
    prepended_silent_frames: int
    changed_audio_bytes: int
    id3_salt_bytes: int
    file_size_before: int
    file_size_after: int
    original_file_sha256: str
    new_file_sha256: str
    original_file_md5: str
    new_file_md5: str
    original_audio_sha256: str
    new_audio_sha256: str
    canonical_acoustic_sha256: str
    acoustic_hmac_sha256: str | None
    has_encrypted_flag: bool
    zero_distortion_verified: bool


def _random_owner_name() -> str:
    """Generate a random ASCII PRIV owner identifier so bots cannot YARA-match a fixed string."""
    length = 6 + secrets.randbelow(9)  # 6..14 chars
    return "".join(secrets.choice(_OWNER_ALPHABET) for _ in range(length))


def _encode_id3v23_priv_frame(owner: str, payload_bytes: bytes) -> bytes:
    """Build a spec-compliant ID3v2.3 PRIV frame (4B ID + 4B big-endian size + 2B flags + data)."""
    body = owner.encode("latin-1") + b"\x00" + payload_bytes
    return b"PRIV" + struct.pack(">I", len(body)) + b"\x00\x00" + body


def build_random_id3v2(
    *,
    min_salt: int = DEFAULT_MIN_SALT,
    max_salt: int = DEFAULT_MAX_SALT,
    salt_owner: str | None = None,
    extra_priv_frames: list[tuple[str, bytes]] | None = None,
) -> tuple[bytes, int]:
    """Construct a valid ID3v2.3 header with random-length CSPRNG salt and optional PRIV frames."""
    if min_salt < 16 or max_salt < min_salt:
        raise ValueError(f"Invalid salt bounds: min_salt={min_salt}, max_salt={max_salt}.")

    salt_len = min_salt + secrets.randbelow(max_salt - min_salt + 1)
    owner = salt_owner if salt_owner is not None else _random_owner_name()

    frames_blob = bytearray(_encode_id3v23_priv_frame(owner, os.urandom(salt_len)))
    if extra_priv_frames:
        for extra_owner, extra_data in extra_priv_frames:
            frames_blob.extend(_encode_id3v23_priv_frame(extra_owner, extra_data))

    header = b"ID3\x03\x00\x00" + to_synchsafe(len(frames_blob)) + bytes(frames_blob)
    return header, salt_len


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp_path.write_bytes(data)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def mutate_mp3(
    input_path: Path,
    *,
    output_path: Path | None = None,
    in_place: bool = False,
    prepend_silence: int = 0,
    min_salt: int = DEFAULT_MIN_SALT,
    max_salt: int = DEFAULT_MAX_SALT,
    salt_owner: str | None = None,
    flag_to_hide: str | None = None,
    flag_owner: str = DEFAULT_FLAG_OWNER,
    keys: KeyBundle | None = None,
) -> MutationResult:
    """Polymorphically mutate an MP3 across metadata AND every MPEG frame header.

    Guarantees:
      - Output is a valid, directly playable .mp3 file.
      - Whole-file MD5/SHA-256 AND raw-audio-stream SHA-256 both change.
      - Zero audio distortion (decoded PCM is 100% identical when prepend_silence=0).
      - Zero external dependencies (unless `flag_to_hide` AES-GCM encryption is requested).
    """
    if not in_place and output_path is None:
        raise ValueError("Provide output_path or explicitly set in_place=True.")
    if prepend_silence < 0 or prepend_silence > 10:
        raise ValueError("prepend_silence must be between 0 and 10 frames.")
    if flag_to_hide is not None and keys is None:
        raise ValueError("A KeyBundle (--env / MP3_SHIELD_ENC_KEY) is required when using --flag.")

    input_path = input_path.resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input MP3 not found: {input_path}")

    original_bytes = input_path.read_bytes()
    orig_audio = extract_audio_stream(original_bytes)
    if not orig_audio:
        raise ValueError(f"No MPEG audio data found in {input_path}")

    frames = walk_mpeg_frames(orig_audio)
    if not frames:
        raise ValueError(f"No valid MPEG Layer III frames found in {input_path}")

    # Canonical acoustic hash & optional keyed HMAC (consistent across repeated mutations)
    canonical_bytes = canonicalize_acoustic_stream(original_bytes)
    canonical_sha256 = sha256_hex(canonical_bytes)
    acoustic_hmac = compute_hmac_sha256(canonical_bytes, keys.hmac_key) if keys is not None else None

    # Walk every MPEG frame and randomize non-acoustic bits (Private, Copyright, Original)
    audio = bytearray(orig_audio)
    mutated_frames = 0
    crc_skipped_frames = 0

    for frame in frames:
        if not frame.no_crc:
            crc_skipped_frames += 1
            continue

        b2 = audio[frame.offset + 2]
        b3 = audio[frame.offset + 3]

        audio[frame.offset + 2] = (b2 & ~NON_ACOUSTIC_B2_MASK) | secrets.randbits(1)
        audio[frame.offset + 3] = (b3 & ~NON_ACOUSTIC_B3_MASK) | (secrets.randbits(2) << 2)
        mutated_frames += 1

    # Guarantee at least 1 byte changed inside the MPEG stream if any non-CRC frame exists
    changed_audio_bytes = sum(1 for a, b in zip(orig_audio, audio) if a != b)
    if mutated_frames > 0 and changed_audio_bytes == 0:
        first_mutable = next(f for f in frames if f.no_crc)
        audio[first_mutable.offset + 2] ^= NON_ACOUSTIC_B2_MASK
        changed_audio_bytes = 1

    # Optional: prepend 1-2 valid silent MPEG frames (defeats frame-count & fixed-offset bots)
    actual_prepended = 0
    silent_prefix = bytearray()
    if prepend_silence > 0:
        template = frames[1] if (is_vbr_header_frame(orig_audio, frames[0]) and len(frames) > 1) else frames[0]
        for _ in range(prepend_silence):
            silent_prefix.extend(build_silent_mpeg_frame(template))
            actual_prepended += 1

    mutated_audio_stream = bytes(silent_prefix) + bytes(audio)

    # Optional encrypted flag inside ID3v2.3 PRIV frame
    extra_priv: list[tuple[str, bytes]] = []
    if flag_to_hide is not None:
        assert keys is not None
        enc_flag = encrypt_bytes(flag_to_hide.encode("utf-8"), keys.enc_key)
        extra_priv.append((flag_owner, enc_flag))

    # Build fresh random-length ID3v2.3 header (random PRIV salt, zero legacy tags)
    id3_header, salt_len = build_random_id3v2(
        min_salt=min_salt,
        max_salt=max_salt,
        salt_owner=salt_owner,
        extra_priv_frames=extra_priv,
    )
    final_bytes = id3_header + mutated_audio_stream

    # Mathematical proof of ZERO acoustic distortion before writing to disk
    assert_zero_acoustic_distortion(
        original_bytes,
        final_bytes,
        prepended_silent_frames=actual_prepended,
    )

    orig_file_sha = sha256_hex(original_bytes)
    new_file_sha = sha256_hex(final_bytes)
    if orig_file_sha == new_file_sha:
        raise RuntimeError("Mutation failed: output file SHA-256 matches input SHA-256.")

    target_path = input_path if in_place else output_path.resolve()  # type: ignore[union-attr]
    _atomic_write(target_path, final_bytes)

    return MutationResult(
        input_path=input_path,
        output_path=target_path,
        total_frames=len(frames),
        mutated_frames=mutated_frames,
        crc_skipped_frames=crc_skipped_frames,
        prepended_silent_frames=actual_prepended,
        changed_audio_bytes=changed_audio_bytes,
        id3_salt_bytes=salt_len,
        file_size_before=len(original_bytes),
        file_size_after=len(final_bytes),
        original_file_sha256=orig_file_sha,
        new_file_sha256=new_file_sha,
        original_file_md5=md5_hex(original_bytes),
        new_file_md5=md5_hex(final_bytes),
        original_audio_sha256=sha256_hex(orig_audio),
        new_audio_sha256=sha256_hex(mutated_audio_stream),
        canonical_acoustic_sha256=canonical_sha256,
        acoustic_hmac_sha256=acoustic_hmac,
        has_encrypted_flag=flag_to_hide is not None,
        zero_distortion_verified=True,
    )


def extract_encrypted_flag(
    mp3_path: Path,
    keys: KeyBundle,
    *,
    flag_owner: str = DEFAULT_FLAG_OWNER,
) -> str | None:
    """Decrypt and return the hidden AES-256-GCM flag stored in an ID3v2 PRIV frame."""
    raw = mp3_path.resolve().read_bytes()
    owner_prefix = flag_owner.encode("latin-1") + b"\x00"
    for frame_id, payload in parse_id3v2_frames(raw):
        if frame_id == "PRIV" and payload.startswith(owner_prefix):
            ct = payload[len(owner_prefix) :]
            return decrypt_bytes(ct, keys.enc_key).decode("utf-8")
    return None
