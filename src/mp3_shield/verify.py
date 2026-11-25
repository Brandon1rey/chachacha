"""Zero-distortion verification (structural frame proof + optional ffmpeg PCM hash) and bot audit."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .crypto import md5_hex, sha256_hex
from .mp3_frames import (
    AudioIntegrityError,
    assert_zero_acoustic_distortion,
    extract_audio_stream,
    inspect_mp3_layout,
    parse_id3v2_frames,
    walk_mpeg_frames,
)

DEFAULT_FLAG_PATTERNS = [
    r"FLAG\{[^}\r\n]+\}",
    r"CTF\{[^}\r\n]+\}",
    r"flag\{[^}\r\n]+\}",
]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Comparison proving byte mutation across the file AND zero audio distortion."""

    original_path: str
    mutated_path: str
    file_size_before: int
    file_size_after: int
    file_sha256_before: str
    file_sha256_after: str
    file_md5_before: str
    file_md5_after: str
    raw_audio_sha256_before: str
    raw_audio_sha256_after: str
    whole_file_hash_changed: bool
    raw_audio_stream_hash_changed: bool
    changed_audio_stream_bytes: int
    total_frames_before: int
    total_frames_after: int
    prepended_silent_frames: int
    structural_zero_distortion: bool
    pcm_sha256_before: str | None
    pcm_sha256_after: str | None
    pcm_identical: bool | None
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Bot-simulation scan result for a single MP3 or encrypted blob."""

    path: str
    file_size: int
    file_sha256: str
    file_md5: str
    raw_audio_sha256: str
    mpeg_frame_count: int
    has_id3v2: bool
    has_id3v1: bool
    has_apev2: bool
    exposed_id3_frames: list[str]
    plaintext_flag_hits: list[str]
    whole_file_hash_busted: bool | None
    raw_audio_hash_busted: bool | None
    zero_acoustic_distortion: bool | None
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compute_pcm_sha256(mp3_path: Path) -> str:
    """Decode MP3 to raw s16le PCM via ffmpeg and return its SHA-256 hex digest."""
    ffmpeg_bin = shutil.which("ffmpeg")
    if ffmpeg_bin is None:
        raise FileNotFoundError(
            "ffmpeg not found in PATH. Install it on Linux with: sudo apt install ffmpeg"
        )

    proc = subprocess.run(
        [ffmpeg_bin, "-v", "error", "-i", str(mp3_path.resolve()), "-f", "s16le", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"ffmpeg failed decoding {mp3_path}: {err}")
    return hashlib.sha256(proc.stdout).hexdigest()


def verify_mutation(
    original_path: Path,
    mutated_path: Path,
    *,
    check_pcm: bool = False,
) -> VerificationReport:
    """Verify byte-level polymorphism AND zero acoustic distortion between two MP3 files."""
    original_path = original_path.resolve()
    mutated_path = mutated_path.resolve()

    orig_bytes = original_path.read_bytes()
    mut_bytes = mutated_path.read_bytes()

    orig_audio = extract_audio_stream(orig_bytes)
    mut_audio = extract_audio_stream(mut_bytes)

    frames_before = walk_mpeg_frames(orig_audio)
    frames_after = walk_mpeg_frames(mut_audio)
    prepended = max(0, len(frames_after) - len(frames_before))

    try:
        assert_zero_acoustic_distortion(orig_bytes, mut_bytes, prepended_silent_frames=prepended)
        structural_ok = True
    except AudioIntegrityError:
        structural_ok = False

    # Count differing bytes inside aligned MPEG audio stream
    if len(orig_audio) == len(mut_audio):
        changed_audio_bytes = sum(1 for a, b in zip(orig_audio, mut_audio) if a != b)
    else:
        # Compare aligned suffix after any prepended silent frames
        offset_diff = len(mut_audio) - len(orig_audio)
        if offset_diff > 0:
            aligned_mut = mut_audio[offset_diff:]
            changed_audio_bytes = offset_diff + sum(1 for a, b in zip(orig_audio, aligned_mut) if a != b)
        else:
            changed_audio_bytes = abs(offset_diff)

    file_sha_before = sha256_hex(orig_bytes)
    file_sha_after = sha256_hex(mut_bytes)
    file_md5_before = md5_hex(orig_bytes)
    file_md5_after = md5_hex(mut_bytes)
    audio_sha_before = sha256_hex(orig_audio)
    audio_sha_after = sha256_hex(mut_audio)

    whole_changed = (file_sha_before != file_sha_after) and (file_md5_before != file_md5_after)
    audio_changed = audio_sha_before != audio_sha_after

    pcm_before: str | None = None
    pcm_after: str | None = None
    pcm_identical: bool | None = None
    if check_pcm:
        pcm_before = compute_pcm_sha256(original_path)
        pcm_after = compute_pcm_sha256(mutated_path)
        pcm_identical = pcm_before == pcm_after

    passed = (
        whole_changed
        and audio_changed
        and structural_ok
        and (pcm_identical is not False)
    )

    return VerificationReport(
        original_path=str(original_path),
        mutated_path=str(mutated_path),
        file_size_before=len(orig_bytes),
        file_size_after=len(mut_bytes),
        file_sha256_before=file_sha_before,
        file_sha256_after=file_sha_after,
        file_md5_before=file_md5_before,
        file_md5_after=file_md5_after,
        raw_audio_sha256_before=audio_sha_before,
        raw_audio_sha256_after=audio_sha_after,
        whole_file_hash_changed=whole_changed,
        raw_audio_stream_hash_changed=audio_changed,
        changed_audio_stream_bytes=changed_audio_bytes,
        total_frames_before=len(frames_before),
        total_frames_after=len(frames_after),
        prepended_silent_frames=prepended,
        structural_zero_distortion=structural_ok,
        pcm_sha256_before=pcm_before,
        pcm_sha256_after=pcm_after,
        pcm_identical=pcm_identical,
        passed=passed,
    )


def audit_file(
    target_path: Path,
    *,
    original_path: Path | None = None,
    patterns: list[str] | None = None,
) -> AuditReport:
    """Simulate a crawler bot scanning a file for hashes, ID3 leaks, and regex flags."""
    target_path = target_path.resolve()
    raw = target_path.read_bytes()
    layout = inspect_mp3_layout(raw)
    audio_stream = extract_audio_stream(raw)
    frames = walk_mpeg_frames(audio_stream)

    regex_list = patterns if patterns else DEFAULT_FLAG_PATTERNS
    plaintext_hits: list[str] = []
    for pat in regex_list:
        compiled = re.compile(pat.encode("utf-8"), flags=re.IGNORECASE)
        for match in compiled.findall(raw):
            decoded = match.decode("utf-8", errors="replace")
            if decoded not in plaintext_hits:
                plaintext_hits.append(decoded)

    exposed_frames: list[str] = []
    if layout.has_id3v2:
        for frame_id, _ in parse_id3v2_frames(raw):
            if frame_id != "PRIV" and frame_id not in exposed_frames:
                exposed_frames.append(frame_id)

    file_sha = sha256_hex(raw)
    file_md5 = md5_hex(raw)
    audio_sha = sha256_hex(audio_stream)

    whole_busted: bool | None = None
    audio_busted: bool | None = None
    zero_distortion: bool | None = None

    if original_path is not None:
        orig_raw = original_path.resolve().read_bytes()
        orig_audio = extract_audio_stream(orig_raw)
        whole_busted = (file_sha != sha256_hex(orig_raw)) and (file_md5 != md5_hex(orig_raw))
        audio_busted = audio_sha != sha256_hex(orig_audio)
        if frames:
            orig_frames = walk_mpeg_frames(orig_audio)
            prepended = max(0, len(frames) - len(orig_frames))
            try:
                assert_zero_acoustic_distortion(orig_raw, raw, prepended_silent_frames=prepended)
                zero_distortion = True
            except AudioIntegrityError:
                zero_distortion = False

    passed = (
        len(plaintext_hits) == 0
        and not layout.has_id3v1
        and not layout.has_apev2
        and len(exposed_frames) == 0
        and (whole_busted is not False)
        and (audio_busted is not False)
        and (zero_distortion is not False)
    )

    return AuditReport(
        path=str(target_path),
        file_size=len(raw),
        file_sha256=file_sha,
        file_md5=file_md5,
        raw_audio_sha256=audio_sha,
        mpeg_frame_count=len(frames),
        has_id3v2=layout.has_id3v2,
        has_id3v1=layout.has_id3v1,
        has_apev2=layout.has_apev2,
        exposed_id3_frames=exposed_frames,
        plaintext_flag_hits=plaintext_hits,
        whole_file_hash_busted=whole_busted,
        raw_audio_hash_busted=audio_busted,
        zero_acoustic_distortion=zero_distortion,
        passed=passed,
    )
