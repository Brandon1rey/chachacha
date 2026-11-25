"""Pure-stdlib MP3 tag parser, MPEG-1/2/2.5 Layer III frame walker, and integrity verifier.

Handles:
  - Leading chained ID3v2 headers (synchsafe sizes, optional footer) & ID3v2 frame listing
  - Trailing ID3v1 (128B), Enhanced ID3v1 (227B TAG+), and APEv2 tags
  - Exact MPEG Layer III frame boundary walking with frame-sync lookahead validation
  - Silent MPEG Layer III boundary frame synthesis matched to stream parameters
  - Acoustic-only canonicalization (masks non-acoustic Private/Copyright/Original bits)
    for both zero-distortion verification and deduplication across polymorphic mutations
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from .crypto import sha256_hex

# Bitrate tables (kbps) for MPEG Layer III
BITRATES_V1 = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0)
BITRATES_V2 = (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0)

# Sample rate tables (Hz) keyed by MPEG version bits: 3=MPEG1, 2=MPEG2, 0=MPEG2.5
SAMPLE_RATES: dict[int, tuple[int, int, int]] = {
    3: (44100, 48000, 32000),
    2: (22050, 24000, 16000),
    0: (11025, 12000, 8000),
}

ID3V2_HEADER_SIZE = 10
ID3V2_FOOTER_SIZE = 10
ID3V2_FOOTER_FLAG = 0x10
ID3V1_SIZE = 128
ID3V1_ENHANCED_SIZE = 227
APEV2_PREAMBLE = b"APETAGEX"
APEV2_FOOTER_SIZE = 32
APEV2_HEADER_FLAG = 1 << 31

# Non-acoustic MPEG header bitmasks:
#   b2 bit 0 (0x01): Private bit
#   b3 bit 3 (0x08): Copyright bit
#   b3 bit 2 (0x04): Original/Copy bit
NON_ACOUSTIC_B2_MASK = 0x01
NON_ACOUSTIC_B3_MASK = 0x0C


class AudioIntegrityError(RuntimeError):
    """Raised if acoustic MPEG header fields or frame payload bytes were altered."""


@dataclass(frozen=True, slots=True)
class Mp3Layout:
    """Byte offsets of the MPEG audio stream within an MP3 file."""

    audio_start: int
    audio_end: int
    total_size: int
    has_id3v2: bool
    has_id3v1: bool
    has_id3v1_enhanced: bool
    has_apev2: bool

    @property
    def audio_size(self) -> int:
        return max(0, self.audio_end - self.audio_start)


@dataclass(frozen=True, slots=True)
class MpegFrameInfo:
    """Parsed header metadata for a single MPEG Layer III frame."""

    offset: int
    length: int
    version: int        # 3=MPEG1, 2=MPEG2, 0=MPEG2.5
    no_crc: bool        # True if unprotected (safe to mutate b2/b3 non-acoustic bits)
    bitrate_bps: int
    sample_rate_hz: int
    sr_idx: int
    padding: int
    channel_mode: int   # 0=Stereo, 1=Joint, 2=Dual, 3=Mono


def to_synchsafe(n: int) -> bytes:
    """Encode an integer as a 4-byte ID3v2 synchsafe integer."""
    if n < 0 or n >= (1 << 28):
        raise ValueError(f"Synchsafe integer out of range: {n}")
    return bytes(
        (
            (n >> 21) & 0x7F,
            (n >> 14) & 0x7F,
            (n >> 7) & 0x7F,
            n & 0x7F,
        )
    )


def decode_synchsafe(four_bytes: bytes | bytearray | memoryview) -> int:
    """Decode a 4-byte ID3v2 synchsafe integer."""
    return (
        ((four_bytes[0] & 0x7F) << 21)
        | ((four_bytes[1] & 0x7F) << 14)
        | ((four_bytes[2] & 0x7F) << 7)
        | (four_bytes[3] & 0x7F)
    )


def inspect_mp3_layout(data: bytes | bytearray) -> Mp3Layout:
    """Locate the exact byte slice [audio_start:audio_end] excluding all metadata tags."""
    total = len(data)
    start = 0
    end = total
    has_id3v2 = False
    has_id3v1 = False
    has_id3v1_enhanced = False
    has_apev2 = False

    # 1. Skip one or more leading ID3v2 headers
    while start + ID3V2_HEADER_SIZE <= end and data[start : start + 3] == b"ID3":
        flags = data[start + 5]
        tag_body_size = decode_synchsafe(data[start + 6 : start + 10])
        footer_size = ID3V2_FOOTER_SIZE if (flags & ID3V2_FOOTER_FLAG) else 0
        next_start = start + ID3V2_HEADER_SIZE + tag_body_size + footer_size
        if next_start > end:
            break
        has_id3v2 = True
        start = next_start

    # 2. Skip trailing ID3v1 (128 bytes starting with b"TAG")
    if end - start >= ID3V1_SIZE and data[end - ID3V1_SIZE : end - ID3V1_SIZE + 3] == b"TAG":
        has_id3v1 = True
        end -= ID3V1_SIZE

        # 2b. Optional Enhanced ID3v1 tag (227 bytes starting with b"TAG+")
        if (
            end - start >= ID3V1_ENHANCED_SIZE
            and data[end - ID3V1_ENHANCED_SIZE : end - ID3V1_ENHANCED_SIZE + 4] == b"TAG+"
        ):
            has_id3v1_enhanced = True
            end -= ID3V1_ENHANCED_SIZE

    # 3. Skip trailing APEv2 footer/tag
    if end - start >= APEV2_FOOTER_SIZE:
        footer = bytes(data[end - APEV2_FOOTER_SIZE : end])
        if footer[:8] == APEV2_PREAMBLE:
            tag_size, _item_count, flags = struct.unpack("<III", footer[12:24])
            header_size = APEV2_FOOTER_SIZE if (flags & APEV2_HEADER_FLAG) else 0
            total_ape_size = tag_size + header_size
            if total_ape_size <= end - start:
                has_apev2 = True
                end -= total_ape_size

    return Mp3Layout(
        audio_start=start,
        audio_end=end,
        total_size=total,
        has_id3v2=has_id3v2,
        has_id3v1=has_id3v1,
        has_id3v1_enhanced=has_id3v1_enhanced,
        has_apev2=has_apev2,
    )


def parse_id3v2_frames(data: bytes | bytearray) -> list[tuple[str, bytes]]:
    """Parse ID3v2.3/ID3v2.4 frames using pure stdlib (returns list of (frame_id, payload))."""
    frames: list[tuple[str, bytes]] = []
    if len(data) < ID3V2_HEADER_SIZE or data[:3] != b"ID3":
        return frames

    major = data[3]
    flags = data[5]
    tag_size = decode_synchsafe(data[6:10])
    pos = ID3V2_HEADER_SIZE
    tag_end = min(len(data), ID3V2_HEADER_SIZE + tag_size)

    # Skip optional ID3v2 extended header (bit 6 = 0x40)
    if flags & 0x40 and pos + 4 <= tag_end:
        ext_size = decode_synchsafe(data[pos : pos + 4]) if major == 4 else struct.unpack(">I", data[pos : pos + 4])[0]
        pos += ext_size if major == 4 else (ext_size + 4)

    if major == 2:
        # Legacy ID3v2.2: 3-byte ID + 3-byte size
        while pos + 6 <= tag_end:
            fid_bytes = bytes(data[pos : pos + 3])
            if fid_bytes == b"\x00\x00\x00":
                break
            fsize = (data[pos + 3] << 16) | (data[pos + 4] << 8) | data[pos + 5]
            pos += 6
            if fsize <= 0 or pos + fsize > tag_end:
                break
            frames.append((fid_bytes.decode("latin-1", errors="replace"), bytes(data[pos : pos + fsize])))
            pos += fsize
        return frames

    # ID3v2.3 / ID3v2.4: 4-byte ID + 4-byte size + 2-byte flags
    while pos + 10 <= tag_end:
        fid_bytes = bytes(data[pos : pos + 4])
        if fid_bytes == b"\x00\x00\x00\x00":
            break
        if not all(65 <= b <= 90 or 48 <= b <= 57 for b in fid_bytes):
            break
        fsize = decode_synchsafe(data[pos + 4 : pos + 8]) if major == 4 else struct.unpack(">I", data[pos + 4 : pos + 8])[0]
        pos += 10
        if fsize < 0 or pos + fsize > tag_end:
            break
        frames.append((fid_bytes.decode("ascii"), bytes(data[pos : pos + fsize])))
        pos += fsize

    return frames


def parse_mpeg_frame_header(buf: bytes | bytearray, pos: int) -> MpegFrameInfo | None:
    """Parse a 4-byte MPEG Layer III frame header at `pos`, or return None if invalid."""
    if pos + 4 > len(buf):
        return None
    b0, b1, b2, b3 = buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]

    # 11-bit frame sync word
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return None

    version = (b1 >> 3) & 0x03      # 3=MPEG1, 2=MPEG2, 0=MPEG2.5, 1=reserved
    layer = (b1 >> 1) & 0x03        # 1=Layer III (MP3)
    no_crc = bool(b1 & 0x01)        # 1=no CRC, 0=CRC protected
    bitrate_idx = (b2 >> 4) & 0x0F
    sr_idx = (b2 >> 2) & 0x03
    padding = (b2 >> 1) & 0x01
    channel_mode = (b3 >> 6) & 0x03

    if version == 1 or layer != 1 or bitrate_idx in (0, 15) or sr_idx == 3:
        return None

    bitrate_bps = (BITRATES_V1 if version == 3 else BITRATES_V2)[bitrate_idx] * 1000
    sample_rate_hz = SAMPLE_RATES[version][sr_idx]
    coeff = 144 if version == 3 else 72
    frame_len = (coeff * bitrate_bps) // sample_rate_hz + padding

    if frame_len < 4 or pos + frame_len > len(buf):
        return None

    return MpegFrameInfo(
        offset=pos,
        length=frame_len,
        version=version,
        no_crc=no_crc,
        bitrate_bps=bitrate_bps,
        sample_rate_hz=sample_rate_hz,
        sr_idx=sr_idx,
        padding=padding,
        channel_mode=channel_mode,
    )


def walk_mpeg_frames(audio: bytes | bytearray) -> list[MpegFrameInfo]:
    """Walk all valid MPEG Layer III frames in an audio buffer with lookahead sync validation."""
    frames: list[MpegFrameInfo] = []
    pos = 0
    total = len(audio)
    synced = False

    while pos + 4 <= total:
        info = parse_mpeg_frame_header(audio, pos)
        if info is None:
            pos += 1
            continue

        # On first frame sync, verify lookahead if more data follows (prevents false 0xFF syncs in junk)
        if not synced and pos + info.length + 4 <= total:
            next_info = parse_mpeg_frame_header(audio, pos + info.length)
            if next_info is None:
                pos += 1
                continue

        synced = True
        frames.append(info)
        pos += info.length

    return frames


def is_vbr_header_frame(audio: bytes | bytearray, frame: MpegFrameInfo) -> bool:
    """Detect Xing / Info / VBRI VBR metadata frames."""
    chunk = bytes(audio[frame.offset : frame.offset + min(frame.length, 64)])
    return b"Xing" in chunk or b"Info" in chunk or b"VBRI" in chunk


def build_silent_mpeg_frame(template: MpegFrameInfo) -> bytes:
    """Synthesize a valid silent MPEG Layer III frame matching `template`'s stream parameters.

    Uses lowest standard bitrate (32 kbps for MPEG-1, 8 kbps for MPEG-2/2.5), matching
    version, sample rate, and channel mode, with all-zero side info (digital silence = 0 PCM)
    and randomized non-acoustic header bits.
    """
    b0 = 0xFF
    # sync (111) | version (2) | layer=01 (Layer III) | no_crc=1
    b1 = 0xE0 | (template.version << 3) | (0x01 << 1) | 0x01
    bitrate_idx = 1  # 32 kbps (MPEG-1) or 8 kbps (MPEG-2/2.5)
    private_bit = secrets.randbits(1)
    b2 = (bitrate_idx << 4) | (template.sr_idx << 2) | (0 << 1) | private_bit
    co_bits = secrets.randbits(2) << 2
    b3 = (template.channel_mode << 6) | co_bits  # mode_ext=0, emphasis=0

    bitrate_bps = (BITRATES_V1 if template.version == 3 else BITRATES_V2)[bitrate_idx] * 1000
    coeff = 144 if template.version == 3 else 72
    frame_len = (coeff * bitrate_bps) // template.sample_rate_hz

    return bytes((b0, b1, b2, b3)) + (b"\x00" * (frame_len - 4))


def extract_audio_stream(data: bytes | bytearray) -> bytes:
    """Return raw MPEG stream bytes (excluding leading ID3v2 and trailing ID3v1/TAG+/APEv2)."""
    layout = inspect_mp3_layout(data)
    return bytes(data[layout.audio_start : layout.audio_end])


def canonicalize_acoustic_stream(data: bytes | bytearray) -> bytes:
    """Return the MPEG stream with non-acoustic header bits zeroed out.

    Two polymorphic mutations of the same MP3 produce 100% identical canonical bytes
    (assuming no silent boundary frames were added), enabling:
      1. Mathematical proof that ZERO acoustic bits changed.
      2. Consistent keyed HMAC-SHA256 deduplication across polymorphic mutations.
    """
    raw = bytearray(extract_audio_stream(data))
    for frame in walk_mpeg_frames(raw):
        if frame.no_crc:
            raw[frame.offset + 2] &= ~NON_ACOUSTIC_B2_MASK
            raw[frame.offset + 3] &= ~NON_ACOUSTIC_B3_MASK
    return bytes(raw)


def assert_zero_acoustic_distortion(
    before: bytes | bytearray,
    after: bytes | bytearray,
    *,
    prepended_silent_frames: int = 0,
) -> str:
    """Mathematically prove zero acoustic distortion between `before` and `after`.

    Checks that:
      - Every original MPEG frame has 100% identical acoustic header fields.
      - Every original MPEG frame has 100% bit-for-bit identical compressed audio payload.
      - Only non-acoustic header bits (Private/Copyright/Original) on non-CRC frames differ.
    Returns SHA-256 of the canonical acoustic stream.
    """
    audio_before = extract_audio_stream(before)
    audio_after = extract_audio_stream(after)

    frames_before = walk_mpeg_frames(audio_before)
    frames_after = walk_mpeg_frames(audio_after)

    if len(frames_after) != len(frames_before) + prepended_silent_frames:
        raise AudioIntegrityError(
            f"Frame count mismatch: before={len(frames_before)}, "
            f"after={len(frames_after)} (expected +{prepended_silent_frames})."
        )

    aligned_after = frames_after[prepended_silent_frames:]
    for idx, (fb, fa) in enumerate(zip(frames_before, aligned_after)):
        if fb.length != fa.length:
            raise AudioIntegrityError(
                f"Frame #{idx} length changed: before={fb.length}, after={fa.length}."
            )
        hb = audio_before[fb.offset : fb.offset + 4]
        ha = audio_after[fa.offset : fa.offset + 4]

        if not fb.no_crc:
            # CRC-protected frame must be 100% untouched including header
            if hb != ha:
                raise AudioIntegrityError(f"CRC-protected frame #{idx} header was modified!")
        else:
            # Acoustic bits of header must be 100% identical
            if (
                hb[0] != ha[0]
                or hb[1] != ha[1]
                or (hb[2] & ~NON_ACOUSTIC_B2_MASK) != (ha[2] & ~NON_ACOUSTIC_B2_MASK)
                or (hb[3] & ~NON_ACOUSTIC_B3_MASK) != (ha[3] & ~NON_ACOUSTIC_B3_MASK)
            ):
                raise AudioIntegrityError(f"Acoustic header bits altered in frame #{idx}!")

        # Compressed MPEG audio payload (side info + spectral Huffman data) must be bit-for-bit identical
        if audio_before[fb.offset + 4 : fb.offset + fb.length] != audio_after[fa.offset + 4 : fa.offset + fa.length]:
            raise AudioIntegrityError(f"Compressed audio payload altered in frame #{idx}!")

    return sha256_hex(canonicalize_acoustic_stream(before))


# Backwards-compatible aliases
extract_audio_frames = extract_audio_stream
audio_frames_sha256 = lambda data: sha256_hex(extract_audio_stream(data))  # noqa: E731
