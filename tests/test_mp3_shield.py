"""Zero-dependency test suite (runs with stdlib `unittest` AND `pytest` on Linux)."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mp3_shield.cli import main as cli_main
from mp3_shield.config import generate_keys, load_keys, write_env_file
from mp3_shield.crypto import md5_hex, sha256_hex
from mp3_shield.mp3_frames import (
    AudioIntegrityError,
    assert_zero_acoustic_distortion,
    extract_audio_stream,
    inspect_mp3_layout,
    to_synchsafe,
    walk_mpeg_frames,
)
from mp3_shield.polymorph import extract_encrypted_flag, mutate_mp3
from mp3_shield.vault import ManifestStore
from mp3_shield.verify import audit_file, verify_mutation

HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


def build_mpeg1_frames(num_frames: int = 20, *, crc_every: int = 0) -> bytes:
    """Build spec-valid MPEG-1 Layer III frames (128 kbps, 44.1 kHz, 417B each)."""
    out = bytearray()
    for i in range(num_frames):
        is_crc = crc_every > 0 and (i % crc_every == 0)
        # 0xFF 0xFB = MPEG1 Layer III no_crc=1; 0xFF 0xFA = CRC protected (no_crc=0)
        b1 = 0xFA if is_crc else 0xFB
        header = bytes((0xFF, b1, 0x90, 0x00))
        payload = bytes(((i * 41 + j) % 251) for j in range(417 - 4))
        out.extend(header)
        out.extend(payload)
    return bytes(out)


def build_mpeg2_frames(num_frames: int = 10) -> bytes:
    """Build spec-valid MPEG-2 Layer III frames (64 kbps, 22050 Hz, coeff=72 -> 208B each)."""
    # version=2 (10), layer=1 (01), no_crc=1 -> 1111 0011 = 0xF3
    # bitrate_idx=8 (64 kbps in V2), sr_idx=0 (22050 Hz), pad=0, priv=0 -> 0x80
    header = bytes((0xFF, 0xF3, 0x80, 0xC0))  # Mono
    frame_len = (72 * 64000) // 22050  # 208 bytes
    out = bytearray()
    for i in range(num_frames):
        out.extend(header)
        out.extend(bytes(((i * 19 + j) % 241) for j in range(frame_len - 4)))
    return bytes(out)


def build_flagged_id3v2(title: str = "FLAG{id3v2_leaked_title}") -> bytes:
    """Build a raw ID3v2.3 header with a plaintext TIT2 frame."""
    body = b"\x03" + title.encode("utf-8")
    frame = b"TIT2" + struct.pack(">I", len(body)) + b"\x00\x00" + body
    return b"ID3\x03\x00\x00" + to_synchsafe(len(frame)) + frame


def build_flagged_id3v1(title: str = "FLAG{id3v1_tail_leak}") -> bytes:
    """Build a trailing 128-byte ID3v1 tag with a plaintext flag."""
    tag = bytearray(128)
    tag[0:3] = b"TAG"
    raw_t = title.encode("latin-1")[:30]
    tag[3 : 3 + len(raw_t)] = raw_t
    tag[127] = 12
    return bytes(tag)


class TestPolymorphicMp3Shield(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.raw_frames = build_mpeg1_frames(24)
        self.flagged_mp3 = self.tmp / "original.mp3"
        self.flagged_mp3.write_bytes(
            build_flagged_id3v2("FLAG{id3v2_secret}")
            + self.raw_frames
            + build_flagged_id3v1("CTF{id3v1_secret}")
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_polymorphic_mutates_file_and_raw_audio_stream_with_zero_distortion(self) -> None:
        out1 = self.tmp / "mut1.mp3"
        out2 = self.tmp / "mut2.mp3"
        keys = generate_keys()

        r1 = mutate_mp3(self.flagged_mp3, output_path=out1, keys=keys)
        r2 = mutate_mp3(self.flagged_mp3, output_path=out2, keys=keys)

        b1 = out1.read_bytes()
        b2 = out2.read_bytes()

        # 1. Whole-file hashes differ from original AND from each other
        self.assertNotEqual(r1.new_file_sha256, r1.original_file_sha256)
        self.assertNotEqual(r1.new_file_md5, r1.original_file_md5)
        self.assertNotEqual(sha256_hex(b1), sha256_hex(b2))
        self.assertNotEqual(md5_hex(b1), md5_hex(b2))

        # 2. Raw MPEG audio stream hashes ALSO changed (defeats ID3-stripping bots!)
        self.assertNotEqual(r1.new_audio_sha256, r1.original_audio_sha256)
        self.assertNotEqual(r1.new_audio_sha256, r2.new_audio_sha256)
        self.assertEqual(r1.total_frames, 24)
        self.assertEqual(r1.mutated_frames, 24)
        self.assertGreater(r1.changed_audio_bytes, 0)

        # 3. Zero plaintext flags or trailing ID3v1 remain anywhere
        for blob in (b1, b2):
            self.assertNotIn(b"FLAG{", blob)
            self.assertNotIn(b"CTF{", blob)
            layout = inspect_mp3_layout(blob)
            self.assertTrue(layout.has_id3v2)
            self.assertFalse(layout.has_id3v1)
            self.assertEqual(len(walk_mpeg_frames(extract_audio_stream(blob))), 24)

        # 4. Canonical acoustic HMAC matches identically across both mutations (for DB dedup)
        self.assertEqual(r1.canonical_acoustic_sha256, r2.canonical_acoustic_sha256)
        self.assertIsNotNone(r1.acoustic_hmac_sha256)
        self.assertEqual(r1.acoustic_hmac_sha256, r2.acoustic_hmac_sha256)

        # 5. Structural verifier & bot auditor pass
        vrep = verify_mutation(self.flagged_mp3, out1, check_pcm=False)
        self.assertTrue(vrep.passed)
        self.assertTrue(vrep.whole_file_hash_changed)
        self.assertTrue(vrep.raw_audio_stream_hash_changed)
        self.assertTrue(vrep.structural_zero_distortion)

        arep = audit_file(out1, original_path=self.flagged_mp3)
        self.assertTrue(arep.passed)
        self.assertEqual(arep.exposed_id3_frames, [])
        self.assertEqual(arep.plaintext_flag_hits, [])
        self.assertTrue(arep.whole_file_hash_busted)
        self.assertTrue(arep.raw_audio_hash_busted)
        self.assertTrue(arep.zero_acoustic_distortion)

    def test_crc_protected_frames_are_never_mutated(self) -> None:
        # 20 frames; indices 0, 4, 8, 12, 16 have CRC enabled (5 CRC frames, 15 unprotected)
        mixed_audio = build_mpeg1_frames(20, crc_every=4)
        src = self.tmp / "crc_mixed.mp3"
        out = self.tmp / "crc_mutated.mp3"
        src.write_bytes(mixed_audio)

        res = mutate_mp3(src, output_path=out)
        self.assertEqual(res.total_frames, 20)
        self.assertEqual(res.crc_skipped_frames, 5)
        self.assertEqual(res.mutated_frames, 15)
        self.assertNotEqual(res.new_audio_sha256, res.original_audio_sha256)

        # Confirm every CRC frame header is 100% untouched byte-for-byte
        orig_audio = extract_audio_stream(src.read_bytes())
        mut_audio = extract_audio_stream(out.read_bytes())
        for f in walk_mpeg_frames(orig_audio):
            if not f.no_crc:
                self.assertEqual(
                    orig_audio[f.offset : f.offset + f.length],
                    mut_audio[f.offset : f.offset + f.length],
                )

    def test_mpeg2_frames_and_silent_boundary_prepend(self) -> None:
        src = self.tmp / "mpeg2.mp3"
        out = self.tmp / "mpeg2_mut.mp3"
        src.write_bytes(build_mpeg2_frames(10))

        res = mutate_mp3(src, output_path=out, prepend_silence=2)
        self.assertEqual(res.total_frames, 10)
        self.assertEqual(res.prepended_silent_frames, 2)
        self.assertEqual(res.mutated_frames, 10)

        mut_frames = walk_mpeg_frames(extract_audio_stream(out.read_bytes()))
        self.assertEqual(len(mut_frames), 12)
        # Prepended silent frames match MPEG-2 22050Hz Mono stream parameters
        for sf in mut_frames[:2]:
            self.assertEqual(sf.version, 2)
            self.assertEqual(sf.sample_rate_hz, 22050)
            self.assertEqual(sf.channel_mode, 3)

        vrep = verify_mutation(src, out, check_pcm=False)
        self.assertTrue(vrep.passed)
        self.assertEqual(vrep.prepended_silent_frames, 2)
        self.assertTrue(vrep.structural_zero_distortion)

    def test_zero_distortion_guard_catches_payload_bit_flip(self) -> None:
        out = self.tmp / "tampered.mp3"
        mutate_mp3(self.flagged_mp3, output_path=out)
        data = bytearray(out.read_bytes())
        layout = inspect_mp3_layout(data)
        # Flip 1 bit inside compressed audio payload of frame 0 (past 4-byte header)
        data[layout.audio_start + 12] ^= 0x01
        with self.assertRaises(AudioIntegrityError):
            assert_zero_acoustic_distortion(self.flagged_mp3.read_bytes(), bytes(data))

    def test_cli_batch_mutate_verify_audit_and_manifest(self) -> None:
        raw_dir = self.tmp / "raw_db"
        mut_dir = self.tmp / "mut_db"
        raw_dir.mkdir()
        (raw_dir / "track1.mp3").write_bytes(self.flagged_mp3.read_bytes())
        (raw_dir / "track2.mp3").write_bytes(self.flagged_mp3.read_bytes())

        env_file = self.tmp / ".env"
        manifest_db = self.tmp / "manifest.db"

        # keygen (stdlib only!)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["keygen", "--output", str(env_file)])
        self.assertEqual(rc, 0)
        if os.name == "posix":
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

        # batch mutate
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                [
                    "mutate",
                    str(raw_dir),
                    "-o",
                    str(mut_dir),
                    "--env",
                    str(env_file),
                    "--manifest",
                    str(manifest_db),
                    "--json",
                ]
            )
        self.assertEqual(rc, 0)
        mut_json = json.loads(buf.getvalue())
        self.assertEqual(len(mut_json), 2)
        self.assertNotEqual(mut_json[0]["new_audio_sha256"], mut_json[1]["new_audio_sha256"])
        self.assertEqual(mut_json[0]["acoustic_hmac_sha256"], mut_json[1]["acoustic_hmac_sha256"])

        # CLI verify single pair
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                ["verify", str(raw_dir / "track1.mp3"), str(mut_dir / "track1.mp3"), "--json"]
            )
        self.assertEqual(rc, 0)
        vdata = json.loads(buf.getvalue())
        self.assertTrue(vdata["passed"])
        self.assertTrue(vdata["raw_audio_stream_hash_changed"])
        self.assertTrue(vdata["structural_zero_distortion"])

        # CLI audit directory
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["audit", str(mut_dir), "--json"])
        self.assertEqual(rc, 0)
        adata = json.loads(buf.getvalue())
        self.assertEqual(len(adata), 2)
        self.assertTrue(all(item["passed"] for item in adata))

        # Manifest dedup check
        store = ManifestStore(manifest_db)
        rows = store.list_all()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["audio_hmac"], rows[1]["audio_hmac"])

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package not installed")
    def test_optional_encrypted_flag_and_vault_roundtrip(self) -> None:
        env_file = self.tmp / "crypto.env"
        keys = generate_keys()
        write_env_file(env_file, keys)

        # Encrypted flag inside polymorphic MP3 PRIV frame
        mut_path = self.tmp / "with_flag.mp3"
        mutate_mp3(
            self.flagged_mp3,
            output_path=mut_path,
            flag_to_hide="FLAG{aes_gcm_in_polymorphic_mp3}",
            keys=keys,
        )
        self.assertNotIn(b"FLAG{", mut_path.read_bytes())
        self.assertEqual(
            extract_encrypted_flag(mut_path, load_keys(env_file)),
            "FLAG{aes_gcm_in_polymorphic_mp3}",
        )

        # Optional AES-256-GCM vault roundtrip
        vault_dir = self.tmp / "vault"
        dec_dir = self.tmp / "dec"
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(
                cli_main(["encrypt", str(self.flagged_mp3), "-o", str(vault_dir), "--env", str(env_file)]),
                0,
            )
            self.assertEqual(
                cli_main(["decrypt", str(vault_dir), "-o", str(dec_dir), "--env", str(env_file)]),
                0,
            )
        restored = next(dec_dir.glob("*.mp3"))
        self.assertEqual(restored.read_bytes(), self.flagged_mp3.read_bytes())


if __name__ == "__main__":
    unittest.main()
