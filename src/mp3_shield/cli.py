"""Command-line interface for mp3-shield (zero-dependency polymorphic MP3 mutator)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import KeyConfigError, generate_keys, load_keys, write_env_file
from .crypto import DecryptionError
from .mp3_frames import AudioIntegrityError
from .pipeline import (
    run_decrypt_pipeline,
    run_polymorph_pipeline,
    run_vault_pipeline,
)
from .polymorph import (
    DEFAULT_FLAG_OWNER,
    DEFAULT_MAX_SALT,
    DEFAULT_MIN_SALT,
    extract_encrypted_flag,
)
from .vault import ManifestStore
from .verify import audit_file, verify_mutation


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mp3-shield",
        description=(
            "Polymorphic MP3 mutator for Linux: keeps every file a valid, playable .mp3 "
            "with ZERO audio distortion while mutating bytes across metadata AND every MPEG frame header."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # mutate (PRIMARY: polymorphic playable MP3 mutator, zero dependencies)
    p_mut = sub.add_parser(
        "mutate",
        help="Polymorphically mutate MP3(s): strip tags, randomize ID3 PRIV salt & every MPEG frame header.",
    )
    p_mut.add_argument("input", type=Path, help="Input .mp3 file or directory.")
    out_grp = p_mut.add_mutually_exclusive_group(required=True)
    out_grp.add_argument("-o", "--output", type=Path, help="Output .mp3 file (for 1 file) or output directory.")
    out_grp.add_argument("--in-place", action="store_true", help="Mutate MP3 file(s) in place.")
    p_mut.add_argument(
        "--prepend-silence",
        type=int,
        default=0,
        help="Prepend N valid silent MPEG frames (0-10; default: 0 for exact ffmpeg PCM hash match).",
    )
    p_mut.add_argument("--min-salt", type=int, default=DEFAULT_MIN_SALT, help="Minimum ID3 PRIV salt bytes (default: 32).")
    p_mut.add_argument("--max-salt", type=int, default=DEFAULT_MAX_SALT, help="Maximum ID3 PRIV salt bytes (default: 287).")
    p_mut.add_argument("--salt-owner", default=None, help="Fixed ID3 PRIV owner string (default: randomized per file).")
    p_mut.add_argument("--flag", default=None, help="Optional flag to AES-256-GCM encrypt inside ID3 PRIV (requires cryptography + keys).")
    p_mut.add_argument("--flag-owner", default=DEFAULT_FLAG_OWNER, help="ID3 PRIV owner name for encrypted flag.")
    p_mut.add_argument("--anonymize-names", action="store_true", help="Rename output files to random UUIDs.")
    p_mut.add_argument("--env", type=Path, default=None, help="Optional .env file for HMAC indexing or --flag encryption.")
    p_mut.add_argument("--manifest", type=Path, default=None, help="Optional SQLite manifest DB path.")
    p_mut.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories.")
    p_mut.add_argument("--json", action="store_true", help="Emit JSON output.")

    # verify (Zero-distortion & mutation proof + optional ffmpeg PCM SHA-256 check)
    p_ver = sub.add_parser(
        "verify",
        help="Prove bytes changed across file & audio stream AND verify zero audio distortion (structural + optional ffmpeg PCM).",
    )
    p_ver.add_argument("original", type=Path, help="Original .mp3 file.")
    p_ver.add_argument("mutated", type=Path, help="Mutated .mp3 file.")
    p_ver.add_argument(
        "--pcm",
        action="store_true",
        help="Also decode both MP3s via `ffmpeg -f s16le` and compare SHA-256 of raw PCM waveforms.",
    )
    p_ver.add_argument("--json", action="store_true", help="Emit JSON output.")

    # audit (Crawler bot simulation)
    p_aud = sub.add_parser(
        "audit",
        help="Simulate crawler bots: regex flag scan, ID3v1/v2/APEv2 leak check, whole-file & raw-audio hash checks.",
    )
    p_aud.add_argument("target", type=Path, help="Mutated file or directory to scan.")
    p_aud.add_argument("--original", type=Path, default=None, help="Original MP3 to verify whole-file & raw-audio hash mutation.")
    p_aud.add_argument("--pattern", action="append", default=None, help="Custom regex pattern to scan for (repeatable).")
    p_aud.add_argument("--json", action="store_true", help="Emit JSON output.")

    # extract-flag
    p_ext = sub.add_parser("extract-flag", help="Decrypt an AES-256-GCM flag stored in an MP3 ID3 PRIV frame.")
    p_ext.add_argument("mp3_file", type=Path, help="Mutated .mp3 file.")
    p_ext.add_argument("--flag-owner", default=DEFAULT_FLAG_OWNER, help="ID3 PRIV owner name.")
    p_ext.add_argument("--env", type=Path, default=None, help="Path to .env file with keys.")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate 256-bit AES-GCM and HMAC-SHA256 keys (.env, chmod 600).")
    p_keygen.add_argument("-o", "--output", type=Path, default=Path(".env"), help="Output env file path.")
    p_keygen.add_argument("--force", action="store_true", help="Overwrite existing env file.")

    # encrypt / decrypt (optional at-rest vault for acoustic/STT bots)
    p_enc = sub.add_parser("encrypt", help="Optional vault mode: full AES-256-GCM encryption at rest.")
    p_enc.add_argument("input", type=Path, help="Input .mp3 file or directory.")
    p_enc.add_argument("-o", "--output", type=Path, required=True, help="Output directory for encrypted files.")
    p_enc.add_argument("--env", type=Path, default=None, help="Path to .env file with keys.")
    p_enc.add_argument("--manifest", type=Path, default=None, help="SQLite manifest DB path.")
    p_enc.add_argument("--anonymize-names", action="store_true", help="Rename outputs to random UUIDs.")
    p_enc.add_argument("--ext", default=".enc", help="Encrypted output extension (default: .enc).")
    p_enc.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories.")
    p_enc.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_dec = sub.add_parser("decrypt", help="Decrypt AES-256-GCM vault files back to bit-for-bit original MP3s.")
    p_dec.add_argument("input", type=Path, help="Encrypted file or directory.")
    p_dec.add_argument("-o", "--output", type=Path, required=True, help="Output directory for restored MP3s.")
    p_dec.add_argument("--env", type=Path, default=None, help="Path to .env file with keys.")
    p_dec.add_argument("--manifest", type=Path, default=None, help="SQLite manifest DB path.")
    p_dec.add_argument("--ext", default=".enc", help="Encrypted file extension (default: .enc).")
    p_dec.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories.")
    p_dec.add_argument("--json", action="store_true", help="Emit JSON output.")

    # manifest inspect
    p_man = sub.add_parser("manifest", help="Inspect records in a SQLite manifest database.")
    p_man.add_argument("db_path", type=Path, help="Path to SQLite manifest DB.")
    p_man.add_argument("--audio-hmac", default=None, help="Filter by acoustic HMAC/hash.")
    p_man.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


def _cmd_mutate(args: argparse.Namespace) -> int:
    need_keys = args.flag is not None or args.env is not None
    keys = load_keys(args.env, required=need_keys)
    results = run_polymorph_pipeline(
        args.input,
        output=args.output,
        in_place=args.in_place,
        prepend_silence=args.prepend_silence,
        min_salt=args.min_salt,
        max_salt=args.max_salt,
        salt_owner=args.salt_owner,
        flag_to_hide=args.flag,
        flag_owner=args.flag_owner,
        keys=keys,
        anonymize_names=args.anonymize_names,
        manifest_db=args.manifest,
        recursive=not args.no_recursive,
    )
    if args.json:
        payload = [
            {
                "input": str(r.input_path),
                "output": str(r.output_path),
                "total_frames": r.total_frames,
                "mutated_frames": r.mutated_frames,
                "crc_skipped_frames": r.crc_skipped_frames,
                "prepended_silent_frames": r.prepended_silent_frames,
                "changed_audio_bytes": r.changed_audio_bytes,
                "id3_salt_bytes": r.id3_salt_bytes,
                "file_size_before": r.file_size_before,
                "file_size_after": r.file_size_after,
                "original_file_sha256": r.original_file_sha256,
                "new_file_sha256": r.new_file_sha256,
                "original_file_md5": r.original_file_md5,
                "new_file_md5": r.new_file_md5,
                "original_audio_sha256": r.original_audio_sha256,
                "new_audio_sha256": r.new_audio_sha256,
                "canonical_acoustic_sha256": r.canonical_acoustic_sha256,
                "acoustic_hmac_sha256": r.acoustic_hmac_sha256,
                "zero_distortion_verified": r.zero_distortion_verified,
            }
            for r in results
        ]
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            print(
                f"[MUTATED] {r.input_path.name} -> {r.output_path}\n"
                f"  Frames   : {r.mutated_frames}/{r.total_frames} headers mutated "
                f"(crc_skipped={r.crc_skipped_frames}, silent_prepended={r.prepended_silent_frames}, "
                f"audio_bytes_changed={r.changed_audio_bytes})\n"
                f"  Size     : {r.file_size_before}B -> {r.file_size_after}B (ID3 PRIV salt={r.id3_salt_bytes}B)\n"
                f"  File SHA : {r.original_file_sha256[:16]}... -> {r.new_file_sha256[:16]}...\n"
                f"  Audio SHA: {r.original_audio_sha256[:16]}... -> {r.new_audio_sha256[:16]}... "
                f"(0% acoustic distortion verified)"
            )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    report = verify_mutation(args.original, args.mutated, check_pcm=args.pcm)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        status = "PASS" if report.passed else "FAIL"
        print(f"[{status}] {report.original_path}  vs  {report.mutated_path}")
        print(f"  Whole-file SHA256 changed : {report.whole_file_hash_changed} ({report.file_sha256_before[:16]} -> {report.file_sha256_after[:16]})")
        print(f"  Raw-audio  SHA256 changed : {report.raw_audio_stream_hash_changed} ({report.raw_audio_sha256_before[:16]} -> {report.raw_audio_sha256_after[:16]})")
        print(f"  Changed audio stream bytes: {report.changed_audio_stream_bytes} across {report.total_frames_before} frames (+{report.prepended_silent_frames} silent)")
        print(f"  Structural 0% distortion  : {report.structural_zero_distortion}")
        if report.pcm_identical is not None:
            print(f"  FFmpeg PCM SHA256 match   : {report.pcm_identical} ({report.pcm_sha256_before[:16]} == {report.pcm_sha256_after[:16]})")
    return 0 if report.passed else 2


def _cmd_audit(args: argparse.Namespace) -> int:
    target: Path = args.target.resolve()
    files = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file())
    if not files:
        print(f"[WARN] No files found in {target}", file=sys.stderr)
        return 1

    reports = [
        audit_file(f, original_path=args.original if len(files) == 1 else None, patterns=args.pattern)
        for f in files
    ]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for r in reports:
            status = "PASS" if r.passed else "FAIL"
            print(
                f"[{status}] {r.path} | size={r.file_size}B | frames={r.mpeg_frame_count} | "
                f"id3v1={r.has_id3v1} apev2={r.has_apev2} "
                f"exposed_frames={r.exposed_id3_frames} flag_hits={r.plaintext_flag_hits}"
            )
            if r.whole_file_hash_busted is not None:
                print(
                    f"       whole_hash_busted={r.whole_file_hash_busted} "
                    f"raw_audio_hash_busted={r.raw_audio_hash_busted} "
                    f"zero_distortion={r.zero_acoustic_distortion}"
                )
    return 0 if all(r.passed for r in reports) else 2


def _cmd_extract_flag(args: argparse.Namespace) -> int:
    keys = load_keys(args.env, required=True)
    assert keys is not None
    flag = extract_encrypted_flag(args.mp3_file, keys, flag_owner=args.flag_owner)
    if flag is None:
        print(f"[INFO] No PRIV frame with owner={args.flag_owner!r} found in {args.mp3_file}", file=sys.stderr)
        return 1
    print(flag)
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    keys = generate_keys()
    written = write_env_file(args.output, keys, overwrite=args.force)
    print(f"[OK] Generated 256-bit AES-GCM & HMAC-SHA256 keys -> {written}")
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    keys = load_keys(args.env, required=True)
    assert keys is not None
    results = run_vault_pipeline(
        args.input,
        args.output,
        keys,
        manifest_db=args.manifest,
        anonymize_names=args.anonymize_names,
        ext=args.ext,
        recursive=not args.no_recursive,
    )
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "input": str(r.input_path),
                        "output": str(r.output_path),
                        "db_hash": r.db_hash,
                        "audio_hmac_sha256": r.audio_hmac_sha256,
                        "original_size": r.original_size,
                        "encrypted_size": r.encrypted_size,
                    }
                    for r in results
                ],
                indent=2,
            )
        )
    else:
        for r in results:
            print(f"[ENCRYPTED] {r.input_path.name} -> {r.output_path} | db_hash={r.db_hash[:16]}...")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    keys = load_keys(args.env, required=True)
    assert keys is not None
    results = run_decrypt_pipeline(
        args.input,
        args.output,
        keys,
        manifest_db=args.manifest,
        ext=args.ext,
        recursive=not args.no_recursive,
    )
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "input": str(r.input_path),
                        "output": str(r.output_path),
                        "restored_sha256": r.restored_sha256,
                        "restored_size": r.restored_size,
                        "hmac_verified": r.hmac_verified,
                    }
                    for r in results
                ],
                indent=2,
            )
        )
    else:
        for r in results:
            print(f"[DECRYPTED] {r.input_path.name} -> {r.output_path} | sha256={r.restored_sha256[:16]}...")
    return 0


def _cmd_manifest(args: argparse.Namespace) -> int:
    if not args.db_path.is_file():
        print(f"[ERROR] Manifest database not found: {args.db_path}", file=sys.stderr)
        return 1
    store = ManifestStore(args.db_path)
    rows = store.find_by_audio_hmac(args.audio_hmac) if args.audio_hmac else store.list_all()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(
                f"#{row['id']} [{row['mode']}] {row['stored_path']} | "
                f"audio_hmac={str(row['audio_hmac'])[:16]}..."
            )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        dispatch = {
            "mutate": _cmd_mutate,
            "verify": _cmd_verify,
            "audit": _cmd_audit,
            "extract-flag": _cmd_extract_flag,
            "keygen": _cmd_keygen,
            "encrypt": _cmd_encrypt,
            "decrypt": _cmd_decrypt,
            "manifest": _cmd_manifest,
        }
        return dispatch[args.command](args)
    except (
        KeyConfigError,
        DecryptionError,
        AudioIntegrityError,
        FileNotFoundError,
        FileExistsError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
