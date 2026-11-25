"""Batch pipeline orchestration for polymorphic MP3 mutation and optional AES-GCM vault."""

from __future__ import annotations

import uuid
from pathlib import Path

from .config import KeyBundle
from .polymorph import (
    DEFAULT_FLAG_OWNER,
    DEFAULT_MAX_SALT,
    DEFAULT_MIN_SALT,
    MutationResult,
    mutate_mp3,
)
from .vault import (
    ManifestStore,
    VaultDecryptResult,
    VaultProtectResult,
    decrypt_mp3_file,
    protect_mp3,
)


def discover_files(source: Path, *, suffixes: tuple[str, ...], recursive: bool = True) -> list[Path]:
    """Return sorted matching files from either a single file path or a directory."""
    source = source.resolve()
    if not source.exists():
        raise FileNotFoundError(f"Source path does not exist: {source}")
    if source.is_file():
        return [source]

    lower_suffixes = tuple(s.lower() for s in suffixes)
    iterator = source.rglob("*") if recursive else source.glob("*")
    return sorted(p for p in iterator if p.is_file() and p.suffix.lower() in lower_suffixes)


def _compute_output_path(
    file_path: Path,
    source_root: Path,
    output_target: Path,
    *,
    new_suffix: str | None,
    anonymize_names: bool,
) -> Path:
    # Allow passing a direct file path (e.g., `-o mutated.mp3`) when input is a single file
    if source_root.is_file() and not anonymize_names and (
        output_target.suffix.lower() in (".mp3", ".enc") and not output_target.is_dir()
    ):
        return output_target

    if anonymize_names:
        suffix = new_suffix if new_suffix is not None else file_path.suffix
        return output_target / f"{uuid.uuid4().hex}{suffix}"

    rel = file_path.relative_to(source_root) if source_root.is_dir() else Path(file_path.name)
    if new_suffix is not None:
        if new_suffix == ".mp3" and rel.name.lower().endswith(".mp3.enc"):
            rel = rel.with_name(rel.name[:-4])
        elif new_suffix.startswith("."):
            rel = rel.with_name(f"{rel.name}{new_suffix}") if not rel.name.endswith(new_suffix) else rel
        else:
            rel = rel.with_suffix(f".{new_suffix}")
    return output_target / rel


def run_polymorph_pipeline(
    source: Path,
    *,
    output: Path | None = None,
    in_place: bool = False,
    prepend_silence: int = 0,
    min_salt: int = DEFAULT_MIN_SALT,
    max_salt: int = DEFAULT_MAX_SALT,
    salt_owner: str | None = None,
    flag_to_hide: str | None = None,
    flag_owner: str = DEFAULT_FLAG_OWNER,
    keys: KeyBundle | None = None,
    anonymize_names: bool = False,
    manifest_db: Path | None = None,
    recursive: bool = True,
) -> list[MutationResult]:
    """Batch polymorphic MP3 mutation pipeline (single file or recursive directory)."""
    if not in_place and output is None:
        raise ValueError("Specify --output or --in-place.")

    source = source.resolve()
    files = discover_files(source, suffixes=(".mp3",), recursive=recursive)
    if not files:
        raise FileNotFoundError(f"No .mp3 files found in {source}")

    store = ManifestStore(manifest_db) if manifest_db else None
    results: list[MutationResult] = []

    for mp3_file in files:
        out_path: Path | None = None
        if not in_place:
            assert output is not None
            out_path = _compute_output_path(
                mp3_file,
                source,
                output.resolve(),
                new_suffix=None,
                anonymize_names=anonymize_names,
            )

        res = mutate_mp3(
            mp3_file,
            output_path=out_path,
            in_place=in_place,
            prepend_silence=prepend_silence,
            min_salt=min_salt,
            max_salt=max_salt,
            salt_owner=salt_owner,
            flag_to_hide=flag_to_hide,
            flag_owner=flag_owner,
            keys=keys,
        )

        if store is not None:
            index_hash = res.acoustic_hmac_sha256 or res.canonical_acoustic_sha256
            store.upsert_record(
                mode="playable",
                db_hash=index_hash,
                audio_hmac=index_hash,
                stored_path=res.output_path,
                original_name=None if anonymize_names else mp3_file.name,
                original_size=res.file_size_before,
                protected_size=res.file_size_after,
            )
        results.append(res)
    return results


def run_vault_pipeline(
    source: Path,
    output_dir: Path,
    keys: KeyBundle,
    *,
    manifest_db: Path | None = None,
    anonymize_names: bool = False,
    ext: str = ".enc",
    recursive: bool = True,
) -> list[VaultProtectResult]:
    """Optional AES-256-GCM at-rest encryption pipeline (for STT/Whisper/Chromaprint threats)."""
    source = source.resolve()
    output_dir = output_dir.resolve()
    ext = ext if ext.startswith(".") else f".{ext}"
    files = discover_files(source, suffixes=(".mp3",), recursive=recursive)
    if not files:
        raise FileNotFoundError(f"No .mp3 files found in {source}")

    store = ManifestStore(manifest_db) if manifest_db else None
    results: list[VaultProtectResult] = []

    for mp3_file in files:
        out_path = _compute_output_path(
            mp3_file,
            source,
            output_dir,
            new_suffix=ext,
            anonymize_names=anonymize_names,
        )
        res = protect_mp3(mp3_file, out_path, keys)
        if store is not None:
            store.upsert_record(
                mode="vault",
                db_hash=res.db_hash,
                audio_hmac=res.audio_hmac_sha256,
                stored_path=res.output_path,
                original_name=None if anonymize_names else mp3_file.name,
                original_size=res.original_size,
                protected_size=res.encrypted_size,
            )
        results.append(res)
    return results


def run_decrypt_pipeline(
    source: Path,
    output_dir: Path,
    keys: KeyBundle,
    *,
    manifest_db: Path | None = None,
    ext: str = ".enc",
    recursive: bool = True,
) -> list[VaultDecryptResult]:
    """Decrypt AES-256-GCM vault files back to bit-for-bit original MP3s."""
    source = source.resolve()
    output_dir = output_dir.resolve()
    ext = ext if ext.startswith(".") else f".{ext}"
    files = discover_files(source, suffixes=(ext,), recursive=recursive)
    if not files:
        raise FileNotFoundError(f"No {ext} files found in {source}")

    store = ManifestStore(manifest_db) if manifest_db else None
    results: list[VaultDecryptResult] = []

    for enc_file in files:
        expected_hash: str | None = None
        restored_name: str | None = None

        if store is not None:
            record = store.find_by_stored_path(enc_file)
            if record is not None:
                expected_hash = str(record["db_hash"])
                if record["original_name"]:
                    restored_name = str(record["original_name"])

        if restored_name:
            out_path = output_dir / restored_name
        else:
            rel = enc_file.relative_to(source) if source.is_dir() else Path(enc_file.name)
            stem_name = rel.name[: -len(ext)] if rel.name.lower().endswith(ext.lower()) else rel.stem
            if not stem_name.lower().endswith(".mp3"):
                stem_name = f"{stem_name}.mp3"
            out_path = output_dir / rel.with_name(stem_name)

        res = decrypt_mp3_file(enc_file, out_path, keys, expected_db_hash=expected_hash)
        results.append(res)
    return results
