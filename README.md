# mp3-shield — Polymorphic MP3 Mutator (Linux, Zero Dependencies)

Mutates `.mp3` files into **valid, directly playable `.mp3` files with zero audio distortion** while changing bytes across **both metadata AND every individual MPEG audio frame header**.

Breaks:
- Whole-file MD5 / SHA-256 hashes & file-size checks
- Raw-audio-stream hashes (even when a bot strips ID3 tags first)
- Byte-offset signatures & YARA rules spanning MPEG frames
- Metadata / plaintext flag regex scanners (`ID3v2`, trailing 128B `ID3v1`, `TAG+`, `APEv2`)
- Optional frame-count & fixed-offset checks (`--prepend-silence 1..2`)

---

## Architecture (Zero External Dependencies)

| MP3 Layer | Mutation Applied | Bot Signature Broken | Audio Impact |
| --- | --- | --- | --- |
| `ID3v2` / `ID3v1` / `TAG+` / `APEv2` | Strips all existing tags; prepends random-length `ID3v2.3` `PRIV` frame with randomized owner + CSPRNG salt (`32–287B`) | MD5/SHA-256, size checks, metadata regex, fixed-owner YARA | None (skipped by decoder) |
| Every MPEG Layer III Frame Header (~26 ms) | Walks frames by exact calculated length; skips CRC-protected frames (`no_crc == 0`); randomizes **Private** (`b2 bit 0`), **Copyright** (`b3 bit 3`), and **Original** (`b3 bit 2`) bits | Raw-audio-stream hashes, byte-offset signatures, YARA rules across frames | None (ignored by MPEG decoders; compressed audio payload untouched) |
| Silent Boundary Frames (optional) | `--prepend-silence N` prepends 1–2 valid digital-zero MPEG frames matched to stream version/sample rate/channels | Frame-count checks, fixed-offset slicing | ~26–52 ms leading silence; zero distortion |

---

## Linux Usage (No `pip` / No `venv` Required)

Works directly with system `python3` (3.10+):

```bash
cd /mnt/c/Users/BranB/Desktop/proyectos/mp3-shield
chmod +x scripts/mp3-shield scripts/run_pipeline.sh scripts/setup_linux.sh
```

### Mutate a Single File or Entire Directory

```bash
# Single MP3
./scripts/mp3-shield mutate original.mp3 -o mutated.mp3

# Batch directory (recursively mutates all .mp3 files)
./scripts/mp3-shield mutate ./raw_mp3s -o ./mutated_mp3s

# Batch + randomize filenames to UUIDs + prepend 2 silent MPEG frames
./scripts/mp3-shield mutate ./raw_mp3s -o ./mutated_mp3s --anonymize-names --prepend-silence 2

# Mutate in place
./scripts/mp3-shield mutate ./raw_mp3s --in-place
```

### One-Line Pipeline + Automatic Bot Audit & Verification

```bash
./scripts/run_pipeline.sh ./raw_mp3s ./mutated_mp3s
```

### Verify Zero Audio Distortion

1. **Built-in structural proof (no `ffmpeg` required)** — proves every MPEG frame's acoustic header fields and compressed audio payload bytes are bit-for-bit identical while both whole-file and raw-audio-stream SHA-256 changed:

```bash
./scripts/mp3-shield verify original.mp3 mutated.mp3
```

2. **Decoded PCM waveform hash proof (`ffmpeg`)** — proves 100% identical decoded sound wave:

```bash
./scripts/mp3-shield verify original.mp3 mutated.mp3 --pcm
```

Or manually via bash:

```bash
ffmpeg -v error -i original.mp3 -f s16le - | sha256sum
ffmpeg -v error -i mutated.mp3  -f s16le - | sha256sum
```

3. **Crawler-bot simulation audit** (checks regex flag hits, `ID3v1`/`APEv2`/exposed `ID3v2` frames, whole-file & raw-audio hash mutation):

```bash
./scripts/mp3-shield audit mutated.mp3 --original original.mp3
```

### Optional: Backend Deduplication (Canonical Acoustic HMAC) & Encrypted `PRIV` Flags

Even after polymorphic mutation changes both ID3 and MPEG header bytes, your backend can track duplicates via `canonical_acoustic_sha256` / keyed `HMAC-SHA256` (masks the 3 mutated non-acoustic bits before hashing):

```bash
./scripts/mp3-shield keygen --output .env
./scripts/mp3-shield mutate ./raw_mp3s -o ./mutated_mp3s --env .env --manifest ./manifest.db
./scripts/mp3-shield manifest ./manifest.db
```

---

## Hard Limit to Keep in Mind

Polymorphic MP3 mutation defeats every byte-level, whole-file hash, raw-stream hash, YARA, and metadata crawler bot while remaining directly playable with zero distortion. If an opposing bot decodes the MP3 to raw PCM and hashes the waveform or runs acoustic fingerprinting (`Chromaprint`) / speech-to-text (`Whisper`), use the included optional `encrypt` / `decrypt` AES-256-GCM vault mode and decrypt on authenticated playback.
