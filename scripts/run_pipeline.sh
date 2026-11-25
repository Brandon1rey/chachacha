#!/usr/bin/env bash
set -euo pipefail

# Linux polymorphic MP3 pipeline runner (zero external dependencies required!)
# Usage:
#   ./scripts/run_pipeline.sh <input_mp3_or_dir> <output_mp3_or_dir> [prepend_silence_frames]

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$PROJECT_ROOT/scripts/mp3-shield"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <input_mp3_or_dir> <output_mp3_or_dir> [prepend_silence_frames]"
  echo "Example:"
  echo "  $0 ./raw_mp3s ./mutated_mp3s"
  echo "  $0 ./raw_mp3s ./mutated_mp3s 2"
  exit 1
fi

INPUT_PATH="$1"
OUTPUT_PATH="$2"
SILENCE_FRAMES="${3:-0}"

"$CLI" mutate "$INPUT_PATH" -o "$OUTPUT_PATH" --prepend-silence "$SILENCE_FRAMES"

echo ""
echo "[AUDIT] Running crawler-bot simulation audit..."
if [[ -f "$INPUT_PATH" && -f "$OUTPUT_PATH" ]]; then
  "$CLI" audit "$OUTPUT_PATH" --original "$INPUT_PATH"
  if command -v ffmpeg >/dev/null 2>&1 && [[ "$SILENCE_FRAMES" -eq 0 ]]; then
    echo "[PCM] Running ffmpeg decoded waveform SHA-256 verification..."
    "$CLI" verify "$INPUT_PATH" "$OUTPUT_PATH" --pcm
  else
    "$CLI" verify "$INPUT_PATH" "$OUTPUT_PATH"
  fi
else
  "$CLI" audit "$OUTPUT_PATH"
fi
