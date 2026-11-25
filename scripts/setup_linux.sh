#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[INFO] Core polymorphic mutation needs ZERO pip packages — works immediately via:"
echo "       ./scripts/mp3-shield mutate input.mp3 -o mutated.mp3"
echo ""

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

if command -v uv >/dev/null 2>&1; then
  echo "[1/2] Creating optional venv with uv (.venv)..."
  uv venv .venv
  source .venv/bin/activate
  uv pip install -e ".[dev]"
  echo "[2/2] Running pytest..."
  pytest
elif python3 -m venv .venv 2>/dev/null; then
  echo "[1/2] Installing editable package into .venv..."
  source .venv/bin/activate
  python -m pip install --upgrade pip >/dev/null
  pip install -e ".[dev]"
  echo "[2/2] Running pytest..."
  pytest
else
  rm -rf .venv
  echo "[INFO] python3-venv not installed; running built-in stdlib unittest suite directly with python3..."
  PYTHONPATH="$PROJECT_ROOT/src" python3 -m unittest discover -s tests -p "test_*.py" -v
fi
