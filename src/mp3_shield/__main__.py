"""Allow direct execution on Linux with zero installation: python3 -m mp3_shield."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
