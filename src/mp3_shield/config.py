"""Key management and environment configuration (100% Python stdlib)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENC_KEY_ENV = "MP3_SHIELD_ENC_KEY"
HMAC_KEY_ENV = "MP3_SHIELD_HMAC_KEY"
KEY_BYTES = 32


class KeyConfigError(ValueError):
    """Raised when encryption or HMAC keys are missing or malformed."""


@dataclass(frozen=True, slots=True)
class KeyBundle:
    """Server-side secret keys (256-bit AES-GCM key + 256-bit HMAC-SHA256 key)."""

    enc_key: bytes
    hmac_key: bytes

    def __post_init__(self) -> None:
        if len(self.enc_key) != KEY_BYTES:
            raise KeyConfigError(
                f"Encryption key must be exactly {KEY_BYTES} bytes (256 bits), got {len(self.enc_key)}."
            )
        if len(self.hmac_key) != KEY_BYTES:
            raise KeyConfigError(
                f"HMAC key must be exactly {KEY_BYTES} bytes (256 bits), got {len(self.hmac_key)}."
            )

    @property
    def enc_key_hex(self) -> str:
        return self.enc_key.hex()

    @property
    def hmac_key_hex(self) -> str:
        return self.hmac_key.hex()


def generate_keys() -> KeyBundle:
    """Generate fresh cryptographically secure 256-bit keys using OS CSPRNG."""
    return KeyBundle(enc_key=os.urandom(KEY_BYTES), hmac_key=os.urandom(KEY_BYTES))


def _parse_hex_key(raw: str, label: str) -> bytes:
    cleaned = raw.strip().strip('"').strip("'")
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise KeyConfigError(f"{label} is not valid hexadecimal.") from exc
    if len(key_bytes) != KEY_BYTES:
        raise KeyConfigError(
            f"{label} must decode to {KEY_BYTES} bytes (64 hex chars), got {len(key_bytes)} bytes."
        )
    return key_bytes


def parse_env_file(env_path: Path) -> dict[str, str]:
    """Parse KEY=VALUE pairs from a .env file without external dependencies."""
    values: dict[str, str] = {}
    if not env_path.is_file():
        return values
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        values[key] = val.strip().strip('"').strip("'")
    return values


def write_env_file(env_path: Path, keys: KeyBundle, *, overwrite: bool = False) -> Path:
    """Write generated keys to an env file with strict 0600 permissions on POSIX."""
    env_path = env_path.resolve()
    if env_path.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite existing key file: {env_path}. Pass --force to overwrite."
        )
    env_path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "# mp3-shield secret keys (256-bit hex) - KEEP OUT OF THE DATABASE AND GIT\n"
        f"{ENC_KEY_ENV}={keys.enc_key_hex}\n"
        f"{HMAC_KEY_ENV}={keys.hmac_key_hex}\n"
    )
    env_path.write_text(content, encoding="utf-8", newline="\n")
    if os.name == "posix":
        os.chmod(env_path, 0o600)
    return env_path


def load_keys(env_file: Path | None = None, *, required: bool = True) -> KeyBundle | None:
    """Load keys from environment variables, falling back to an env file if provided/present."""
    file_vars: dict[str, str] = {}
    if env_file is not None:
        if not env_file.is_file():
            raise KeyConfigError(f"Specified env file does not exist: {env_file}")
        file_vars = parse_env_file(env_file)
    else:
        default_env = Path.cwd() / ".env"
        if default_env.is_file():
            file_vars = parse_env_file(default_env)

    enc_raw = os.environ.get(ENC_KEY_ENV) or file_vars.get(ENC_KEY_ENV)
    hmac_raw = os.environ.get(HMAC_KEY_ENV) or file_vars.get(HMAC_KEY_ENV)

    missing = []
    if not enc_raw:
        missing.append(ENC_KEY_ENV)
    if not hmac_raw:
        missing.append(HMAC_KEY_ENV)
    if missing:
        if not required:
            return None
        raise KeyConfigError(
            f"Missing required key environment variable(s): {', '.join(missing)}. "
            "Run `mp3-shield keygen --output .env` or export them in your shell."
        )

    assert enc_raw is not None and hmac_raw is not None
    return KeyBundle(
        enc_key=_parse_hex_key(enc_raw, ENC_KEY_ENV),
        hmac_key=_parse_hex_key(hmac_raw, HMAC_KEY_ENV),
    )
