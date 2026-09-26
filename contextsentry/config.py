from __future__ import annotations

import os
import secrets
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.environ.get("CONTEXTSENTRY_ROOT", PACKAGE_ROOT.parent)).expanduser().resolve()
STATE_DIR = Path(os.environ.get("CONTEXTSENTRY_STATE_DIR", PROJECT_ROOT / ".contextsentry" / "state")).expanduser().resolve()
POLICY_PATH = Path(os.environ.get("CONTEXTSENTRY_POLICY_PATH", PROJECT_ROOT / ".contextsentry" / "policy.json")).expanduser().resolve()


def ensure_state_dir(state_dir: Path | None = None) -> Path:
    selected = (state_dir or STATE_DIR).expanduser().resolve()
    selected.mkdir(parents=True, exist_ok=True)
    try:
        selected.chmod(0o700)
    except OSError:
        pass
    return selected


def get_audit_key(state_dir: Path | None = None) -> bytes:
    configured = os.environ.get("CONTEXTSENTRY_AUDIT_KEY")
    if configured:
        return configured.encode("utf-8")
    state_dir = ensure_state_dir(state_dir)
    key_path = state_dir / "audit.key"
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return key_path.read_bytes()
    try:
        value = secrets.token_hex(32).encode("ascii")
        os.write(descriptor, value)
    finally:
        os.close(descriptor)
    return value
