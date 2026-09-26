from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|authorization)\b(\s*[:=]\s*)([^\s,;]+)"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(character for character in normalized if unicodedata.category(character) != "Cf")


def redact(value: str) -> str:
    redacted = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
    redacted = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", redacted)
    return _CONTROL.sub("", redacted)


def safe_label(value: object, limit: int = 240) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    text = redact(normalize_text(text))
    text = " ".join(text.split())
    if len(text) > limit:
        return f"{text[: limit - 1]}…"
    return text


def read_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value
