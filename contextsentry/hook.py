from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .policy import PolicyEngine
from .util import safe_label

_MAX_INPUT = 1048576
_EVENT_KEYS = ("event", "hook_event_name", "hookEventName", "event_name", "eventName")
_TOOL_NAME_KEYS = ("tool_name", "toolName")
_TOOL_INPUT_KEYS = ("tool_input", "toolInput", "arguments", "args")
_TOOL_OUTPUT_KEYS = ("tool_response", "toolResponse", "result")
_EVENT_NAMES = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")


def _event_name(payload: dict[str, Any]) -> str:
    for key in _EVENT_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            canonical = value.strip()
            for known in _EVENT_NAMES:
                if known.lower() == canonical.lower():
                    return known
            return canonical
    return "Unknown"


def _normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized["event"] = _event_name(normalized)
    if not isinstance(normalized.get("tool"), str) or not normalized.get("tool"):
        for key in _TOOL_NAME_KEYS:
            if isinstance(normalized.get(key), str) and normalized[key]:
                normalized["tool"] = normalized[key]
                break
    if not isinstance(normalized.get("input"), dict):
        for key in _TOOL_INPUT_KEYS:
            if isinstance(normalized.get(key), dict):
                normalized["input"] = normalized[key]
                break
    if "output" not in normalized:
        for key in _TOOL_OUTPUT_KEYS:
            if key in normalized:
                normalized["output"] = normalized[key]
                break
    return normalized


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate key: {key}")
        value[key] = item
    return value


def main() -> int:
    raw = sys.stdin.read(_MAX_INPUT + 1)
    event = "Unknown"
    try:
        if len(raw) > _MAX_INPUT:
            raise ValueError("Hook input exceeds size limit")
        payload = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(payload, dict):
            raise ValueError("Hook payload must be an object")
        payload = _normalize_payload(payload)
        event = str(payload["event"])
        root = Path(os.environ.get("CONTEXTSENTRY_ROOT", Path.cwd())).expanduser().resolve()
        decision = PolicyEngine(root=root).handle(payload)
        if decision.stdout:
            sys.stdout.write(decision.stdout)
        return decision.exit_code
    except Exception as error:
        sys.stderr.write(f"ContextSentry hook error: {safe_label(str(error), 200)}\n")
        return 2 if event in {"UserPromptSubmit", "PreToolUse"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
