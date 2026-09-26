from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

from .util import canonical_json, digest_text, utc_now


class SessionStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir.expanduser().resolve()
        self.path = self.state_dir / "sessions.json"

    def get(self, session_id: str) -> dict[str, Any]:
        state = self._read()
        return state.get(digest_text(session_id), {"tainted": False, "finding_ids": [], "events": 0})

    def mark_tainted(self, session_id: str, finding_ids: list[str]) -> dict[str, Any]:
        with self.path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            state = self._read_unlocked(handle)
            key = digest_text(session_id)
            session = state.get(key, {"tainted": False, "finding_ids": [], "events": 0})
            session["tainted"] = True
            session["finding_ids"] = sorted(set(session.get("finding_ids", [])) | set(finding_ids))
            session["last_seen"] = utc_now()
            state[key] = session
            handle.seek(0)
            handle.truncate()
            handle.write(canonical_json(state))
            handle.flush()
            os.fsync(handle.fileno())
            return session

    def record_event(self, session_id: str) -> dict[str, Any]:
        with self.path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            state = self._read_unlocked(handle)
            key = digest_text(session_id)
            session = state.get(key, {"tainted": False, "finding_ids": [], "events": 0})
            session["events"] = int(session.get("events", 0)) + 1
            session["last_seen"] = utc_now()
            state[key] = session
            handle.seek(0)
            handle.truncate()
            handle.write(canonical_json(state))
            handle.flush()
            os.fsync(handle.fileno())
            return session

    def count_tainted(self) -> int:
        return sum(1 for session in self._read().values() if session.get("tainted"))

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        with self.path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            return self._read_unlocked(handle)

    def _read_unlocked(self, handle) -> dict[str, Any]:
        handle.seek(0)
        content = handle.read()
        if not content:
            return {}
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("Invalid session state")
        return value
