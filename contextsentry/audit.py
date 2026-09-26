from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .models import Decision
from .util import canonical_json, digest_text, safe_label, utc_now


class AuditLog:
    def __init__(self, state_dir: Path, key: bytes) -> None:
        self.state_dir = state_dir.expanduser().resolve()
        self.path = self.state_dir / "audit.jsonl"
        self.head_path = self.state_dir / "audit.head.json"
        self.key = key

    def append(
        self,
        session_id: str,
        decision: Decision,
        tool: str = "",
        policy_version: str = "",
        policy_digest: str = "",
        findings: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            records = self._read_records(handle)
            previous = records[-1] if records else None
            sequence = int(previous["sequence"]) + 1 if previous else 1
            record: dict[str, Any] = {
                "schema_version": 1,
                "sequence": sequence,
                "timestamp": utc_now(),
                "session": digest_text(session_id)[:16],
                "event": decision.event,
                "tool": safe_label(tool, 80),
                "target": safe_label(decision.target, 240),
                "target_digest": digest_text(decision.target),
                "decision": decision.decision,
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "severity": decision.severity,
                "taint": decision.taint,
                "finding_ids": sorted({str(finding.rule_id) for finding in findings}),
                "policy_version": policy_version,
                "policy_digest": policy_digest,
                "previous_mac": previous["mac"] if previous else "GENESIS",
            }
            record["mac"] = hmac.new(self.key, canonical_json(record).encode("utf-8"), hashlib.sha256).hexdigest()
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            self._write_checkpoint(record, len(records) + 1)
            return record

    def records(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            records = self._read_records(handle)
        if limit is not None:
            return records[-limit:]
        return records

    def verify(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"valid": True, "records": 0, "head": None, "checkpoint": None, "error": None}
        try:
            records = self.records()
        except (OSError, ValueError, json.JSONDecodeError) as error:
            return {"valid": False, "records": 0, "head": None, "checkpoint": None, "error": safe_label(str(error))}
        previous_mac = "GENESIS"
        for expected_sequence, record in enumerate(records, start=1):
            if record.get("sequence") != expected_sequence:
                return {"valid": False, "records": len(records), "head": None, "checkpoint": None, "error": f"Invalid sequence at {expected_sequence}"}
            if record.get("previous_mac") != previous_mac:
                return {"valid": False, "records": len(records), "head": None, "checkpoint": None, "error": f"Broken chain at {expected_sequence}"}
            supplied_mac = record.get("mac", "")
            unsigned = {key: value for key, value in record.items() if key != "mac"}
            expected_mac = hmac.new(self.key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(supplied_mac, expected_mac):
                return {"valid": False, "records": len(records), "head": None, "checkpoint": None, "error": f"Invalid MAC at {expected_sequence}"}
            previous_mac = supplied_mac
        checkpoint = self._read_checkpoint()
        head = records[-1] if records else None
        if checkpoint is not None:
            checkpoint_sequence = int(checkpoint.get("sequence", 0))
            if checkpoint_sequence < 0 or checkpoint_sequence > len(records):
                return {"valid": False, "records": len(records), "head": head, "checkpoint": checkpoint, "error": "Audit tail is shorter than the sealed checkpoint"}
            checkpoint_record = records[checkpoint_sequence - 1] if checkpoint_sequence else None
            expected_head = checkpoint_record["mac"] if checkpoint_record else None
            if checkpoint.get("mac") != expected_head:
                return {"valid": False, "records": len(records), "head": head, "checkpoint": checkpoint, "error": "Checkpoint does not match the sealed audit record"}
        return {"valid": True, "records": len(records), "head": head, "checkpoint": checkpoint, "error": None}

    def checkpoint(self) -> dict[str, Any]:
        records = self.records()
        return self._write_checkpoint(records[-1] if records else None, len(records))

    def summary(self) -> dict[str, Any]:
        try:
            records = self.records()
        except (OSError, ValueError, json.JSONDecodeError) as error:
            return {
                "valid": False,
                "error": safe_label(str(error)),
                "records": 0,
                "blocked": 0,
                "allowed": 0,
                "observed": 0,
                "tainted": 0,
                "head": None,
            }
        verification = self.verify()
        return {
            "valid": verification["valid"],
            "error": verification["error"],
            "records": len(records),
            "blocked": sum(1 for record in records if record.get("decision") == "block"),
            "allowed": sum(1 for record in records if record.get("decision") == "allow"),
            "observed": sum(1 for record in records if record.get("decision") == "observe"),
            "tainted": sum(1 for record in records if record.get("taint")),
            "head": records[-1] if records else None,
        }

    def clear(self) -> None:
        for path in (self.path, self.head_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _read_records(self, handle) -> list[dict[str, Any]]:
        handle.seek(0)
        content = handle.read()
        if not content:
            return []
        lines = content.splitlines()
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(lines, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Malformed audit record at line {line_number}") from error
            if not isinstance(value, dict):
                raise ValueError(f"Invalid audit record at line {line_number}")
            records.append(value)
        self._validate_links(records)
        return records

    def _validate_links(self, records: list[dict[str, Any]]) -> None:
        previous = "GENESIS"
        for index, record in enumerate(records, start=1):
            supplied_mac = str(record.get("mac", ""))
            if record.get("sequence") != index or record.get("previous_mac") != previous:
                raise ValueError(f"Broken audit chain at line {index}")
            unsigned = {key: value for key, value in record.items() if key != "mac"}
            expected_mac = hmac.new(self.key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(supplied_mac, expected_mac):
                raise ValueError(f"Invalid audit MAC at line {index}")
            previous = supplied_mac

    def _write_checkpoint(self, record: dict[str, Any] | None, count: int) -> dict[str, Any]:
        body = {
            "sequence": record["sequence"] if record else 0,
            "mac": record["mac"] if record else None,
            "records": count,
            "timestamp": utc_now(),
        }
        body["checkpoint_mac"] = hmac.new(self.key, canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
        temporary = self.head_path.with_suffix(".tmp")
        temporary.write_text(canonical_json(body), encoding="utf-8")
        os.replace(temporary, self.head_path)
        return body

    def _read_checkpoint(self) -> dict[str, Any] | None:
        if not self.head_path.exists():
            return None
        try:
            checkpoint = json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"invalid": True}
        if not isinstance(checkpoint, dict):
            return {"invalid": True}
        supplied = checkpoint.get("checkpoint_mac", "")
        unsigned = {key: value for key, value in checkpoint.items() if key != "checkpoint_mac"}
        expected = hmac.new(self.key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            return {"invalid": True}
        return checkpoint
