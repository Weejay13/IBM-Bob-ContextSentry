from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: str
    source: str = "inline"
    line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    event: str
    decision: str
    reason: str
    rule_id: str
    severity: str
    message: str
    target: str = ""
    taint: bool = False
    findings: tuple[Finding, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if self.decision == "block" and self.event in {"UserPromptSubmit", "PreToolUse"}:
            return 2
        return 0

    @property
    def stdout(self) -> str:
        if self.event == "SessionStart":
            return self.message
        if self.event == "UserPromptSubmit" and self.decision == "allow":
            return self.message
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "decision": self.decision,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "target": self.target,
            "taint": self.taint,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
            "exit_code": self.exit_code,
        }
