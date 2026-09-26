from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Iterable

from .models import Finding
from .util import normalize_text, safe_label

_INJECTION_PATTERNS = (
    (
        "CS-001",
        "Instruction override",
        "critical",
        "prompt_injection",
        re.compile(r"(?is)\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|above|earlier|system|developer|contextsentry)\b.{0,80}\b(?:instructions?|rules?|context|contexts|messages?|guardrails?)\b"),
    ),
    (
        "CS-002",
        "Firewall bypass request",
        "critical",
        "policy_bypass",
        re.compile(r"(?is)\b(?:disable|turn\s+off|bypass|skip|suppress)\b.{0,80}\b(?:contextsentry|firewall|security\s+hook|audit|policy)\b"),
    ),
    (
        "CS-003",
        "Secret access request",
        "critical",
        "secret_access",
        re.compile(r"(?is)\b(?:read|open|cat|print|show|reveal|collect|exfiltrate)\b.{0,100}(?:\.env|id_rsa|private\s+key|credentials?|api\s*key|access\s*token|\.ssh|\.aws)\b"),
    ),
    (
        "CS-004",
        "External exfiltration request",
        "critical",
        "exfiltration",
        re.compile(r"(?is)\b(?:send|upload|post|transmit|exfiltrate|forward)\b.{0,120}\b(?:https?://|external|remote|webhook|attacker|pastebin)\b"),
    ),
    (
        "CS-005",
        "Destructive command request",
        "high",
        "destructive_action",
        re.compile(r"(?is)\b(?:rm\s+-rf|delete\s+(?:all|every)|drop\s+(?:the\s+)?database|wipe\s+(?:the\s+)?repo)\b"),
    ),
)

_SECRET_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".p12",
    ".pem",
    ".pfx",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "shadow",
}
_SECRET_PARTS = {".aws", ".gnupg", ".ssh", ".kube", ".docker"}
_WINDOWS_ABSOLUTE = re.compile(r"^(?:[a-zA-Z]:[\\/]|\\\\)")
_SHELL_META = re.compile(r"[;&|><`\n\r\x00]")


def scan_untrusted_text(text: str, source: str = "inline") -> list[Finding]:
    normalized = normalize_text(text)
    findings: list[Finding] = []
    for rule_id, title, severity, category, pattern in _INJECTION_PATTERNS:
        match = pattern.search(normalized)
        if match:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    category=category,
                    evidence=safe_label(match.group(0), 160),
                    source=source,
                )
            )
    return findings


def is_secret_path(path: str) -> bool:
    normalized = normalize_text(path).replace("\\", "/").lower()
    pure = PurePosixPath(normalized)
    name = pure.name
    if name in _SECRET_NAMES or name.startswith(".env."):
        return True
    if any(part in _SECRET_NAMES for part in pure.parts):
        return True
    if any(part in _SECRET_PARTS for part in pure.parts):
        return True
    if name.endswith((".key", ".pem", ".p12", ".pfx")):
        return True
    if normalized.startswith("/etc/") or normalized.startswith("/proc/") or normalized.startswith("/sys/"):
        return True
    if normalized.endswith("/.gitconfig"):
        return True
    return False


def is_protected_path(path: str) -> bool:
    normalized = normalize_text(path).replace("\\", "/")
    pure = PurePosixPath(normalized.lstrip("/"))
    return any(part in {".git", ".bob", ".contextsentry", "bob_sessions"} for part in pure.parts)


def is_windows_absolute(path: str) -> bool:
    return bool(_WINDOWS_ABSOLUTE.match(path))


def has_shell_meta(command: str) -> bool:
    return bool(_SHELL_META.search(command))


def any_finding(findings: Iterable[Finding], severity: str | None = None) -> Finding | None:
    for finding in findings:
        if severity is None or finding.severity == severity:
            return finding
    return None
