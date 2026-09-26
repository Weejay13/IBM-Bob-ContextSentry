from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding
from .patterns import is_secret_path, scan_untrusted_text
from .util import safe_label

_IGNORED_DIRECTORIES = {".git", ".contextsentry", "bob_sessions", "node_modules", "__pycache__", ".venv", "venv"}
_TEXT_SUFFIXES = {".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html", ".java", ".js", ".json", ".jsx", ".kt", ".md", ".mjs", ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt", ".vue", ".xml", ".yaml", ".yml"}
_SCRIPT_FILES = {"Dockerfile", "Makefile"}


class RepositoryScanner:
    def __init__(self, root: Path | str, max_files: int = 500, max_file_bytes: int = 131072, max_total_bytes: int = 2097152) -> None:
        self.root = Path(root).expanduser().resolve()
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def scan(self, relative_path: str = ".") -> dict[str, Any]:
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        truncated = False
        try:
            target = self._resolve(relative_path)
        except ValueError as error:
            findings.append(Finding("FS-002", "Path outside workspace", "critical", "path_escape", safe_label(str(error)), source=relative_path))
            return self._result(relative_path, 0, 0, True, findings)
        if target.is_file():
            file_result = self._scan_file(target)
            findings.extend(file_result[0])
            files_scanned = 1
            bytes_scanned = file_result[1]
            truncated = file_result[2]
        elif target.is_dir():
            for path in self._iter_files(target):
                if files_scanned >= self.max_files or bytes_scanned >= self.max_total_bytes:
                    truncated = True
                    break
                file_findings, file_bytes, file_truncated = self._scan_file(path)
                findings.extend(file_findings)
                files_scanned += 1
                bytes_scanned += file_bytes
                truncated = truncated or file_truncated
        else:
            findings.append(Finding("FS-003", "Path does not exist", "medium", "invalid_path", safe_label(relative_path), source=relative_path))
        return self._result(relative_path, files_scanned, bytes_scanned, truncated, findings)

    def scan_instruction_files(self) -> dict[str, Any]:
        candidates = [
            self.root / "AGENTS.md",
            self.root / "CLAUDE.md",
            self.root / ".cursorrules",
            self.root / ".github" / "copilot-instructions.md",
        ]
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        for path in candidates:
            if not path.is_file():
                continue
            file_findings, file_bytes, _ = self._scan_file(path)
            findings.extend(file_findings)
            files_scanned += 1
            bytes_scanned += file_bytes
        return self._result("workspace instructions", files_scanned, bytes_scanned, False, findings)

    def _iter_files(self, target: Path):
        for directory, names, filenames in __import__("os").walk(target):
            names[:] = sorted(name for name in names if name not in _IGNORED_DIRECTORIES)
            for filename in sorted(filenames):
                path = Path(directory) / filename
                if path.is_symlink():
                    try:
                        path.resolve().relative_to(self.root)
                    except ValueError:
                        yield path
                    continue
                if path.is_file():
                    yield path

    def _scan_file(self, path: Path) -> tuple[list[Finding], int, bool]:
        findings: list[Finding] = []
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(self.root).as_posix()
        except (OSError, ValueError):
            relative = safe_label(path)
            findings.append(Finding("FS-004", "Symlink escapes workspace", "critical", "path_escape", relative, source=relative))
            return findings, 0, False
        if path.is_symlink():
            findings.append(Finding("FS-004", "Symlink requires policy review", "high", "symlink", relative, source=relative))
        if is_secret_path(relative):
            findings.append(Finding("FS-001", "Secret-bearing path", "critical", "secret_access", relative, source=relative))
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name not in _SCRIPT_FILES:
            return findings, 0, False
        try:
            with path.open("rb") as handle:
                raw = handle.read(self.max_file_bytes + 1)
        except OSError:
            return findings, 0, False
        truncated = len(raw) > self.max_file_bytes
        raw = raw[: self.max_file_bytes]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return findings, len(raw), truncated
        seen: set[tuple[str, int]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            for finding in scan_untrusted_text(line, relative):
                identity = (finding.rule_id, line_number)
                if identity not in seen:
                    seen.add(identity)
                    findings.append(
                        Finding(
                            rule_id=finding.rule_id,
                            title=finding.title,
                            severity=finding.severity,
                            category=finding.category,
                            evidence=finding.evidence,
                            source=relative,
                            line=line_number,
                        )
                    )
        if path.name == "package.json":
            findings.extend(self._scan_package_scripts(path, text, relative))
        return findings, len(raw), truncated

    def _scan_package_scripts(self, path: Path, text: str, relative: str) -> list[Finding]:
        try:
            package = json.loads(text)
        except json.JSONDecodeError:
            return []
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        if not isinstance(scripts, dict):
            return []
        findings: list[Finding] = []
        for name, command in scripts.items():
            if not isinstance(command, str):
                continue
            normalized = command.lower()
            if any(token in normalized for token in ("curl ", "wget ", "nc ", "ssh ", "powershell", "invoke-webrequest", "http://", "https://")):
                findings.append(
                    Finding(
                        "CMD-001",
                        "Network-capable package script",
                        "critical",
                        "supply_chain",
                        safe_label(f"{name}: {command}"),
                        source=relative,
                        metadata={"script": str(name)},
                    )
                )
            if any(token in str(name).lower() for token in ("preinstall", "postinstall", "prepare")):
                findings.append(
                    Finding(
                        "CMD-002",
                        "Lifecycle script executes automatically",
                        "high",
                        "supply_chain",
                        safe_label(f"{name}: {command}"),
                        source=relative,
                        metadata={"script": str(name)},
                    )
                )
        return findings

    def _resolve(self, relative_path: str) -> Path:
        candidate = Path(relative_path).expanduser()
        target = candidate if candidate.is_absolute() else self.root / candidate
        resolved = target.resolve(strict=False)
        resolved.relative_to(self.root)
        return resolved

    def _result(self, source: str, files_scanned: int, bytes_scanned: int, truncated: bool, findings: list[Finding]) -> dict[str, Any]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ordered = sorted(findings, key=lambda finding: (severity_order.get(finding.severity, 4), finding.source, finding.line or 0, finding.rule_id))
        counts = {severity: sum(1 for finding in ordered if finding.severity == severity) for severity in severity_order}
        return {
            "source": source,
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
            "truncated": truncated,
            "counts": counts,
            "findings": [finding.to_dict() for finding in ordered],
        }
