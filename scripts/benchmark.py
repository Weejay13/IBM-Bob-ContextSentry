from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contextsentry.scanner import RepositoryScanner
EXPECTED_ATTACK_RULES = {"CS-001", "CS-003", "CS-004", "CMD-001", "CMD-002"}


def main() -> int:
    scanner = RepositoryScanner(ROOT)
    poisoned = scanner.scan("demo/poisoned_repo")
    safe = scanner.scan("demo/safe_repo")
    detected = {finding["rule_id"] for finding in poisoned["findings"]}
    result = {
        "poisoned_repository": {
            "files_scanned": poisoned["files_scanned"],
            "findings": len(poisoned["findings"]),
            "critical_findings": poisoned["counts"].get("critical", 0),
            "expected_signals": sorted(EXPECTED_ATTACK_RULES),
            "detected_signals": sorted(detected & EXPECTED_ATTACK_RULES),
            "expected_signal_coverage": f"{len(detected & EXPECTED_ATTACK_RULES)}/{len(EXPECTED_ATTACK_RULES)}",
        },
        "safe_repository": {
            "files_scanned": safe["files_scanned"],
            "findings": len(safe["findings"]),
            "unexpected_findings": len(safe["findings"]),
        },
    }
    print(json.dumps(result, indent=2))
    return 0 if len(detected & EXPECTED_ATTACK_RULES) == len(EXPECTED_ATTACK_RULES) and not safe["findings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
