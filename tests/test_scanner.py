from __future__ import annotations

import unittest
from pathlib import Path

from contextsentry.scanner import RepositoryScanner


class RepositoryScannerTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent

    def test_poisoned_fixture_is_detected(self) -> None:
        result = RepositoryScanner(self.root).scan("demo/poisoned_repo")
        rule_ids = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("CS-001", rule_ids)
        self.assertIn("CS-003", rule_ids)
        self.assertIn("CMD-001", rule_ids)
        self.assertIn("CMD-002", rule_ids)
        self.assertGreaterEqual(result["counts"]["critical"], 3)

    def test_session_start_does_not_treat_project_readme_as_attack_content(self) -> None:
        result = RepositoryScanner(self.root).scan_instruction_files()
        self.assertEqual(result["findings"], [])

    def test_safe_fixture_has_no_findings(self) -> None:
        result = RepositoryScanner(self.root).scan("demo/safe_repo")
        self.assertEqual(result["findings"], [])
        self.assertGreater(result["files_scanned"], 0)

    def test_outside_path_is_rejected(self) -> None:
        result = RepositoryScanner(self.root).scan("../")
        self.assertEqual(result["findings"][0]["rule_id"], "FS-002")


if __name__ == "__main__":
    unittest.main()
