from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from contextsentry.audit import AuditLog
from contextsentry.models import Decision


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.audit = AuditLog(self.state, b"audit-test-key")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def decision(self, name: str = "safe.py") -> Decision:
        return Decision("PreToolUse", "allow", "WORKSPACE_READ_ALLOWED", "CS-PATH-006", "info", "Allowed", target=name)

    def test_empty_chain_is_valid(self) -> None:
        self.assertTrue(self.audit.verify()["valid"])

    def test_chain_links_records(self) -> None:
        self.audit.append("session-one", self.decision("one.py"))
        self.audit.append("session-one", self.decision("two.py"))
        verification = self.audit.verify()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["records"], 2)
        self.assertNotEqual(verification["head"]["previous_mac"], "GENESIS")

    def test_tampering_invalidates_chain(self) -> None:
        self.audit.append("session-one", self.decision("one.py"))
        self.audit.append("session-one", self.decision("two.py"))
        lines = self.audit.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["target"] = "tampered.py"
        lines[0] = json.dumps(record, separators=(",", ":"), sort_keys=True)
        self.audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verification = self.audit.verify()
        self.assertFalse(verification["valid"])
        self.assertIn("Invalid", verification["error"])

    def test_checkpoint_survives_later_records(self) -> None:
        self.audit.append("session-one", self.decision("one.py"))
        self.audit.append("session-two", self.decision("two.py"))
        verification = self.audit.verify()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["checkpoint"]["sequence"], 2)
        self.assertEqual(verification["head"]["sequence"], 2)

    def test_deleted_record_invalidates_chain(self) -> None:
        self.audit.append("session-one", self.decision("one.py"))
        self.audit.append("session-one", self.decision("two.py"))
        lines = self.audit.path.read_text(encoding="utf-8").splitlines()
        self.audit.path.write_text(lines[0] + "\n", encoding="utf-8")
        self.assertFalse(self.audit.verify()["valid"])


if __name__ == "__main__":
    unittest.main()
