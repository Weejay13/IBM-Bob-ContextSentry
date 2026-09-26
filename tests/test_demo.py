from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from contextsentry.demo import DemoRunner
from contextsentry.policy import PolicyEngine


class RecordingEngine:
    def __init__(self, fail_on: int | None = None) -> None:
        self.fail_on = fail_on
        self.calls = 0

    def handle(self, payload):
        self.calls += 1
        if self.fail_on is not None and self.calls == self.fail_on:
            raise RuntimeError("simulated engine failure")
        return SimpleNamespace(
            event=payload.get("event", "Unknown"),
            decision="block" if self.calls % 2 else "allow",
            reason="TEST_DECISION",
            rule_id="CS-TEST-001",
            severity="high",
            target="test-target",
        )


class DemoRunnerTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent

    def runner(self, engine=None) -> DemoRunner:
        return DemoRunner(engine or PolicyEngine(root=self.root), step_delay=0.0, final_delay=0.0)

    def test_run_completes_with_sealed_audit(self) -> None:
        runner = self.runner()
        started = runner.start()
        self.assertEqual(started["status"], "running")
        final = runner.wait()
        self.assertEqual(final["status"], "complete")
        self.assertEqual(final["current_step"], 8)
        self.assertEqual(final["total_steps"], 8)
        self.assertEqual(len(final["steps"]), 8)
        self.assertIsNone(final["error"])
        outcomes = [step["outcome"] for step in final["steps"]]
        self.assertIn("block", outcomes)
        self.assertEqual(final["steps"][-1]["rule_id"], "CS-OBS-002")

    def test_engine_failure_reports_error_instead_of_hanging(self) -> None:
        engine = RecordingEngine(fail_on=3)
        runner = self.runner(engine)
        runner.start()
        final = runner.wait()
        self.assertEqual(final["status"], "error")
        self.assertEqual(final["failed_step"], 3)
        self.assertIn("simulated engine failure", final["error"])
        self.assertEqual(len(final["steps"]), 2)

    def test_failed_run_can_be_restarted(self) -> None:
        engine = RecordingEngine(fail_on=1)
        runner = self.runner(engine)
        runner.start()
        self.assertEqual(runner.wait()["status"], "error")
        engine.fail_on = None
        runner.start()
        final = runner.wait()
        self.assertEqual(final["status"], "complete")
        self.assertEqual(len(final["steps"]), 8)

    def test_reset_interrupts_run_and_blocks_stale_writes(self) -> None:
        runner = self.runner()
        runner.start()
        state = runner.reset()
        self.assertEqual(state["status"], "idle")
        self.assertEqual(state["steps"], [])
        final = runner.wait()
        self.assertEqual(final["status"], "idle")
        self.assertEqual(final["current_step"], 0)
        self.assertEqual(final["steps"], [])

    def test_start_during_live_run_reuses_session(self) -> None:
        runner = DemoRunner(PolicyEngine(root=self.root), step_delay=0.05, final_delay=0.0)
        first = runner.start()
        second = runner.start()
        self.assertEqual(first["session_id"], second["session_id"])
        runner.wait()
        self.assertEqual(runner.status()["status"], "complete")

    def test_start_recovers_from_dead_thread(self) -> None:
        engine = RecordingEngine(fail_on=2)
        runner = self.runner(engine)
        runner.start()
        self.assertEqual(runner.wait()["status"], "error")
        engine.fail_on = None
        restarted = runner.start()
        self.assertEqual(restarted["status"], "running")
        self.assertEqual(len(runner.wait()["steps"]), 8)


if __name__ == "__main__":
    unittest.main()
