from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from proofgate.contract import Contract
from proofgate.engine import Gate
from proofgate.journal import MAX_EVENT_BYTES, EventJournal, JournalError

from tests.helpers import contract_dict


class EngineTests(unittest.TestCase):
    def test_all_evidence_is_required_for_done(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_text("ok", encoding="utf-8")
            (root / "report.json").write_text('{"passed":true}', encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict(
                    [
                        {"id": "file", "type": "file", "path": "artifact"},
                        {"id": "json", "type": "json", "path": "report.json", "pointer": "/passed", "equals": True},
                    ]
                )
            )
            verdict = Gate(contract, root=root).evaluate(execute_commands=False)
            self.assertTrue(verdict.done)
            self.assertEqual(verdict.reason_code, "ALL_EVIDENCE_VERIFIED")

    def test_missing_evidence_waits_instead_of_done(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = Contract.from_dict(contract_dict([{"id": "file", "type": "file", "path": "missing"}]))
            verdict = Gate(contract, root=directory).evaluate(execute_commands=False)
            self.assertEqual(verdict.state, "WAITING")
            self.assertFalse(verdict.done)

    def test_check_mode_marks_command_as_inference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = Contract.from_dict(
                contract_dict([{"id": "command", "type": "command", "command": [sys.executable, "-c", "print('not run')"]}])
            )
            verdict = Gate(contract, root=directory).evaluate(execute_commands=False)
            self.assertEqual(verdict.results[0].classification, "inference")
            self.assertEqual(verdict.results[0].code, "COMMAND_NOT_EXECUTED")

    def test_command_failure_sets_failed_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = Contract.from_dict(
                contract_dict([{"id": "command", "type": "command", "command": [sys.executable, "-c", "raise SystemExit(1)"]}])
            )
            verdict = Gate(contract, root=directory).evaluate(execute_commands=True)
            self.assertEqual(verdict.state, "FAILED")

    def test_verdict_append_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_text("ok", encoding="utf-8")
            contract = Contract.from_dict(contract_dict([{"id": "file", "type": "file", "path": "artifact"}]))
            journal = EventJournal(root / "events.jsonl")
            gate = Gate(contract, root=root)
            first = gate.evaluate(execute_commands=True, journal=journal, idempotency_key="attempt-1")
            second = gate.evaluate(execute_commands=True, journal=journal, idempotency_key="attempt-1")
            self.assertEqual(first.state, second.state)
            self.assertEqual(first.reason_code, second.reason_code)
            self.assertEqual(len(journal.replay().events), 2)

    def test_idempotent_retry_rejects_semantically_impossible_recorded_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_text("ok", encoding="utf-8")
            contract = Contract.from_dict(contract_dict([{"id": "file", "type": "file", "path": "artifact"}]))
            gate = Gate(contract, root=root)
            journal = EventJournal(root / "events.jsonl")
            journal.append_once(
                idempotency_key="attempt:claim",
                kind="attempt_claim",
                data={"request_sha256": gate._operation_fingerprint(False), "task_id": contract.task_id},
                reserve_bytes=MAX_EVENT_BYTES,
            )
            impossible = gate.evaluate(execute_commands=False).as_journal_dict()
            impossible["status"] = "blocked"
            journal.append(
                idempotency_key="attempt:verdict",
                kind="verdict",
                data=impossible,
            )
            with self.assertRaisesRegex(JournalError, "contradicts"):
                gate.evaluate(
                    execute_commands=False,
                    journal=journal,
                    idempotency_key="attempt",
                )

    def test_idempotency_claim_prevents_command_reexecution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = (
                "from pathlib import Path; p=Path('runs.txt'); "
                "n=int(p.read_text())+1 if p.exists() else 1; p.write_text(str(n)); print('stable')"
            )
            contract = Contract.from_dict(
                contract_dict([{"id": "command", "type": "command", "command": [sys.executable, "-c", code]}])
            )
            journal = EventJournal(root / "events.jsonl")
            first = Gate(contract, root=root).evaluate(
                execute_commands=True, journal=journal, idempotency_key="same"
            )
            second = Gate(contract, root=root).evaluate(
                execute_commands=True, journal=journal, idempotency_key="same"
            )
            self.assertTrue(first.done)
            self.assertTrue(second.done)
            self.assertEqual((root / "runs.txt").read_text(encoding="utf-8"), "1")
            self.assertEqual(len(journal.replay().events), 2)

    def test_concurrent_idempotency_claim_allows_only_one_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import time; open('runs.txt','a').write('run\\n'); time.sleep(0.25)"
            contract = Contract.from_dict(
                contract_dict([{"id": "command", "type": "command", "command": [sys.executable, "-c", code]}])
            )
            journal = EventJournal(root / "events.jsonl")
            barrier = threading.Barrier(2)
            outcomes: list[object] = []

            def run() -> None:
                barrier.wait()
                try:
                    outcomes.append(
                        Gate(contract, root=root).evaluate(
                            execute_commands=True,
                            journal=journal,
                            idempotency_key="concurrent",
                        )
                    )
                except BaseException as exc:  # asserted by the coordinator
                    outcomes.append(exc)

            workers = [threading.Thread(target=run) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual((root / "runs.txt").read_text(encoding="utf-8").splitlines(), ["run"])
            self.assertEqual(len(journal.replay().events), 2)
            self.assertEqual(len(outcomes), 2)

    def test_reusing_key_with_changed_request_fails_before_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = EventJournal(root / "events.jsonl")
            first = Contract.from_dict(
                contract_dict([{"id": "file", "type": "file", "path": "missing-one"}])
            )
            second = Contract.from_dict(
                contract_dict(
                    [
                        {
                            "id": "command",
                            "type": "command",
                            "command": [sys.executable, "-c", "open('ran','w').write('yes')"],
                        }
                    ]
                )
            )
            Gate(first, root=root).evaluate(
                execute_commands=False,
                journal=journal,
                idempotency_key="same",
            )
            with self.assertRaisesRegex(JournalError, "idempotency conflict"):
                Gate(second, root=root).evaluate(
                    execute_commands=True,
                    journal=journal,
                    idempotency_key="same",
                )
            self.assertFalse((root / "ran").exists())

    def test_idempotency_key_reserves_suffix_space_before_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = Contract.from_dict(
                contract_dict(
                    [
                        {
                            "id": "command",
                            "type": "command",
                            "command": [sys.executable, "-c", "open('ran','w').write('yes')"],
                        }
                    ]
                )
            )
            with self.assertRaisesRegex(ValueError, "248"):
                Gate(contract, root=root).evaluate(
                    execute_commands=True,
                    journal=EventJournal(root / "events.jsonl"),
                    idempotency_key="x" * 249,
                )
            self.assertFalse((root / "ran").exists())

    def test_insufficient_terminal_capacity_rejects_before_command_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = Contract.from_dict(
                contract_dict(
                    [
                        {
                            "id": "command",
                            "type": "command",
                            "command": [sys.executable, "-c", "open('ran','w').write('yes')"],
                        }
                    ]
                )
            )
            with patch("proofgate.engine.MAX_EVENT_BYTES", 1000), patch(
                "proofgate.journal.MAX_EVENT_BYTES", 1000
            ), patch("proofgate.journal.MAX_JOURNAL_BYTES", 1200):
                with self.assertRaisesRegex(JournalError, "reserved terminal"):
                    Gate(contract, root=root).evaluate(
                        execute_commands=True,
                        journal=EventJournal(root / "events.jsonl"),
                        idempotency_key="capacity",
                    )
            self.assertFalse((root / "ran").exists())

    def test_journal_summary_bounds_non_utf8_command_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import os; os.write(1,b'\\xff'*65536); os.write(2,b'\\xfe'*65536)"
            contract = Contract.from_dict(
                contract_dict([{"id": "command", "type": "command", "command": [sys.executable, "-c", code]}])
            )
            journal = EventJournal(root / "events.jsonl")
            verdict = Gate(contract, root=root).evaluate(
                execute_commands=True, journal=journal, idempotency_key="binary"
            )
            self.assertTrue(verdict.done)
            self.assertEqual(len(journal.replay().events), 2)

    def test_hash_mismatch_is_failed_and_counts_toward_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact").write_text("wrong", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict(
                    [{"id": "file", "type": "file", "path": "artifact", "sha256": "0" * 64}],
                    circuit_breaker={"failure_threshold": 1},
                )
            )
            journal = EventJournal(root / "events.jsonl")
            verdict = Gate(contract, root=root).evaluate(
                execute_commands=False, journal=journal, idempotency_key="mismatch"
            )
            self.assertEqual(verdict.state, "FAILED")
            self.assertEqual(journal.replay().failures, 1)

    def test_circuit_breaker_prevents_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "marker"
            command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"]
            contract = Contract.from_dict(
                contract_dict(
                    [{"id": "command", "type": "command", "command": command}],
                    circuit_breaker={"failure_threshold": 2},
                )
            )
            journal = EventJournal(root / "events.jsonl")
            for index in range(2):
                journal.append(
                    idempotency_key=f"prior-{index}",
                    kind="verdict",
                    data={"state": "FAILED"},
                )
            verdict = Gate(contract, root=root).evaluate(
                execute_commands=True,
                journal=journal,
                idempotency_key="blocked-attempt",
            )
            self.assertEqual(verdict.state, "REJECTED")
            self.assertEqual(verdict.reason_code, "CIRCUIT_OPEN")
            self.assertFalse(marker.exists())

    def test_invalid_root_is_rejected(self) -> None:
        contract = Contract.from_dict(contract_dict([{"id": "file", "type": "file", "path": "x"}]))
        verdict = Gate(contract, root="/definitely/not/a/real/directory").evaluate(execute_commands=False)
        self.assertEqual(verdict.state, "REJECTED")

    def test_dependency_failure_skips_downstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "downstream.txt").write_text("exists", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict(
                    [
                        {"id": "upstream", "type": "file", "path": "missing.txt"},
                        {"id": "downstream", "type": "file", "path": "downstream.txt", "depends_on": ["upstream"]},
                    ]
                )
            )
            verdict = Gate(contract, root=root).evaluate(execute_commands=False)
            by_id = {item.id: item for item in verdict.results}
            self.assertEqual(by_id["downstream"].code, "DEPENDENCY_BLOCKED")
            self.assertFalse(verdict.done)

    def test_threshold_policy_can_complete_with_visible_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_text("ok", encoding="utf-8")
            (root / "two").write_text("ok", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict(
                    [
                        {"id": "one", "type": "file", "path": "one"},
                        {"id": "two", "type": "file", "path": "two"},
                        {"id": "three", "type": "file", "path": "missing"},
                    ],
                    policy={"mode": "threshold", "minimum_verified": 2},
                )
            )
            verdict = Gate(contract, root=root).evaluate(execute_commands=False)
            self.assertTrue(verdict.done)
            self.assertEqual(verdict.as_dict()["metrics"]["policy_mode"], "threshold")


if __name__ == "__main__":
    unittest.main()
