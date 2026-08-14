from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from proofgate.contract import Contract
from proofgate.engine import Gate
from proofgate.journal import EventJournal

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
            self.assertEqual(first, second)
            self.assertEqual(len(journal.replay().events), 1)

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


if __name__ == "__main__":
    unittest.main()

