from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from proofgate.contract import Contract
from proofgate.engine import Gate
from proofgate.journal import EventJournal
from proofgate.receipt import ReceiptError, canonical_bytes, create_receipt, load_receipt, verify_receipt, write_receipt

from tests.helpers import contract_dict


class ReceiptTests(unittest.TestCase):
    def test_receipt_binds_contract_verdict_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("release-v1\n", encoding="utf-8")
            contract = Contract.from_dict(contract_dict([{"id": "artifact", "type": "file", "path": "artifact.txt"}]))
            verdict = Gate(contract, root=root).evaluate(execute_commands=False)
            receipt = create_receipt(contract, verdict, root=root)
            path = root / "receipt.json"
            write_receipt(path, receipt)
            result = verify_receipt(load_receipt(path), root=root)
            self.assertTrue(result.valid)
            self.assertEqual(result.code, "RECEIPT_VERIFIED")
            self.assertEqual(result.artifacts_verified, 1)

    def test_tampered_receipt_and_artifact_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.txt"
            artifact.write_text("original", encoding="utf-8")
            contract = Contract.from_dict(contract_dict([{"id": "artifact", "type": "file", "path": "artifact.txt"}]))
            receipt = create_receipt(contract, Gate(contract, root=root).evaluate(execute_commands=False), root=root)
            path = root / "receipt.json"
            write_receipt(path, receipt)
            artifact.write_text("modified", encoding="utf-8")
            self.assertEqual(verify_receipt(load_receipt(path), root=root).code, "ARTIFACT_HASH_MISMATCH")
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["created_at"] = "2026-01-01T00:00:00Z"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ReceiptError, "hash"):
                load_receipt(path)

    def test_blocked_receipt_cannot_satisfy_downstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = Contract.from_dict(
                contract_dict(
                    [{"id": "missing", "type": "file", "path": "missing.txt"}],
                    task={"id": "upstream", "terminal_state": "DONE"},
                )
            )
            upstream_verdict = Gate(upstream, root=root).evaluate(execute_commands=False)
            self.assertFalse(upstream_verdict.done)
            path = root / "blocked.json"
            write_receipt(path, create_receipt(upstream, upstream_verdict, root=root))

            downstream = Contract.from_dict(
                contract_dict(
                    [
                        {
                            "id": "prior",
                            "type": "receipt",
                            "path": "blocked.json",
                            "expected_task_id": "upstream",
                        }
                    ],
                    task={"id": "downstream", "terminal_state": "DONE"},
                )
            )
            verdict = Gate(downstream, root=root).evaluate(execute_commands=False)
            self.assertFalse(verdict.done)
            self.assertEqual(verdict.results[0].code, "RECEIPT_NOT_DONE")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_receipt_shape_validation_is_independent_of_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            (root / "artifact.txt").write_text("trusted", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict([{"id": "artifact", "type": "file", "path": "artifact.txt"}])
            )
            receipt_path = base / "receipt.json"
            write_receipt(
                receipt_path,
                create_receipt(contract, Gate(contract, root=root).evaluate(execute_commands=False), root=root),
            )

            unrelated = base / "unrelated"
            unrelated.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (unrelated / "artifact.txt").symlink_to(outside / "artifact.txt")
            previous = Path.cwd()
            try:
                os.chdir(unrelated)
                loaded = load_receipt(receipt_path)
            finally:
                os.chdir(previous)
            self.assertTrue(verify_receipt(loaded, root=root).valid)

    def test_receipt_hash_is_stable_when_idempotent_run_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("trusted", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict([{"id": "artifact", "type": "file", "path": "artifact.txt"}])
            )
            gate = Gate(contract, root=root)
            journal = EventJournal(root / "events.jsonl")
            first = gate.evaluate(execute_commands=False, journal=journal, idempotency_key="stable")
            second = gate.evaluate(execute_commands=False, journal=journal, idempotency_key="stable")
            created_at = "2026-08-16T00:00:00Z"
            first_receipt = create_receipt(contract, first, root=root, journal=journal, created_at=created_at)
            second_receipt = create_receipt(contract, second, root=root, journal=journal, created_at=created_at)
            self.assertEqual(first_receipt["receipt_sha256"], second_receipt["receipt_sha256"])

    def test_canonical_receipt_json_rejects_non_finite_numbers(self) -> None:
        with self.assertRaisesRegex(ReceiptError, "canonical JSON"):
            canonical_bytes({"value": float("nan")})

    def test_rehashed_but_semantically_impossible_completion_is_rejected_before_nesting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("trusted", encoding="utf-8")
            upstream = Contract.from_dict(
                contract_dict(
                    [{"id": "artifact", "type": "file", "path": "artifact.txt"}],
                    task={"id": "upstream", "terminal_state": "DONE"},
                )
            )
            receipt = create_receipt(
                upstream,
                Gate(upstream, root=root).evaluate(execute_commands=False),
                root=root,
            )
            receipt["verdict"]["evidence"][0].update(
                {"classification": "blockage", "passed": False, "code": "FILE_MISSING"}
            )
            unsigned = dict(receipt)
            unsigned.pop("receipt_sha256")
            receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
            path = root / "impossible.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")

            downstream = Contract.from_dict(
                contract_dict(
                    [
                        {
                            "id": "prior",
                            "type": "receipt",
                            "path": "impossible.json",
                            "expected_task_id": "upstream",
                        }
                    ],
                    task={"id": "downstream", "terminal_state": "DONE"},
                )
            )
            verdict = Gate(downstream, root=root).evaluate(execute_commands=False)
            self.assertFalse(verdict.done)
            self.assertEqual(verdict.results[0].code, "RECEIPT_INVALID")

    def test_receipt_rejects_unknown_terminal_state_even_with_valid_self_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("trusted", encoding="utf-8")
            contract = Contract.from_dict(
                contract_dict([{"id": "artifact", "type": "file", "path": "artifact.txt"}])
            )
            receipt = create_receipt(
                contract,
                Gate(contract, root=root).evaluate(execute_commands=False),
                root=root,
            )
            receipt["verdict"].update({"state": "IMPOSSIBLE", "status": "blocked", "done": False})
            unsigned = dict(receipt)
            unsigned.pop("receipt_sha256")
            receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
            with self.assertRaisesRegex(ReceiptError, "state"):
                verify_receipt(receipt, verify_artifacts=False)


if __name__ == "__main__":
    unittest.main()
