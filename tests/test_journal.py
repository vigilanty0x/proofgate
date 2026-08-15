import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from status_truth import AppendOnlyJournal, CheckOutcome, CheckResult, IdempotencyConflict, JournalCorruption, normalize
from helpers import NOW, provenance


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.path = Path(self.directory.name) / "nested" / "journal.jsonl"
        self.journal = AppendOnlyJournal(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def record(self, operation="op-1", outcome=CheckOutcome.PASS, recorded_at=NOW):
        prov = provenance(outcome.value) if outcome in {CheckOutcome.PASS, CheckOutcome.FAIL} else None
        return normalize(
            subject="svc", operation_id=operation,
            checks=[CheckResult("heartbeat", outcome, provenance=prov)], recorded_at=recorded_at,
        )

    def test_empty_journal_verifies(self):
        self.assertEqual(self.journal.verify(), {"valid": True, "entries": 0, "head_sha256": None})

    def test_append_creates_parent_and_file(self):
        self.journal.append(self.record())
        self.assertTrue(self.path.is_file())

    def test_append_uses_one_json_line(self):
        self.journal.append(self.record())
        self.assertEqual(len(self.path.read_text().splitlines()), 1)

    def test_exact_replay_returns_same_entry(self):
        first = self.journal.append(self.record(recorded_at=NOW))
        second = self.journal.append(self.record(recorded_at="2026-01-01T00:00:01Z"))
        self.assertEqual(first.journal_id, second.journal_id)
        self.assertEqual(self.journal.verify()["entries"], 1)

    def test_conflicting_operation_is_rejected(self):
        self.journal.append(self.record(outcome=CheckOutcome.PASS))
        with self.assertRaises(IdempotencyConflict):
            self.journal.append(self.record(outcome=CheckOutcome.FAIL))

    def test_two_entries_form_hash_chain(self):
        first = self.journal.append(self.record("op-1"))
        second = self.journal.append(self.record("op-2"))
        self.assertEqual(second.previous_sha256, first.entry_sha256)

    def test_verify_reports_head(self):
        last = self.journal.append(self.record())
        verified = self.journal.verify()
        self.assertEqual(verified["head_sha256"], last.entry_sha256)

    def test_iter_round_trips_record(self):
        record = self.record()
        self.journal.append(record)
        self.assertEqual(list(self.journal.iter_entries())[0].record, record)

    def test_mutated_record_is_detected(self):
        self.journal.append(self.record())
        raw = json.loads(self.path.read_text())
        raw["record"]["subject"] = "mutated"
        self.path.write_text(json.dumps(raw) + "\n")
        with self.assertRaisesRegex(JournalCorruption, "hash mismatch"):
            self.journal.verify()

    def test_broken_previous_hash_is_detected(self):
        self.journal.append(self.record("op-1"))
        self.journal.append(self.record("op-2"))
        lines = self.path.read_text().splitlines()
        second = json.loads(lines[1])
        second["previous_sha256"] = "0" * 64
        body = {key: second[key] for key in ("journal_id", "previous_sha256", "record")}
        from status_truth.contract import canonical_json
        import hashlib
        second["entry_sha256"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        self.path.write_text(lines[0] + "\n" + json.dumps(second) + "\n")
        with self.assertRaisesRegex(JournalCorruption, "chain"):
            self.journal.verify()

    def test_partial_line_is_detected(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text('{"partial":true}')
        with self.assertRaisesRegex(JournalCorruption, "partial"):
            self.journal.verify()

    def test_invalid_json_is_detected(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("not-json\n")
        with self.assertRaisesRegex(JournalCorruption, "malformed"):
            self.journal.verify()


if __name__ == "__main__":
    unittest.main()

