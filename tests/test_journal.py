from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from proofgate.journal import EventJournal, JournalError, ZERO_HASH, _canonical, _event_hash


class JournalTests(unittest.TestCase):
    def test_append_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / "events.jsonl")
            event = journal.append(idempotency_key="attempt-1", kind="note", data={"value": 1})
            replay = journal.replay()
            self.assertEqual(len(replay.events), 1)
            self.assertEqual(replay.events[0]["hash"], event["hash"])
            self.assertNotEqual(replay.last_hash, ZERO_HASH)

    def test_same_operation_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / "events.jsonl")
            first = journal.append(idempotency_key="same", kind="note", data={"value": 1})
            second = journal.append(idempotency_key="same", kind="note", data={"value": 1})
            self.assertEqual(first, second)
            self.assertEqual(len(journal.replay().events), 1)

    def test_idempotency_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / "events.jsonl")
            journal.append(idempotency_key="same", kind="note", data={"value": 1})
            with self.assertRaisesRegex(JournalError, "idempotency conflict"):
                journal.append(idempotency_key="same", kind="note", data={"value": 2})

    def test_idempotency_comparison_preserves_json_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / "events.jsonl")
            journal.append(idempotency_key="same", kind="note", data={"value": True})
            with self.assertRaisesRegex(JournalError, "idempotency conflict"):
                journal.append(idempotency_key="same", kind="note", data={"value": 1})

    def test_non_finite_event_data_is_rejected_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaisesRegex(JournalError, "JSON"):
                EventJournal(path).append(idempotency_key="nan", kind="note", data={"value": float("nan")})
            self.assertFalse(path.exists() and path.stat().st_size)
            with self.assertRaisesRegex(JournalError, "keys must be strings"):
                EventJournal(path).append(idempotency_key="key", kind="note", data={1: "value"})

    def test_replay_requires_integer_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            unsigned = {
                "event_id": "one",
                "idempotency_key": "one",
                "sequence": 1.0,
                "kind": "note",
                "timestamp": "2026-08-16T00:00:00Z",
                "data": {},
                "previous_hash": ZERO_HASH,
            }
            path.write_bytes(_canonical({**unsigned, "hash": _event_hash(unsigned)}) + b"\n")
            with self.assertRaisesRegex(JournalError, "sequence mismatch"):
                EventJournal(path).replay()

    def test_append_cannot_cross_total_journal_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            with patch("proofgate.journal.MAX_JOURNAL_BYTES", 900):
                journal.append(idempotency_key="one", kind="note", data={"value": "x" * 350})
                before = path.read_bytes()
                with self.assertRaisesRegex(JournalError, "journal exceeds"):
                    journal.append(idempotency_key="two", kind="note", data={"value": "y" * 350})
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(len(journal.replay().events), 1)

    def test_claim_can_reserve_space_before_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            with patch("proofgate.journal.MAX_JOURNAL_BYTES", 800), patch(
                "proofgate.journal.MAX_EVENT_BYTES", 500
            ):
                with self.assertRaisesRegex(JournalError, "journal exceeds"):
                    journal.append_once(
                        idempotency_key="claim:claim",
                        kind="attempt_claim",
                        data={"request_sha256": "0" * 64},
                        reserve_bytes=500,
                    )
                self.assertFalse(path.exists() and path.stat().st_size)

    def test_claim_reservation_survives_append_and_protects_terminal_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            with patch("proofgate.journal.MAX_JOURNAL_BYTES", 1500), patch(
                "proofgate.journal.MAX_EVENT_BYTES", 1000
            ):
                journal.append_once(
                    idempotency_key="run:claim",
                    kind="attempt_claim",
                    data={"request_sha256": "0" * 64, "task_id": "demo"},
                    reserve_bytes=1000,
                )
                with self.assertRaisesRegex(JournalError, "reserved terminal"):
                    journal.append(
                        idempotency_key="unrelated",
                        kind="note",
                        data={"value": "x" * 500},
                    )
                terminal = journal.append(
                    idempotency_key="run:verdict",
                    kind="verdict",
                    data={"state": "DONE"},
                )
                self.assertEqual(terminal["kind"], "verdict")
                self.assertEqual(len(journal.replay().events), 2)

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            journal.append(idempotency_key="one", kind="note", data={"value": 1})
            event = json.loads(path.read_text(encoding="utf-8"))
            event["data"]["value"] = 2
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(JournalError, "hash mismatch"):
                journal.replay()

    def test_concurrent_appends_remain_contiguous_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / "events.jsonl")
            errors: list[BaseException] = []

            def append(index: int) -> None:
                try:
                    journal.append(idempotency_key=f"parallel-{index}", kind="check", data={"index": index})
                except BaseException as exc:  # captured and asserted in the coordinator thread
                    errors.append(exc)

            workers = [threading.Thread(target=append, args=(index,)) for index in range(20)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
            self.assertFalse(errors)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            replay = journal.replay()
            self.assertEqual(len(replay.events), 20)
            self.assertEqual([event["sequence"] for event in replay.events], list(range(1, 21)))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            journal.append(idempotency_key="one", kind="check", data={"ok": True})
            line = path.read_text(encoding="utf-8")
            path.write_text(line.replace('"kind":', '"kind":"shadow","kind":', 1), encoding="utf-8")
            with self.assertRaisesRegex(JournalError, "duplicate JSON key"):
                journal.replay()

    def test_broken_chain_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = EventJournal(path)
            journal.append(idempotency_key="one", kind="note", data={"value": 1})
            journal.append(idempotency_key="two", kind="note", data={"value": 2})
            lines = path.read_text(encoding="utf-8").splitlines()
            second = json.loads(lines[1])
            second["previous_hash"] = ZERO_HASH
            lines[1] = json.dumps(second)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(JournalError, "chain mismatch"):
                journal.replay()


if __name__ == "__main__":
    unittest.main()
