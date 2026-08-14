from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from proofgate.journal import EventJournal, JournalError, ZERO_HASH


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

