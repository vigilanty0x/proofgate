"""Append-only, hash-chained journal with idempotent operation identifiers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterator, Mapping

from .contract import ContractError, StatusRecord, canonical_json


class JournalError(RuntimeError):
    pass


class IdempotencyConflict(JournalError):
    pass


class JournalCorruption(JournalError):
    pass


@dataclass(frozen=True, slots=True)
class JournalEntry:
    journal_id: str
    previous_sha256: str | None
    record: StatusRecord
    entry_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "journal_id": self.journal_id,
            "previous_sha256": self.previous_sha256,
            "record": self.record.to_dict(),
            "entry_sha256": self.entry_sha256,
        }


class AppendOnlyJournal:
    """A small local JSONL journal. Existing bytes are never rewritten."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def append(self, record: StatusRecord) -> JournalEntry:
        entries = list(self.iter_entries())
        for existing in entries:
            if existing.record.operation_id == record.operation_id:
                if existing.record.logical_sha256 != record.logical_sha256:
                    raise IdempotencyConflict(
                        f"operation_id {record.operation_id!r} already has different logical content"
                    )
                return existing
        previous = entries[-1].entry_sha256 if entries else None
        journal_id = hashlib.sha256(
            f"{record.operation_id}:{record.logical_sha256}".encode("utf-8")
        ).hexdigest()
        body = {"journal_id": journal_id, "previous_sha256": previous, "record": record.to_dict()}
        entry_sha = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        entry = JournalEntry(journal_id, previous, record, entry_sha)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = (canonical_json(entry.to_dict()) + "\n").encode("utf-8")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return entry

    def iter_entries(self) -> Iterator[JournalEntry]:
        if not self.path.exists():
            return
        previous: str | None = None
        operation_ids: set[str] = set()
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.endswith("\n"):
                    raise JournalCorruption(f"line {line_number}: partial journal entry")
                try:
                    raw = json.loads(line)
                    entry = self._decode(raw)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError, ContractError) as exc:
                    raise JournalCorruption(f"line {line_number}: malformed entry") from exc
                body = {
                    "journal_id": entry.journal_id,
                    "previous_sha256": entry.previous_sha256,
                    "record": entry.record.to_dict(),
                }
                expected = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
                if expected != entry.entry_sha256:
                    raise JournalCorruption(f"line {line_number}: entry hash mismatch")
                if entry.previous_sha256 != previous:
                    raise JournalCorruption(f"line {line_number}: hash chain mismatch")
                if entry.record.operation_id in operation_ids:
                    raise JournalCorruption(f"line {line_number}: duplicate operation_id")
                operation_ids.add(entry.record.operation_id)
                previous = entry.entry_sha256
                yield entry

    def verify(self) -> dict[str, object]:
        entries = list(self.iter_entries())
        return {
            "valid": True,
            "entries": len(entries),
            "head_sha256": entries[-1].entry_sha256 if entries else None,
        }

    @staticmethod
    def _decode(value: Mapping[str, Any]) -> JournalEntry:
        record = StatusRecord.from_dict(value["record"])
        return JournalEntry(
            journal_id=value["journal_id"], previous_sha256=value.get("previous_sha256"),
            record=record, entry_sha256=value["entry_sha256"],
        )

