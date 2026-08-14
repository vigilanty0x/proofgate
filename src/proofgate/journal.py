"""Tamper-evident, append-only JSON Lines event journal."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable
import uuid

MAX_EVENT_BYTES = 256 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
ZERO_HASH = "0" * 64


class JournalError(RuntimeError):
    """The event journal is invalid, conflicting, or unavailable."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JournalError(f"event data is not JSON serializable: {exc}") from exc


def _event_hash(event_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(event_without_hash)).hexdigest()


@dataclass(frozen=True)
class Replay:
    events: tuple[dict[str, Any], ...]
    last_hash: str
    failures: int
    states: tuple[str, ...]


class EventJournal:
    """A small durable journal with hash chaining and idempotency protection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _read_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            if self.path.stat().st_size > MAX_JOURNAL_BYTES:
                raise JournalError(f"journal exceeds {MAX_JOURNAL_BYTES} bytes")
            return self.path.read_text(encoding="utf-8").splitlines()
        except JournalError:
            raise
        except (OSError, UnicodeError) as exc:
            raise JournalError(f"cannot read journal: {exc}") from exc

    def replay(self) -> Replay:
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        previous = ZERO_HASH
        failures = 0
        states: list[str] = []

        for index, line in enumerate(self._read_lines(), start=1):
            if not line.strip():
                raise JournalError(f"blank journal line at {index}")
            if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                raise JournalError(f"event at line {index} exceeds {MAX_EVENT_BYTES} bytes")
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise JournalError(f"invalid JSON at journal line {index}: {exc}") from exc
            if not isinstance(event, dict):
                raise JournalError(f"journal line {index} is not an object")
            required = {
                "event_id",
                "idempotency_key",
                "sequence",
                "kind",
                "timestamp",
                "data",
                "previous_hash",
                "hash",
            }
            if set(event) != required:
                raise JournalError(f"journal line {index} has an invalid field set")
            if event["sequence"] != index:
                raise JournalError(f"journal sequence mismatch at line {index}")
            if event["previous_hash"] != previous:
                raise JournalError(f"journal hash chain mismatch at line {index}")
            event_id = event["event_id"]
            key = event["idempotency_key"]
            if not isinstance(event_id, str) or event_id in seen_ids:
                raise JournalError(f"duplicate or invalid event_id at line {index}")
            if not isinstance(key, str) or not key or key in seen_keys:
                raise JournalError(f"duplicate or invalid idempotency_key at line {index}")
            unsigned = dict(event)
            claimed = unsigned.pop("hash")
            actual = _event_hash(unsigned)
            if claimed != actual:
                raise JournalError(f"journal event hash mismatch at line {index}")
            seen_ids.add(event_id)
            seen_keys.add(key)
            previous = claimed
            events.append(event)
            data = event.get("data")
            if event.get("kind") == "verdict" and isinstance(data, dict):
                state = data.get("state")
                if isinstance(state, str):
                    states.append(state)
                if state in {"FAILED", "REJECTED"}:
                    failures += 1

        return Replay(tuple(events), previous, failures, tuple(states))

    def append(self, *, idempotency_key: str, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
            raise JournalError("idempotency_key must be 1 to 256 characters")
        if not isinstance(kind, str) or not kind or len(kind) > 64:
            raise JournalError("kind must be 1 to 64 characters")
        replay = self.replay()
        for event in replay.events:
            if event["idempotency_key"] == idempotency_key:
                if event["kind"] == kind and event["data"] == data:
                    return event
                raise JournalError(f"idempotency conflict for key: {idempotency_key}")

        unsigned: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "idempotency_key": idempotency_key,
            "sequence": len(replay.events) + 1,
            "kind": kind,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "data": data,
            "previous_hash": replay.last_hash,
        }
        event = {**unsigned, "hash": _event_hash(unsigned)}
        encoded = _canonical(event) + b"\n"
        if len(encoded) > MAX_EVENT_BYTES:
            raise JournalError(f"event exceeds {MAX_EVENT_BYTES} bytes")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise JournalError(f"cannot append journal: {exc}") from exc
        return event

    def iter_events(self) -> Iterable[dict[str, Any]]:
        return iter(self.replay().events)

