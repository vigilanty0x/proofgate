"""Tamper-evident, append-only JSON Lines event journal."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator
import uuid

from .jsonutil import StrictJSONError, strict_dumps, strict_loads

MAX_EVENT_BYTES = 256 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
ZERO_HASH = "0" * 64


class JournalError(RuntimeError):
    """The event journal is invalid, conflicting, or unavailable."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise JournalError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    try:
        return strict_dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, StrictJSONError) as exc:
        raise JournalError(f"event data is not strict JSON: {exc}") from exc


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

    @contextmanager
    def _lock(self, *, exclusive: bool) -> Iterator[BinaryIO | None]:
        """Lock and yield the same handle used for journal I/O.

        Windows mandatory byte-range locks can reject a second handle opened by
        the same process.  Reading and appending through the already-locked
        handle therefore preserves the atomic section on every supported OS.
        """

        if exclusive:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a+b"
        else:
            if not self.path.exists():
                yield None
                return
            mode = "rb"
        try:
            handle = self.path.open(mode)
        except FileNotFoundError:
            yield None
            return
        except OSError as exc:
            raise JournalError(f"cannot open journal lock: {exc}") from exc
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                operation = msvcrt.LK_LOCK if exclusive else msvcrt.LK_RLCK
                msvcrt.locking(handle.fileno(), operation, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield handle
        except OSError as exc:
            raise JournalError(f"journal lock failed: {exc}") from exc
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()

    def _read_lines(self, handle: BinaryIO | None = None) -> list[str]:
        if handle is None and not self.path.exists():
            return []
        try:
            if handle is None:
                size = self.path.stat().st_size
                if size > MAX_JOURNAL_BYTES:
                    raise JournalError(f"journal exceeds {MAX_JOURNAL_BYTES} bytes")
                raw = self.path.read_bytes()
            else:
                size = os.fstat(handle.fileno()).st_size
                if size > MAX_JOURNAL_BYTES:
                    raise JournalError(f"journal exceeds {MAX_JOURNAL_BYTES} bytes")
                handle.seek(0)
                raw = handle.read()
            return raw.decode("utf-8").splitlines()
        except JournalError:
            raise
        except (OSError, UnicodeError) as exc:
            raise JournalError(f"cannot read journal: {exc}") from exc

    def _replay_unlocked(self, handle: BinaryIO | None = None) -> Replay:
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        previous = ZERO_HASH
        failures = 0
        states: list[str] = []

        for index, line in enumerate(self._read_lines(handle), start=1):
            if not line.strip():
                raise JournalError(f"blank journal line at {index}")
            if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                raise JournalError(f"event at line {index} exceeds {MAX_EVENT_BYTES} bytes")
            try:
                event = strict_loads(line, object_pairs_hook=_unique_object)
            except JournalError:
                raise
            except (json.JSONDecodeError, StrictJSONError) as exc:
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
            if type(event["sequence"]) is not int or event["sequence"] != index:
                raise JournalError(f"journal sequence mismatch at line {index}")
            if event["previous_hash"] != previous:
                raise JournalError(f"journal hash chain mismatch at line {index}")
            event_id = event["event_id"]
            key = event["idempotency_key"]
            if not isinstance(event_id, str) or not event_id or len(event_id) > 128 or event_id in seen_ids:
                raise JournalError(f"duplicate or invalid event_id at line {index}")
            if not isinstance(key, str) or not key or len(key) > 256 or key in seen_keys:
                raise JournalError(f"duplicate or invalid idempotency_key at line {index}")
            if not isinstance(event["kind"], str) or not event["kind"] or len(event["kind"]) > 64:
                raise JournalError(f"invalid event kind at line {index}")
            if not isinstance(event["timestamp"], str) or not event["timestamp"].endswith("Z"):
                raise JournalError(f"invalid event timestamp at line {index}")
            if not isinstance(event["data"], dict):
                raise JournalError(f"invalid event data at line {index}")
            for field in ("previous_hash", "hash"):
                digest = event[field]
                if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise JournalError(f"invalid {field} at journal line {index}")
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

    def replay(self) -> Replay:
        with self._lock(exclusive=False) as handle:
            return self._replay_unlocked(handle)

    def find(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return one verified event by idempotency key without creating a journal."""

        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
            raise JournalError("idempotency_key must be 1 to 256 characters")
        replay = self.replay()
        return next(
            (event for event in replay.events if event["idempotency_key"] == idempotency_key),
            None,
        )

    @staticmethod
    def _outstanding_attempts(replay: Replay) -> set[str]:
        """Return gate-operation prefixes whose terminal event is still owed."""

        claims = {
            event["idempotency_key"][: -len(":claim")]
            for event in replay.events
            if event["kind"] == "attempt_claim" and event["idempotency_key"].endswith(":claim")
        }
        completed = {
            event["idempotency_key"][: -len(":verdict")]
            for event in replay.events
            if event["kind"] == "verdict" and event["idempotency_key"].endswith(":verdict")
        }
        return claims - completed

    def append_once(
        self,
        *,
        idempotency_key: str,
        kind: str,
        data: dict[str, Any],
        reserve_bytes: int = 0,
    ) -> tuple[dict[str, Any], bool]:
        """Atomically append once, returning ``(event, created)`` for coordinators."""

        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
            raise JournalError("idempotency_key must be 1 to 256 characters")
        if not isinstance(kind, str) or not kind or len(kind) > 64:
            raise JournalError("kind must be 1 to 64 characters")
        if not isinstance(data, dict):
            raise JournalError("data must be an object")
        if type(reserve_bytes) is not int or not 0 <= reserve_bytes <= MAX_EVENT_BYTES:
            raise JournalError(f"reserve_bytes must be an integer from 0 to {MAX_EVENT_BYTES}")
        if kind == "attempt_claim" and reserve_bytes != MAX_EVENT_BYTES:
            raise JournalError(f"attempt_claim must reserve exactly {MAX_EVENT_BYTES} bytes")
        if kind == "attempt_claim" and not idempotency_key.endswith(":claim"):
            raise JournalError("attempt_claim idempotency_key must end with :claim")
        if reserve_bytes and kind != "attempt_claim":
            raise JournalError("reserve_bytes is supported only for attempt_claim events")
        canonical_data = _canonical(data)
        with self._lock(exclusive=True) as handle:
            if handle is None:  # exclusive locking always creates the file
                raise JournalError("cannot acquire writable journal handle")
            replay = self._replay_unlocked(handle)
            for event in replay.events:
                if event["idempotency_key"] == idempotency_key:
                    if event["kind"] == kind and _canonical(event["data"]) == canonical_data:
                        return event, False
                    raise JournalError(f"idempotency conflict for key: {idempotency_key}")
            if kind == "attempt_claim":
                prefix = idempotency_key[: -len(":claim")]
                if any(event["idempotency_key"] == f"{prefix}:verdict" for event in replay.events):
                    raise JournalError("attempt claim cannot follow its terminal verdict")
            if kind == "verdict" and idempotency_key.endswith(":verdict"):
                prefix = idempotency_key[: -len(":verdict")]
                if not any(
                    event["kind"] == "attempt_claim"
                    and event["idempotency_key"] == f"{prefix}:claim"
                    for event in replay.events
                ):
                    raise JournalError("terminal verdict has no matching attempt claim")

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
            current_size = os.fstat(handle.fileno()).st_size
            outstanding = self._outstanding_attempts(replay)
            reserved_terminal_bytes = len(outstanding) * MAX_EVENT_BYTES
            if kind == "verdict" and idempotency_key.endswith(":verdict"):
                prefix = idempotency_key[: -len(":verdict")]
                if prefix in outstanding:
                    reserved_terminal_bytes -= MAX_EVENT_BYTES
            required_capacity = current_size + len(encoded) + reserved_terminal_bytes + reserve_bytes
            if required_capacity > MAX_JOURNAL_BYTES:
                if reserved_terminal_bytes or reserve_bytes:
                    raise JournalError(
                        f"journal exceeds {MAX_JOURNAL_BYTES} bytes including reserved terminal capacity"
                    )
                raise JournalError(f"journal exceeds {MAX_JOURNAL_BYTES} bytes")
            try:
                handle.seek(0, os.SEEK_END)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise JournalError(f"cannot append journal: {exc}") from exc
            return event, True

    def append(self, *, idempotency_key: str, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        event, _created = self.append_once(idempotency_key=idempotency_key, kind=kind, data=data)
        return event

    def iter_events(self) -> Iterable[dict[str, Any]]:
        return iter(self.replay().events)
