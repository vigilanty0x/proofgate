"""Small API surface joining normalization and append-only recording."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .contract import CheckResult, StatusPolicy, StatusRecord
from .engine import normalize
from .journal import AppendOnlyJournal, JournalEntry


class StatusTruthService:
    def __init__(self, journal: AppendOnlyJournal) -> None:
        self.journal = journal

    def assess(
        self, *, subject: str, operation_id: str, checks: Iterable[CheckResult],
        policy: StatusPolicy | None = None, recorded_at: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[StatusRecord, JournalEntry]:
        record = normalize(
            subject=subject, operation_id=operation_id, checks=checks, policy=policy,
            recorded_at=recorded_at, metadata=metadata,
        )
        return record, self.journal.append(record)

