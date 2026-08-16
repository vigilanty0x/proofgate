"""Self-contained health probes and a mandatory counter-proof."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from .contract import CheckOutcome, CheckResult, Provenance, TruthState
from .journal import AppendOnlyJournal, IdempotencyConflict
from .service import StatusTruthService


FIXED_TIME = "2026-01-01T00:00:00Z"


def _provenance(value: object) -> Provenance:
    return Provenance.from_evidence(
        source="synthetic-probe", observed_at=FIXED_TIME, collector="status-truth-probe", evidence=value,
    )


def liveness() -> dict[str, object]:
    return {"probe": "liveness", "ok": True, "contract": "1.0"}


def readiness(journal_path: str | Path) -> dict[str, object]:
    path = Path(journal_path)
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        writable = parent.is_dir() and os_access_write(parent)
        verification = AppendOnlyJournal(path).verify()
    except OSError as exc:
        return {"probe": "readiness", "ok": False, "reason": type(exc).__name__}
    return {"probe": "readiness", "ok": writable and bool(verification["valid"]), **verification}


def os_access_write(path: Path) -> bool:
    import os
    return os.access(path, os.W_OK)


def functional_counter_proof() -> dict[str, object]:
    with TemporaryDirectory(prefix="status-truth-probe-") as directory:
        service = StatusTruthService(AppendOnlyJournal(Path(directory) / "journal.jsonl"))
        control, first = service.assess(
            subject="synthetic-service", operation_id="control-001",
            checks=[CheckResult("heartbeat", CheckOutcome.PASS, True, "Synthetic heartbeat passed.", _provenance(True))],
            recorded_at=FIXED_TIME,
        )
        replay, second = service.assess(
            subject="synthetic-service", operation_id="control-001",
            checks=[CheckResult("heartbeat", CheckOutcome.PASS, True, "Synthetic heartbeat passed.", _provenance(True))],
            recorded_at="2026-01-01T00:00:01Z",
        )
        failure, _ = service.assess(
            subject="synthetic-service", operation_id="failure-001",
            checks=[CheckResult("heartbeat", CheckOutcome.FAIL, True, "Synthetic outage.", _provenance(False))],
            recorded_at=FIXED_TIME,
        )
        conflict_detected = False
        try:
            service.assess(
                subject="synthetic-service", operation_id="control-001",
                checks=[CheckResult("heartbeat", CheckOutcome.FAIL, True, "Changed result.", _provenance(False))],
                recorded_at=FIXED_TIME,
            )
        except IdempotencyConflict:
            conflict_detected = True
        verified = service.journal.verify()
        ok = all((
            control.state is TruthState.HEALTHY,
            replay.state is TruthState.HEALTHY,
            failure.state is TruthState.FAILED,
            not failure.success,
            first.journal_id == second.journal_id,
            conflict_detected,
            verified["entries"] == 2,
        ))
        return {
            "probe": "functional", "ok": ok,
            "control_state": control.state.value,
            "counter_proof_state": failure.state.value,
            "failure_success": failure.success,
            "idempotent_replay": first.journal_id == second.journal_id,
            "conflict_detected": conflict_detected,
            "journal_verified": verified["valid"],
        }

