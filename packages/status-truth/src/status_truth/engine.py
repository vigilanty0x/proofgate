"""Deterministic fail-closed normalization engine."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .contract import (
    CheckOutcome, CheckResult, ContractError, Diagnostic, DiagnosticKind,
    StatusPolicy, StatusRecord, TruthState, utc_now,
)


def normalize(
    *, subject: str, operation_id: str, checks: Iterable[CheckResult],
    policy: StatusPolicy | None = None, recorded_at: str | None = None,
    metadata: Mapping[str, str] | None = None,
) -> StatusRecord:
    """Normalize checks into a deterministic, fail-closed status record."""
    check_tuple = tuple(checks)
    if not check_tuple:
        raise ContractError("at least one check is required")
    selected_policy = policy or StatusPolicy()
    required_by_policy = set(selected_policy.required_names)
    normalized_checks = tuple(
        CheckResult(c.name, c.outcome, c.required or c.name in required_by_policy, c.detail, c.provenance)
        for c in check_tuple
    )
    required = tuple(c for c in normalized_checks if c.required)
    optional = tuple(c for c in normalized_checks if not c.required)

    if any(c.outcome is CheckOutcome.FAIL for c in required):
        state = TruthState.FAILED
    elif any(c.outcome in {CheckOutcome.TIMEOUT, CheckOutcome.CIRCUIT_OPEN} for c in required):
        state = TruthState.BLOCKED
    elif any(c.outcome is CheckOutcome.UNKNOWN for c in required):
        state = TruthState.UNKNOWN
    elif not required:
        state = TruthState.UNKNOWN
    elif any(c.outcome is not CheckOutcome.PASS for c in optional):
        state = TruthState.DEGRADED
    else:
        state = TruthState.HEALTHY

    diagnostics = tuple(_diagnostic(check) for check in normalized_checks)
    if not required:
        diagnostics += (Diagnostic(
            DiagnosticKind.BLOCKAGE, "NO_REQUIRED_CHECKS",
            "No required check can prove a healthy state.", None,
        ),)
    return StatusRecord(
        subject=subject, operation_id=operation_id, state=state,
        recorded_at=recorded_at or utc_now(), policy=selected_policy,
        checks=normalized_checks, diagnostics=diagnostics, metadata=metadata or {},
    )


def _diagnostic(check: CheckResult) -> Diagnostic:
    if check.outcome is CheckOutcome.PASS:
        return Diagnostic(DiagnosticKind.PROOF, "CHECK_PASSED", check.detail or "Check passed with evidence.", check.name)
    if check.outcome is CheckOutcome.FAIL:
        return Diagnostic(DiagnosticKind.PROOF, "CHECK_FAILED", check.detail or "Check failed with evidence.", check.name)
    if check.outcome is CheckOutcome.UNKNOWN:
        return Diagnostic(DiagnosticKind.INFERENCE, "CHECK_UNKNOWN", check.detail or "No conclusive result is available.", check.name)
    if check.outcome is CheckOutcome.TIMEOUT:
        return Diagnostic(DiagnosticKind.BLOCKAGE, "CHECK_TIMEOUT", check.detail or "Check exceeded its time budget.", check.name)
    return Diagnostic(DiagnosticKind.BLOCKAGE, "CIRCUIT_OPEN", check.detail or "Check was blocked by an open circuit.", check.name)

