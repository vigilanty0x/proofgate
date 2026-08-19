from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class Category(StrEnum):
    SECRET = "secret"
    ENV_CONFIG = "env_config"
    PERMISSION = "permission"
    SSRF = "ssrf"
    SECURITY_HEADER = "security_header"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingState(StrEnum):
    MEASURED = "measured"
    NOT_MEASURED = "not_measured"
    NOT_APPLICABLE = "not_applicable"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    category: Category
    severity: Severity
    evidence: str
    message: str = ""
    active: bool = True
    state: FindingState = FindingState.MEASURED


@dataclass(frozen=True, slots=True)
class Evaluation:
    verdict: Verdict
    reasons: tuple[str, ...]
    finding_count: int
    active_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "finding_count": self.finding_count,
            "active_count": self.active_count,
        }


def evaluate(findings: Iterable[Finding], *, measurement_complete: bool) -> Evaluation:
    """Evaluate normalized defensive findings without turning missing evidence green."""

    items = tuple(findings)
    reasons: list[str] = []

    if not measurement_complete:
        reasons.append("measurement_incomplete")

    seen: set[str] = set()
    for item in items:
        if not item.finding_id.strip():
            reasons.append("missing_finding_id")
        elif item.finding_id in seen:
            reasons.append(f"duplicate_finding_id:{item.finding_id}")
        seen.add(item.finding_id)
        if not item.evidence.strip():
            reasons.append(f"missing_evidence:{item.finding_id or '<unknown>'}")
        if item.state is FindingState.NOT_MEASURED:
            reasons.append(f"not_measured:{item.finding_id or '<unknown>'}")

    if reasons:
        return Evaluation(
            verdict=Verdict.BLOCKED,
            reasons=tuple(sorted(set(reasons))),
            finding_count=len(items),
            active_count=sum(item.active for item in items),
        )

    active = tuple(
        item for item in items
        if item.active and item.state is FindingState.MEASURED
    )
    if active:
        ordered = sorted(active, key=lambda item: (item.severity.value, item.finding_id))
        return Evaluation(
            verdict=Verdict.FAIL,
            reasons=tuple(f"active:{item.category.value}:{item.finding_id}" for item in ordered),
            finding_count=len(items),
            active_count=len(active),
        )

    return Evaluation(
        verdict=Verdict.PASS,
        reasons=("measurement_complete_no_active_findings",),
        finding_count=len(items),
        active_count=0,
    )
