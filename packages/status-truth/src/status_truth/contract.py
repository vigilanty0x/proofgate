"""Machine-readable public contract and bounded input validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "1.0"
MAX_TEXT = 4_096
MAX_CHECKS = 100
MAX_METADATA_ITEMS = 50


class ContractError(ValueError):
    """Raised when public input does not satisfy the bounded contract."""


class TruthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class CheckOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    TIMEOUT = "timeout"
    CIRCUIT_OPEN = "circuit_open"
    UNKNOWN = "unknown"


class DiagnosticKind(StrEnum):
    PROOF = "proof"
    INFERENCE = "inference"
    BLOCKAGE = "blockage"


def _text(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{name} must be a string")
    value = value.strip()
    if not value and not allow_empty:
        raise ContractError(f"{name} must not be empty")
    if len(value) > MAX_TEXT:
        raise ContractError(f"{name} exceeds {MAX_TEXT} characters")
    return value


def _timestamp(value: str) -> str:
    value = _text(value, "observed_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("observed_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ContractError("observed_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Provenance:
    source: str
    observed_at: str
    collector: str
    evidence_sha256: str
    reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _text(self.source, "source"))
        object.__setattr__(self, "collector", _text(self.collector, "collector"))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at))
        digest = _text(self.evidence_sha256, "evidence_sha256").lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ContractError("evidence_sha256 must be 64 lowercase hex characters")
        object.__setattr__(self, "evidence_sha256", digest)
        if self.reference is not None:
            object.__setattr__(self, "reference", _text(self.reference, "reference"))

    @classmethod
    def from_evidence(
        cls, *, source: str, observed_at: str, collector: str, evidence: object,
        reference: str | None = None,
    ) -> "Provenance":
        return cls(source, observed_at, collector, sha256_json(evidence), reference)

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "observed_at": self.observed_at,
            "collector": self.collector,
            "evidence_sha256": self.evidence_sha256,
            "reference": self.reference,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Provenance":
        return cls(
            source=value.get("source"), observed_at=value.get("observed_at"),
            collector=value.get("collector"), evidence_sha256=value.get("evidence_sha256"),
            reference=value.get("reference"),
        )


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    outcome: CheckOutcome
    required: bool = True
    detail: str = ""
    provenance: Provenance | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "check.name"))
        if not isinstance(self.outcome, CheckOutcome):
            try:
                object.__setattr__(self, "outcome", CheckOutcome(self.outcome))
            except (ValueError, TypeError) as exc:
                raise ContractError("invalid check outcome") from exc
        if not isinstance(self.required, bool):
            raise ContractError("check.required must be boolean")
        object.__setattr__(self, "detail", _text(self.detail, "check.detail", allow_empty=True))
        if self.outcome in {CheckOutcome.PASS, CheckOutcome.FAIL} and self.provenance is None:
            raise ContractError("pass/fail checks require provenance")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "outcome": self.outcome.value,
            "required": self.required,
            "detail": self.detail,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CheckResult":
        provenance = value.get("provenance")
        return cls(
            name=value.get("name"), outcome=value.get("outcome"),
            required=value.get("required", True), detail=value.get("detail", ""),
            provenance=Provenance.from_dict(provenance) if isinstance(provenance, Mapping) else None,
        )


@dataclass(frozen=True, slots=True)
class StatusPolicy:
    name: str = "fail-closed-v1"
    required_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "policy.name"))
        normalized = tuple(_text(item, "policy.required_names") for item in self.required_names)
        if len(set(normalized)) != len(normalized):
            raise ContractError("policy.required_names must be unique")
        if len(normalized) > MAX_CHECKS:
            raise ContractError("too many required check names")
        object.__setattr__(self, "required_names", normalized)

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "required_names": list(self.required_names)}


@dataclass(frozen=True, slots=True)
class Diagnostic:
    kind: DiagnosticKind
    code: str
    summary: str
    check: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DiagnosticKind):
            object.__setattr__(self, "kind", DiagnosticKind(self.kind))
        object.__setattr__(self, "code", _text(self.code, "diagnostic.code"))
        object.__setattr__(self, "summary", _text(self.summary, "diagnostic.summary"))
        if self.check is not None:
            object.__setattr__(self, "check", _text(self.check, "diagnostic.check"))

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "code": self.code, "summary": self.summary, "check": self.check}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Diagnostic":
        return cls(value.get("kind"), value.get("code"), value.get("summary"), value.get("check"))


@dataclass(frozen=True, slots=True)
class StatusRecord:
    subject: str
    operation_id: str
    state: TruthState
    recorded_at: str
    policy: StatusPolicy
    checks: tuple[CheckResult, ...]
    diagnostics: tuple[Diagnostic, ...]
    metadata: Mapping[str, str] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", _text(self.subject, "subject"))
        object.__setattr__(self, "operation_id", _text(self.operation_id, "operation_id"))
        object.__setattr__(self, "recorded_at", _timestamp(self.recorded_at))
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError(f"unsupported schema_version: {self.schema_version}")
        if not isinstance(self.state, TruthState):
            object.__setattr__(self, "state", TruthState(self.state))
        if not self.checks or len(self.checks) > MAX_CHECKS:
            raise ContractError(f"checks must contain 1..{MAX_CHECKS} items")
        names = [check.name for check in self.checks]
        if len(set(names)) != len(names):
            raise ContractError("check names must be unique")
        missing = set(self.policy.required_names) - set(names)
        if missing:
            raise ContractError(f"missing policy checks: {sorted(missing)}")
        if len(self.metadata) > MAX_METADATA_ITEMS:
            raise ContractError("too many metadata items")
        clean_metadata = {
            _text(key, "metadata key"): _text(value, "metadata value", allow_empty=True)
            for key, value in self.metadata.items()
        }
        object.__setattr__(self, "metadata", clean_metadata)
        if self.state is TruthState.HEALTHY:
            unsafe = [c.name for c in self.checks if c.required and c.outcome is not CheckOutcome.PASS]
            if unsafe:
                raise ContractError("healthy cannot contain non-passing required checks")

    @property
    def success(self) -> bool:
        return self.state is TruthState.HEALTHY

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "subject": self.subject,
            "operation_id": self.operation_id,
            "state": self.state.value,
            "success": self.success,
            "recorded_at": self.recorded_at,
            "policy": self.policy.to_dict(),
            "checks": [check.to_dict() for check in self.checks],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "metadata": dict(sorted(self.metadata.items())),
        }

    def logical_dict(self) -> dict[str, object]:
        value = self.to_dict()
        value.pop("recorded_at")
        return value

    @property
    def logical_sha256(self) -> str:
        return sha256_json(self.logical_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StatusRecord":
        policy = value.get("policy")
        checks = value.get("checks")
        diagnostics = value.get("diagnostics", [])
        if not isinstance(policy, Mapping) or not isinstance(checks, Sequence):
            raise ContractError("record policy/checks malformed")
        return cls(
            subject=value.get("subject"), operation_id=value.get("operation_id"),
            state=value.get("state"), recorded_at=value.get("recorded_at"),
            policy=StatusPolicy(policy.get("name", "fail-closed-v1"), tuple(policy.get("required_names", ()))),
            checks=tuple(CheckResult.from_dict(item) for item in checks if isinstance(item, Mapping)),
            diagnostics=tuple(Diagnostic.from_dict(item) for item in diagnostics if isinstance(item, Mapping)),
            metadata=value.get("metadata", {}), schema_version=value.get("schema_version", ""),
        )

