from __future__ import annotations

from dataclasses import dataclass
import json
import re
from collections.abc import Mapping, Sequence

from .core import Category, Evaluation, Finding, FindingState, Severity, evaluate
from .redaction import redact


class AdapterContractError(ValueError):
    """Raised when a source result does not match its audited output contract."""


@dataclass(frozen=True, slots=True)
class AdapterResult:
    source: str
    source_status: str
    findings: tuple[Finding, ...]
    measurement_complete: bool

    def evaluation(self) -> Evaluation:
        return evaluate(self.findings, measurement_complete=self.measurement_complete)

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "source_status": self.source_status,
            "measurement_complete": self.measurement_complete,
            "findings": [
                {
                    "finding_id": item.finding_id,
                    "category": item.category.value,
                    "severity": item.severity.value,
                    "evidence": item.evidence,
                    "message": item.message,
                    "active": item.active,
                    "state": item.state.value,
                }
                for item in self.findings
            ],
            "evaluation": self.evaluation().as_dict(),
        }


def _bounded_text(value: object, *, label: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit:
        raise AdapterContractError(f"{label} must be a bounded nonempty string")
    return value


def _string_list(value: object, *, label: str, limit: int = 10_000) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise AdapterContractError(f"{label} must be a bounded list")
    return [_bounded_text(item, label=label) for item in value]


def _evidence(**fields: object) -> str:
    text = json.dumps(redact(fields), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text.encode("utf-8")) > 16_384:
        raise AdapterContractError("normalized evidence exceeds limit")
    return text


def _slug(value: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower()
    return token[:96] or "item"


def normalize_env_example(result: Mapping[str, object]) -> AdapterResult:
    if not isinstance(result, Mapping) or set(result) != {"status", "missing", "extra", "leaked"}:
        raise AdapterContractError("env-example-guard result has unexpected shape")
    status = result["status"]
    if status not in {"verified", "blocked", "inconclusive"}:
        raise AdapterContractError("env-example-guard status is invalid")
    missing = _string_list(result["missing"], label="missing")
    extra = _string_list(result["extra"], label="extra")
    leaked = _string_list(result["leaked"], label="leaked")

    if status == "verified":
        if missing or extra or leaked:
            raise AdapterContractError("verified env result contains findings")
        return AdapterResult("env-example-guard", status, (), True)
    if status == "inconclusive":
        if missing or extra or leaked:
            raise AdapterContractError("inconclusive env result contains findings")
        return AdapterResult("env-example-guard", status, (), False)

    findings: list[Finding] = []
    for index, key in enumerate(leaked):
        findings.append(Finding(
            finding_id=f"env:leaked:{index}:{_slug(key)}",
            category=Category.SECRET,
            severity=Severity.CRITICAL,
            evidence=_evidence(source="env-example-guard", key=key, issue="sensitive_value"),
            message="Example configuration contains a non-placeholder sensitive value.",
        ))
    for index, key in enumerate(missing):
        findings.append(Finding(
            finding_id=f"env:missing:{index}:{_slug(key)}",
            category=Category.ENV_CONFIG,
            severity=Severity.MEDIUM,
            evidence=_evidence(source="env-example-guard", key=key, issue="missing_example_key"),
            message="Runtime environment key is missing from the example contract.",
        ))
    for index, key in enumerate(extra):
        findings.append(Finding(
            finding_id=f"env:extra:{index}:{_slug(key)}",
            category=Category.ENV_CONFIG,
            severity=Severity.LOW,
            evidence=_evidence(source="env-example-guard", key=key, issue="extra_example_key"),
            message="Example configuration contains a key not observed at runtime.",
        ))
    return AdapterResult("env-example-guard", status, tuple(findings), bool(findings))


_SECRET_CRITICAL = {
    "aws_access_key", "bearer_token", "connection_credential", "github_fine_grained",
    "jwt", "pem_private_key", "sensitive_assignment", "slack_token", "stripe_live_key",
}


def normalize_secrets(result: Mapping[str, object]) -> AdapterResult:
    if not isinstance(result, Mapping) or set(result) != {"status", "findings", "findings_truncated"}:
        raise AdapterContractError("secrets-hygiene result has unexpected shape")
    status = result["status"]
    if status not in {"clean", "blocked"} or not isinstance(result["findings_truncated"], bool):
        raise AdapterContractError("secrets-hygiene status is invalid")
    raw_findings = result["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > 1_000:
        raise AdapterContractError("secrets-hygiene findings must be bounded")

    findings: list[Finding] = []
    incomplete = bool(result["findings_truncated"])
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, Mapping) or set(raw) != {"path", "kind", "line"}:
            raise AdapterContractError("secrets-hygiene finding has unexpected shape")
        path = _bounded_text(raw["path"], label="path")
        kind = _bounded_text(raw["kind"], label="kind", limit=128)
        line = raw["line"]
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            raise AdapterContractError("secrets-hygiene line is invalid")
        if kind == "size_blocked":
            incomplete = True
            findings.append(Finding(
                finding_id=f"secret:size:{index}:{_slug(path)}",
                category=Category.SECRET,
                severity=Severity.HIGH,
                evidence=_evidence(source="secrets-hygiene", path=path, kind=kind, line=line),
                message="Secret scan could not measure an oversized file.",
                active=False,
                state=FindingState.NOT_MEASURED,
            ))
            continue
        findings.append(Finding(
            finding_id=f"secret:{_slug(kind)}:{index}:{_slug(path)}",
            category=Category.SECRET,
            severity=Severity.CRITICAL if kind in _SECRET_CRITICAL else Severity.HIGH,
            evidence=_evidence(source="secrets-hygiene", path=path, kind=kind, line=line),
            message="Secret hygiene source reported a redacted finding.",
        ))

    if status == "clean" and findings:
        raise AdapterContractError("clean secret result contains findings")
    if status == "blocked" and not findings and not incomplete:
        raise AdapterContractError("blocked secret result contains no evidence")
    return AdapterResult("secrets-hygiene", status, tuple(findings), not incomplete)


_HEADER_HIGH = {
    ("content-security-policy", "missing"),
    ("content-security-policy", "script_policy"),
    ("content-security-policy", "unsafe_script_source"),
    ("strict-transport-security", "missing"),
    ("strict-transport-security", "max_age"),
}


def normalize_security_headers(result: Mapping[str, object]) -> AdapterResult:
    if not isinstance(result, Mapping) or set(result) != {"status", "issues"}:
        raise AdapterContractError("security-headers-lab result has unexpected shape")
    status = result["status"]
    if status not in {"hardened", "blocked"}:
        raise AdapterContractError("security-headers-lab status is invalid")
    raw_issues = result["issues"]
    if not isinstance(raw_issues, list) or len(raw_issues) > 200:
        raise AdapterContractError("security header issues must be bounded")
    findings: list[Finding] = []
    for index, raw in enumerate(raw_issues):
        if not isinstance(raw, Mapping) or set(raw) != {"header", "issue"}:
            raise AdapterContractError("security header issue has unexpected shape")
        header = _bounded_text(raw["header"], label="header", limit=256).casefold()
        issue = _bounded_text(raw["issue"], label="issue", limit=128)
        findings.append(Finding(
            finding_id=f"header:{index}:{_slug(header)}:{_slug(issue)}",
            category=Category.SECURITY_HEADER,
            severity=Severity.HIGH if (header, issue) in _HEADER_HIGH else Severity.MEDIUM,
            evidence=_evidence(source="security-headers-lab", header=header, issue=issue),
            message="Security header policy is not satisfied.",
        ))
    if status == "hardened" and findings:
        raise AdapterContractError("hardened header result contains issues")
    if status == "blocked" and not findings:
        raise AdapterContractError("blocked header result contains no issues")
    return AdapterResult("security-headers-lab", status, tuple(findings), True)


def _permission_expectations(value: object) -> dict[tuple[str, str, str], str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)) or len(value) > 100_000:
        raise AdapterContractError("permission expectations must be a bounded sequence")
    expected: dict[tuple[str, str, str], str] = {}
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {"subject", "action", "resource", "decision"}:
            raise AdapterContractError("permission expectation has unexpected shape")
        subject = _bounded_text(raw["subject"], label="subject", limit=256)
        action = _bounded_text(raw["action"], label="action", limit=256)
        resource = _bounded_text(raw["resource"], label="resource", limit=256)
        decision = raw["decision"]
        if decision not in {"allowed", "denied"}:
            raise AdapterContractError("permission expectation decision is invalid")
        key = (subject, action, resource)
        if key in expected:
            raise AdapterContractError("duplicate permission expectation")
        expected[key] = decision
    return expected


def normalize_permission_matrix(
    result: Mapping[str, object], *, expected_decisions: Sequence[Mapping[str, object]] | None,
) -> AdapterResult:
    if not isinstance(result, Mapping) or set(result) != {"matrix"}:
        raise AdapterContractError("permission-matrix result has unexpected shape")
    raw_matrix = result["matrix"]
    if not isinstance(raw_matrix, list) or len(raw_matrix) > 100_000:
        raise AdapterContractError("permission matrix must be bounded")
    if expected_decisions is None:
        return AdapterResult("permission-matrix", "expectation_missing", (), False)
    expected = _permission_expectations(expected_decisions)
    seen: set[tuple[str, str, str]] = set()
    findings: list[Finding] = []
    for index, raw in enumerate(raw_matrix):
        if not isinstance(raw, Mapping) or set(raw) != {"subject", "action", "resource", "decision", "reason"}:
            raise AdapterContractError("permission matrix cell has unexpected shape")
        subject = _bounded_text(raw["subject"], label="subject", limit=256)
        action = _bounded_text(raw["action"], label="action", limit=256)
        resource = _bounded_text(raw["resource"], label="resource", limit=256)
        decision = raw["decision"]
        reason = _bounded_text(raw["reason"], label="reason", limit=128)
        if decision not in {"allowed", "denied"}:
            raise AdapterContractError("permission matrix decision is invalid")
        key = (subject, action, resource)
        if key in seen:
            raise AdapterContractError("duplicate permission matrix cell")
        seen.add(key)
        wanted = expected.get(key)
        if wanted is not None and decision != wanted:
            findings.append(Finding(
                finding_id=f"permission:{index}:{_slug(subject)}:{_slug(action)}:{_slug(resource)}",
                category=Category.PERMISSION,
                severity=Severity.CRITICAL if wanted == "denied" and decision == "allowed" else Severity.HIGH,
                evidence=_evidence(source="permission-matrix", subject=subject, action=action, resource=resource,
                                   actual=decision, expected=wanted, reason=reason),
                message="Permission decision differs from the declared policy expectation.",
            ))
    return AdapterResult("permission-matrix", "measured", tuple(findings), bool(expected) and seen == set(expected))


def normalize_ssrf(result: Mapping[str, object], *, expected_decision: str | None) -> AdapterResult:
    if not isinstance(result, Mapping) or "decision" not in result:
        raise AdapterContractError("ssrf-guard-demo result has unexpected shape")
    decision = result["decision"]
    if decision not in {"allowed", "blocked"}:
        raise AdapterContractError("ssrf decision is invalid")
    if expected_decision is None:
        return AdapterResult("ssrf-guard-demo", str(decision), (), False)
    if expected_decision not in {"allowed", "blocked"}:
        raise AdapterContractError("expected SSRF decision is invalid")
    if decision == expected_decision:
        return AdapterResult("ssrf-guard-demo", str(decision), (), True)
    reason = result.get("reason", "")
    if reason and not isinstance(reason, str):
        raise AdapterContractError("ssrf reason is invalid")
    finding = Finding(
        finding_id=f"ssrf:decision:{_slug(expected_decision)}:{_slug(str(decision))}",
        category=Category.SSRF,
        severity=Severity.CRITICAL if expected_decision == "blocked" and decision == "allowed" else Severity.HIGH,
        evidence=_evidence(source="ssrf-guard-demo", actual=decision, expected=expected_decision, reason=reason),
        message="SSRF guard decision differs from the fixture expectation.",
    )
    return AdapterResult("ssrf-guard-demo", str(decision), (finding,), True)


def normalize_source(
    source: str,
    result: Mapping[str, object],
    *,
    expected_decisions: Sequence[Mapping[str, object]] | None = None,
    expected_decision: str | None = None,
) -> AdapterResult:
    if source == "env-example-guard":
        return normalize_env_example(result)
    if source == "secrets-hygiene":
        return normalize_secrets(result)
    if source == "security-headers-lab":
        return normalize_security_headers(result)
    if source == "permission-matrix":
        return normalize_permission_matrix(result, expected_decisions=expected_decisions)
    if source == "ssrf-guard-demo":
        return normalize_ssrf(result, expected_decision=expected_decision)
    raise AdapterContractError("unsupported TrustKit source")
