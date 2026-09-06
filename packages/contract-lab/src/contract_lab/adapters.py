from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

from .canonical import canonical_bytes, canonical_digest


@dataclass(frozen=True, slots=True)
class AdapterReceipt:
    source: str
    source_status: str
    verdict: str
    payload_digest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "source_status": self.source_status,
            "verdict": self.verdict,
            "payload_digest": self.payload_digest,
        }


def _receipt(source: str, source_status: str, verdict: str, payload: Any) -> AdapterReceipt:
    return AdapterReceipt(source, source_status, verdict, canonical_digest(payload))


def _blocked(source: str, reason: str = "malformed_source_result") -> AdapterReceipt:
    return _receipt(source, "invalid", "BLOCKED", {"reason": reason})


def _bounded_text(value: Any, *, limit: int = 4096) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= limit


def adapt_schema_validation(result: Any) -> AdapterReceipt:
    source = "schema-contract-tester"
    required = {"status", "errors", "errors_truncated", "records"}
    if not isinstance(result, dict) or set(result) != required:
        return _blocked(source)
    status = result["status"]
    errors = result["errors"]
    truncated = result["errors_truncated"]
    records = result["records"]
    if (
        status not in {"compatible", "blocked"}
        or not isinstance(errors, list)
        or len(errors) > 1_000
        or not isinstance(truncated, bool)
        or not isinstance(records, int)
        or isinstance(records, bool)
        or not 0 <= records <= 100_000
    ):
        return _blocked(source)
    for error in errors:
        if not isinstance(error, dict) or set(error) != {"row", "field", "error"}:
            return _blocked(source)
        if (
            not isinstance(error["row"], int)
            or isinstance(error["row"], bool)
            or error["row"] < 0
            or error["row"] >= records
            or not _bounded_text(error["field"], limit=256)
            or error["error"] not in {"missing", "type"}
        ):
            return _blocked(source)
    if status == "compatible":
        if errors or truncated:
            return _blocked(source, "inconsistent_compatible_result")
        return _receipt(source, status, "PASS", result)
    if not errors:
        return _blocked(source, "blocked_without_error_evidence")
    return _receipt(source, status, "FAIL", result)


_HEX64 = re.compile(r"[0-9a-f]{64}")


def adapt_webhook(result: Any) -> AdapterReceipt:
    source = "webhook-sandbox"
    if not isinstance(result, dict):
        return _blocked(source)

    # Source-level unreadable/invalid input uses a deliberately smaller failure shape.
    if set(result) == {"accepted", "errors", "assurance"}:
        errors = result.get("errors")
        if (
            result.get("accepted") is False
            and result.get("assurance") == "none"
            and isinstance(errors, list)
            and 1 <= len(errors) <= 16
            and all(_bounded_text(item, limit=128) for item in errors)
        ):
            return _blocked(source, "source_input_invalid")
        return _blocked(source)

    required = {"accepted", "errors", "assurance", "request_sha256", "bytes"}
    if set(result) != required:
        return _blocked(source)
    accepted = result["accepted"]
    errors = result["errors"]
    assurance = result["assurance"]
    request_sha = result["request_sha256"]
    byte_count = result["bytes"]
    if (
        not isinstance(accepted, bool)
        or not isinstance(errors, list)
        or len(errors) > 32
        or any(not _bounded_text(item, limit=128) for item in errors)
        or assurance not in {"structural_only", "hmac_sha256"}
        or not isinstance(request_sha, str)
        or _HEX64.fullmatch(request_sha) is None
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or not 0 <= byte_count <= 1_048_576
    ):
        return _blocked(source)
    if accepted != (not errors):
        return _blocked(source, "accepted_errors_inconsistent")
    return _receipt(source, "accepted" if accepted else "rejected", "PASS" if accepted else "FAIL", result)


def _source_mock_digest(payload: dict[str, Any]) -> str | None:
    unsigned = {key: value for key, value in payload.items() if key != "evidence_sha256"}
    try:
        return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return None


_ROUTE = re.compile(r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (/[A-Za-z0-9._~!$&'()*+,;=:@%{}\-/]{0,300})")


def _valid_mock_routes(responses: Any, record: dict[str, Any]) -> bool:
    if not isinstance(responses, dict) or set(responses) != {"kind", "network_server", "routes"}:
        return False
    if responses.get("kind") != "deterministic-response-fixtures" or responses.get("network_server") is not False:
        return False
    declared_routes = record.get("routes")
    modes_declared = record.get("modes")
    default_status = record.get("default_status")
    if (
        not isinstance(declared_routes, list)
        or not 1 <= len(declared_routes) <= 100
        or len(declared_routes) != len(set(declared_routes))
        or any(not isinstance(route, str) or _ROUTE.fullmatch(route) is None for route in declared_routes)
        or not isinstance(modes_declared, list)
        or len(modes_declared) != len(set(modes_declared))
        or set(modes_declared) != {"success", "degraded", "invalid"}
        or not isinstance(default_status, int)
        or isinstance(default_status, bool)
        or not 200 <= default_status <= 299
        or not _bounded_text(record.get("contract"), limit=300)
    ):
        return False
    routes = responses.get("routes")
    if not isinstance(routes, dict) or set(routes) != set(declared_routes):
        return False
    expected_modes = {"success", "degraded", "invalid"}
    for route, route_modes in routes.items():
        if not isinstance(route_modes, dict) or set(route_modes) != expected_modes:
            return False
        success = route_modes.get("success")
        degraded = route_modes.get("degraded")
        invalid = route_modes.get("invalid")
        if success != {"status": default_status, "body": {"ok": True}}:
            return False
        if degraded != {"status": 503, "body": {"ok": False, "state": "degraded"}}:
            return False
        if invalid != {"status": 500, "body": "invalid-contract-response"}:
            return False
    return True


def adapt_mock(result: Any) -> AdapterReceipt:
    source = "api-contract-mock-server"
    required = {"project", "status", "reason", "record", "responses", "evidence_sha256"}
    if not isinstance(result, dict) or set(result) != required or result.get("project") != source:
        return _blocked(source)
    status = result.get("status")
    reason = result.get("reason")
    evidence_sha = result.get("evidence_sha256")
    if (
        status not in {"passed", "failed", "blocked"}
        or not _bounded_text(reason, limit=4096)
        or not isinstance(evidence_sha, str)
        or _HEX64.fullmatch(evidence_sha) is None
        or _source_mock_digest(result) != evidence_sha
    ):
        return _blocked(source, "source_evidence_invalid")

    record = result.get("record")
    responses = result.get("responses")
    if status == "passed":
        if not isinstance(record, dict) or not _valid_mock_routes(responses, record):
            return _blocked(source, "inconsistent_passed_result")
        return _receipt(source, status, "PASS", result)
    if responses is not None:
        return _blocked(source, "nonpass_with_response_artifact")
    if status == "blocked":
        if not isinstance(record, dict) or not reason.startswith("missing required fields:"):
            return _blocked(source, "inconsistent_blocked_result")
        return _receipt(source, status, "BLOCKED", result)
    if record is not None and not isinstance(record, dict):
        return _blocked(source)
    return _receipt(source, status, "FAIL", result)
