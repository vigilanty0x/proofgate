from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any

PROJECT = "api-contract-mock-server"
REQUIRED_FIELDS = ("contract", "routes", "modes", "default_status")
MAX_INPUT_BYTES = 65_536
ROUTE = re.compile(r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (/[A-Za-z0-9._~!$&'()*+,;=:@%{}\-/]{0,300})")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def build_mock_scenarios(record: dict[str, Any]) -> dict[str, Any]:
    if not _text(record.get("contract"), 300):
        raise ValueError("contract must be a bounded single-line identifier")
    routes = record.get("routes")
    if not isinstance(routes, list) or not 1 <= len(routes) <= 100 or any(not isinstance(route, str) or not ROUTE.fullmatch(route) for route in routes):
        raise ValueError("routes must use the unique 'METHOD /path' grammar")
    if len(routes) != len(set(routes)):
        raise ValueError("routes must be unique")
    modes = record.get("modes")
    if not isinstance(modes, list) or len(modes) != len(set(modes)) or set(modes) != {"success", "degraded", "invalid"}:
        raise ValueError("modes must contain success, degraded, and invalid exactly once")
    status = record.get("default_status")
    if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status <= 299:
        raise ValueError("default_status must be a 2xx HTTP integer")
    responses = {
        route: {
            "success": {"status": status, "body": {"ok": True}},
            "degraded": {"status": 503, "body": {"ok": False, "state": "degraded"}},
            "invalid": {"status": 500, "body": "invalid-contract-response"},
        }
        for route in routes
    }
    if len(_canonical(responses).encode()) > MAX_INPUT_BYTES:
        raise ValueError("generated fixture exceeds 65536 bytes")
    return {"kind": "deterministic-response-fixtures", "network_server": False, "routes": responses}


def evaluate(record: Any) -> dict[str, Any]:
    artifact: Any = None
    safe_record = None
    try:
        if not isinstance(record, dict):
            raise ValueError("record must be a JSON object")
        if len(_canonical(record).encode()) > MAX_INPUT_BYTES:
            raise ValueError("record exceeds 65536 bytes")
        safe_record = record
        missing = [field for field in REQUIRED_FIELDS if field not in record]
        if missing:
            status, reason = "blocked", "missing required fields: " + ", ".join(missing)
        else:
            artifact = build_mock_scenarios(record)
            status, reason = "passed", "bounded response fixtures generated; no server was started"
    except (TypeError, ValueError, KeyError, OverflowError) as exc:
        status, reason = "failed", str(exc)
    receipt = {"project": PROJECT, "status": status, "reason": reason, "record": safe_record, "responses": artifact}
    receipt["evidence_sha256"] = sha256(_canonical(receipt).encode()).hexdigest()
    return receipt
