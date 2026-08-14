from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def contract_dict(evidence: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract_version": "1.0",
        "task": {"id": "demo", "initial_state": "PENDING", "terminal_state": "DONE"},
        "timeout_seconds": 2,
        "circuit_breaker": {"failure_threshold": 2},
        "evidence": evidence,
    }
    value.update(overrides)
    return value


def write_contract(root: Path, value: dict[str, Any]) -> Path:
    path = root / "proofgate.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path

