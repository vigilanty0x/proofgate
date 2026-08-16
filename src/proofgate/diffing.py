"""Deterministic comparison for verdicts and receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .jsonutil import StrictJSONError, strict_loads

MAX_DIFF_INPUT_BYTES = 16 * 1024 * 1024


class DiffError(ValueError):
    """A comparison input is malformed or too large."""


def load_json_document(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    try:
        if candidate.stat().st_size > MAX_DIFF_INPUT_BYTES:
            raise DiffError(f"input exceeds {MAX_DIFF_INPUT_BYTES} bytes")
        value = strict_loads(candidate.read_text(encoding="utf-8"))
    except DiffError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
        raise DiffError(f"invalid JSON input: {exc}") from exc
    if not isinstance(value, dict):
        raise DiffError("comparison input must be a JSON object")
    if "verdict" in value and isinstance(value["verdict"], dict):
        value = value["verdict"]
    return value


def _evidence_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    evidence = value.get("evidence")
    if not isinstance(evidence, list):
        raise DiffError("verdict evidence must be an array")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            raise DiffError(f"evidence[{index}] must be an object")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in result:
            raise DiffError(f"evidence[{index}].id is invalid or duplicated")
        result[identifier] = item
    return result


def compare_verdicts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two full verdicts or receipt verdict summaries."""

    for label, value in (("before", before), ("after", after)):
        if not isinstance(value, dict):
            raise DiffError(f"{label} verdict must be an object")
        if not isinstance(value.get("state"), str) or not isinstance(value.get("status"), str):
            raise DiffError(f"{label} verdict is missing state or status")
    before_items = _evidence_map(before)
    after_items = _evidence_map(after)
    added = sorted(set(after_items) - set(before_items))
    removed = sorted(set(before_items) - set(after_items))
    changed: list[dict[str, Any]] = []
    regressions: list[str] = []
    improvements: list[str] = []
    for identifier in sorted(set(before_items) & set(after_items)):
        old = before_items[identifier]
        new = after_items[identifier]
        old_view = {
            "passed": old.get("passed"),
            "classification": old.get("classification"),
            "code": old.get("code"),
            "details_sha256": old.get("details_sha256"),
        }
        new_view = {
            "passed": new.get("passed"),
            "classification": new.get("classification"),
            "code": new.get("code"),
            "details_sha256": new.get("details_sha256"),
        }
        if old_view != new_view:
            changed.append({"id": identifier, "before": old_view, "after": new_view})
        if old.get("passed") is True and new.get("passed") is not True:
            regressions.append(identifier)
        if old.get("passed") is not True and new.get("passed") is True:
            improvements.append(identifier)
    before_done = before.get("state") == "DONE" and before.get("status") == "verified"
    after_done = after.get("state") == "DONE" and after.get("status") == "verified"
    regression = (before_done and not after_done) or bool(regressions) or bool(removed)
    return {
        "task_id_before": before.get("task_id"),
        "task_id_after": after.get("task_id"),
        "state_before": before.get("state"),
        "state_after": after.get("state"),
        "status_before": before.get("status"),
        "status_after": after.get("status"),
        "regression": regression,
        "added_evidence": added,
        "removed_evidence": removed,
        "regressed_evidence": regressions,
        "improved_evidence": improvements,
        "changed_evidence": changed,
    }
