"""Strict, dependency-free parsing for ProofGate contracts."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

MAX_CONTRACT_BYTES = 1024 * 1024
MAX_EVIDENCE = 128
ALLOWED_TYPES = {"command", "file", "json"}
ALLOWED_STATES = {"PENDING", "RUNNING", "WAITING", "FAILED", "REJECTED", "DONE"}


class ContractError(ValueError):
    """A contract is malformed or unsafe."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _positive_int(value: Any, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ContractError(f"{label} must be an integer from 1 to {maximum}")
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    normalized = value.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("//"):
        raise ContractError(f"{label} must be relative")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise ContractError(f"{label} must not be a drive path")
    if ".." in candidate.parts:
        raise ContractError(f"{label} must not traverse parent directories")
    return normalized


@dataclass(frozen=True)
class EvidenceRule:
    id: str
    type: str
    config: dict[str, Any]


@dataclass(frozen=True)
class Contract:
    version: str
    task_id: str
    initial_state: str
    terminal_state: str
    timeout_seconds: int
    failure_threshold: int
    evidence: tuple[EvidenceRule, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> "Contract":
        if not isinstance(raw, dict):
            raise ContractError("contract root must be an object")
        allowed = {"contract_version", "task", "timeout_seconds", "circuit_breaker", "evidence"}
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ContractError(f"unknown top-level fields: {', '.join(unknown)}")
        if raw.get("contract_version") != "1.0":
            raise ContractError("contract_version must be '1.0'")

        task = raw.get("task")
        if not isinstance(task, dict):
            raise ContractError("task must be an object")
        if set(task) - {"id", "initial_state", "terminal_state"}:
            raise ContractError("task contains unknown fields")
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id.strip() or len(task_id) > 128:
            raise ContractError("task.id must be a non-empty string up to 128 characters")
        initial = task.get("initial_state", "PENDING")
        terminal = task.get("terminal_state", "DONE")
        if initial not in ALLOWED_STATES or terminal not in ALLOWED_STATES:
            raise ContractError("task states must use the documented state vocabulary")
        if terminal != "DONE":
            raise ContractError("task.terminal_state must be DONE")

        timeout = _positive_int(raw.get("timeout_seconds", 60), "timeout_seconds", maximum=3600)
        breaker = raw.get("circuit_breaker", {})
        if not isinstance(breaker, dict) or set(breaker) - {"failure_threshold"}:
            raise ContractError("circuit_breaker must contain only failure_threshold")
        threshold = _positive_int(
            breaker.get("failure_threshold", 3),
            "circuit_breaker.failure_threshold",
            maximum=100,
        )

        evidence_raw = raw.get("evidence")
        if not isinstance(evidence_raw, list) or not evidence_raw:
            raise ContractError("evidence must be a non-empty array")
        if len(evidence_raw) > MAX_EVIDENCE:
            raise ContractError(f"evidence may contain at most {MAX_EVIDENCE} rules")

        rules: list[EvidenceRule] = []
        ids: set[str] = set()
        for index, item in enumerate(evidence_raw):
            if not isinstance(item, dict):
                raise ContractError(f"evidence[{index}] must be an object")
            rule_id = item.get("id")
            rule_type = item.get("type")
            if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id) > 128:
                raise ContractError(f"evidence[{index}].id is invalid")
            if rule_id in ids:
                raise ContractError(f"duplicate evidence id: {rule_id}")
            ids.add(rule_id)
            if rule_type not in ALLOWED_TYPES:
                raise ContractError(f"evidence[{index}].type must be command, file, or json")
            config = dict(item)
            config.pop("id", None)
            config.pop("type", None)
            cls._validate_rule(rule_type, config, index, timeout)
            rules.append(EvidenceRule(rule_id, rule_type, config))

        return cls("1.0", task_id, initial, terminal, timeout, threshold, tuple(rules))

    @staticmethod
    def _validate_rule(rule_type: str, config: dict[str, Any], index: int, global_timeout: int) -> None:
        label = f"evidence[{index}]"
        if rule_type == "command":
            allowed = {"command", "expect_exit", "timeout_seconds"}
            if set(config) - allowed:
                raise ContractError(f"{label} command rule has unknown fields")
            command = config.get("command")
            if (
                not isinstance(command, list)
                or not command
                or len(command) > 64
                or any(not isinstance(part, str) or not part or len(part) > 4096 for part in command)
            ):
                raise ContractError(f"{label}.command must be a non-empty string array")
            expect = config.get("expect_exit", 0)
            if isinstance(expect, bool) or not isinstance(expect, int) or not -255 <= expect <= 255:
                raise ContractError(f"{label}.expect_exit must be an integer from -255 to 255")
            rule_timeout = config.get("timeout_seconds", global_timeout)
            _positive_int(rule_timeout, f"{label}.timeout_seconds", maximum=global_timeout)
            return

        if rule_type == "file":
            allowed = {"path", "sha256", "min_bytes"}
            if set(config) - allowed:
                raise ContractError(f"{label} file rule has unknown fields")
            _safe_relative_path(config.get("path"), f"{label}.path")
            digest = config.get("sha256")
            if digest is not None and (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)
            ):
                raise ContractError(f"{label}.sha256 must be a 64-character hexadecimal digest")
            minimum = config.get("min_bytes", 1)
            if isinstance(minimum, bool) or not isinstance(minimum, int) or not 0 <= minimum <= 2**40:
                raise ContractError(f"{label}.min_bytes must be a non-negative integer")
            return

        allowed = {"path", "pointer", "equals"}
        if set(config) - allowed:
            raise ContractError(f"{label} json rule has unknown fields")
        _safe_relative_path(config.get("path"), f"{label}.path")
        pointer = config.get("pointer")
        if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
            raise ContractError(f"{label}.pointer must be an RFC 6901 JSON pointer")
        if "equals" not in config:
            raise ContractError(f"{label}.equals is required")


def load_contract(path: str | Path) -> Contract:
    contract_path = Path(path)
    try:
        size = contract_path.stat().st_size
    except OSError as exc:
        raise ContractError(f"cannot read contract: {exc}") from exc
    if size > MAX_CONTRACT_BYTES:
        raise ContractError(f"contract exceeds {MAX_CONTRACT_BYTES} bytes")
    try:
        raw = json.loads(contract_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid contract JSON: {exc}") from exc
    return Contract.from_dict(raw)

