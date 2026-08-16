"""Strict, dependency-free parsing for ProofGate contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from .jsonutil import StrictJSONError, strict_dumps, strict_loads
from .safeio import FileBoundError, UnsafePathError, read_regular_file

MAX_CONTRACT_BYTES = 1024 * 1024
MAX_EVIDENCE = 128
ALLOWED_TYPES = {"command", "directory", "file", "json", "receipt", "text"}
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
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or "\x00" in value:
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
    depends_on: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = {"id": self.id, "type": self.type, **self.config}
        if self.depends_on:
            value["depends_on"] = list(self.depends_on)
        return value


@dataclass(frozen=True)
class Policy:
    """How verified evidence is combined into the terminal verdict."""

    mode: str = "all"
    minimum_verified: int | None = None

    def required(self, evidence_count: int) -> int:
        if self.mode == "all":
            return evidence_count
        if self.mode == "any":
            return 1
        if self.minimum_verified is None:  # protected by contract validation
            raise ContractError("threshold policy is missing minimum_verified")
        return self.minimum_verified

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"mode": self.mode}
        if self.mode == "threshold":
            value["minimum_verified"] = self.minimum_verified
        return value


@dataclass(frozen=True)
class Contract:
    version: str
    task_id: str
    initial_state: str
    terminal_state: str
    timeout_seconds: int
    failure_threshold: int
    evidence: tuple[EvidenceRule, ...]
    policy: Policy = field(default_factory=Policy)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.version,
            "task": {
                "id": self.task_id,
                "initial_state": self.initial_state,
                "terminal_state": self.terminal_state,
            },
            "timeout_seconds": self.timeout_seconds,
            "circuit_breaker": {"failure_threshold": self.failure_threshold},
            "policy": self.policy.as_dict(),
            "evidence": [rule.as_dict() for rule in self.evidence],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "Contract":
        try:
            strict_dumps(raw, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, StrictJSONError) as exc:
            raise ContractError(f"contract is not strict JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise ContractError("contract root must be an object")
        allowed = {"contract_version", "task", "timeout_seconds", "circuit_breaker", "policy", "evidence"}
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

        policy = cls._parse_policy(raw.get("policy", {"mode": "all"}), len(evidence_raw))

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
                raise ContractError(
                    f"evidence[{index}].type must be one of: {', '.join(sorted(ALLOWED_TYPES))}"
                )
            config = dict(item)
            config.pop("id", None)
            config.pop("type", None)
            dependencies_raw = config.pop("depends_on", [])
            if (
                not isinstance(dependencies_raw, list)
                or len(dependencies_raw) > MAX_EVIDENCE
                or any(not isinstance(value, str) or not value.strip() for value in dependencies_raw)
                or len(set(dependencies_raw)) != len(dependencies_raw)
            ):
                raise ContractError(f"evidence[{index}].depends_on must be a unique string array")
            cls._validate_rule(rule_type, config, index, timeout)
            rules.append(EvidenceRule(rule_id, rule_type, config, tuple(dependencies_raw)))

        cls._validate_dependency_graph(rules)
        return cls("1.0", task_id, initial, terminal, timeout, threshold, tuple(rules), policy)

    @staticmethod
    def _parse_policy(raw: Any, evidence_count: int) -> Policy:
        if not isinstance(raw, dict) or set(raw) - {"mode", "minimum_verified"}:
            raise ContractError("policy must contain only mode and minimum_verified")
        mode = raw.get("mode", "all")
        if mode not in {"all", "any", "threshold"}:
            raise ContractError("policy.mode must be all, any, or threshold")
        minimum = raw.get("minimum_verified")
        if mode == "threshold":
            if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= evidence_count:
                raise ContractError(f"policy.minimum_verified must be an integer from 1 to {evidence_count}")
        elif minimum is not None:
            raise ContractError("policy.minimum_verified is valid only for threshold mode")
        return Policy(mode, minimum)

    @staticmethod
    def _validate_dependency_graph(rules: list[EvidenceRule]) -> None:
        ids = {rule.id for rule in rules}
        graph = {rule.id: rule.depends_on for rule in rules}
        for rule in rules:
            unknown = sorted(set(rule.depends_on) - ids)
            if unknown:
                raise ContractError(f"evidence {rule.id} depends on unknown evidence: {', '.join(unknown)}")
            if rule.id in rule.depends_on:
                raise ContractError(f"evidence dependency cycle includes {rule.id}")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(rule_id: str) -> None:
            if rule_id in visited:
                return
            if rule_id in visiting:
                raise ContractError(f"evidence dependency cycle includes {rule_id}")
            visiting.add(rule_id)
            for dependency in graph[rule_id]:
                visit(dependency)
            visiting.remove(rule_id)
            visited.add(rule_id)

        for rule_id in graph:
            visit(rule_id)

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

        if rule_type == "json":
            allowed = {"path", "pointer", "equals"}
            if set(config) - allowed:
                raise ContractError(f"{label} json rule has unknown fields")
            _safe_relative_path(config.get("path"), f"{label}.path")
            pointer = config.get("pointer")
            if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
                raise ContractError(f"{label}.pointer must be an RFC 6901 JSON pointer")
            if "equals" not in config:
                raise ContractError(f"{label}.equals is required")
            return

        if rule_type == "text":
            allowed = {"path", "contains", "case_sensitive", "min_occurrences"}
            if set(config) - allowed:
                raise ContractError(f"{label} text rule has unknown fields")
            _safe_relative_path(config.get("path"), f"{label}.path")
            needles = config.get("contains")
            if isinstance(needles, str):
                needles = [needles]
            if (
                not isinstance(needles, list)
                or not needles
                or len(needles) > 32
                or any(not isinstance(item, str) or not item or len(item) > 512 for item in needles)
                or len(set(needles)) != len(needles)
            ):
                raise ContractError(f"{label}.contains must be a non-empty unique string or string array")
            if not isinstance(config.get("case_sensitive", True), bool):
                raise ContractError(f"{label}.case_sensitive must be boolean")
            minimum = config.get("min_occurrences", 1)
            _positive_int(minimum, f"{label}.min_occurrences", maximum=10000)
            return

        if rule_type == "directory":
            allowed = {"path", "pattern", "min_files", "max_files"}
            if set(config) - allowed:
                raise ContractError(f"{label} directory rule has unknown fields")
            _safe_relative_path(config.get("path"), f"{label}.path")
            pattern = config.get("pattern", "*")
            if (
                not isinstance(pattern, str)
                or not pattern
                or len(pattern) > 256
                or "\x00" in pattern
                or ".." in Path(pattern).parts
                or Path(pattern).is_absolute()
            ):
                raise ContractError(f"{label}.pattern must be a safe relative glob")
            minimum = config.get("min_files", 1)
            maximum = config.get("max_files", 10000)
            if isinstance(minimum, bool) or not isinstance(minimum, int) or not 0 <= minimum <= 10000:
                raise ContractError(f"{label}.min_files must be an integer from 0 to 10000")
            if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 <= maximum <= 10000:
                raise ContractError(f"{label}.max_files must be an integer from 0 to 10000")
            if minimum > maximum:
                raise ContractError(f"{label}.min_files must not exceed max_files")
            return

        allowed = {"path", "expected_task_id", "verify_artifacts"}
        if set(config) - allowed:
            raise ContractError(f"{label} receipt rule has unknown fields")
        _safe_relative_path(config.get("path"), f"{label}.path")
        expected = config.get("expected_task_id")
        if expected is not None and (not isinstance(expected, str) or not expected.strip() or len(expected) > 128):
            raise ContractError(f"{label}.expected_task_id must be a non-empty string up to 128 characters")
        if not isinstance(config.get("verify_artifacts", True), bool):
            raise ContractError(f"{label}.verify_artifacts must be boolean")


def _parse_contract_bytes(encoded: bytes) -> Contract:
    try:
        raw = strict_loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except ContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
        raise ContractError(f"invalid contract JSON: {exc}") from exc
    return Contract.from_dict(raw)


def load_contract_under_root(root: str | Path, relative: str) -> Contract:
    try:
        encoded = read_regular_file(root, relative, maximum=MAX_CONTRACT_BYTES)
    except FileBoundError as exc:
        raise ContractError(f"contract exceeds {MAX_CONTRACT_BYTES} bytes") from exc
    except (UnsafePathError, OSError) as exc:
        raise ContractError(f"cannot safely read contract: {exc}") from exc
    return _parse_contract_bytes(encoded)


def load_contract(path: str | Path) -> Contract:
    contract_path = Path(path)
    parent = contract_path.parent if contract_path.parent != Path("") else Path(".")
    return load_contract_under_root(parent, contract_path.name)
