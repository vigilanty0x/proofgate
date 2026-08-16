"""Dependency-aware evaluation of multiple ProofGate contracts."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

from .contract import ContractError, load_contract_under_root
from .engine import Gate
from .journal import EventJournal, JournalError
from .receipt import semantic_sha256
from .jsonutil import StrictJSONError, strict_dumps, strict_loads
from .safeio import FileBoundError, UnsafePathError, read_regular_file

MAX_SUITE_BYTES = 1024 * 1024
MAX_CONTRACTS = 128
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SuiteError(ValueError):
    """A suite contract is malformed or cannot be evaluated safely."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SuiteError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise SuiteError(f"{label} must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    path = Path(normalized)
    if path.is_absolute() or normalized.startswith("//") or ".." in path.parts:
        raise SuiteError(f"{label} must be a safe relative path")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise SuiteError(f"{label} must not be a drive path")
    return normalized


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise SuiteError(f"{label} must match {ID_RE.pattern}")
    return value


@dataclass(frozen=True)
class SuiteUnit:
    id: str
    path: str
    depends_on: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"id": self.id, "path": self.path}
        if self.depends_on:
            value["depends_on"] = list(self.depends_on)
        return value


@dataclass(frozen=True)
class Suite:
    version: str
    id: str
    contracts: tuple[SuiteUnit, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> "Suite":
        try:
            strict_dumps(raw, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, StrictJSONError) as exc:
            raise SuiteError(f"suite is not strict JSON: {exc}") from exc
        if not isinstance(raw, dict) or set(raw) != {"suite_version", "id", "contracts"}:
            raise SuiteError("suite must contain exactly suite_version, id, and contracts")
        if raw["suite_version"] != "1.0":
            raise SuiteError("suite_version must be '1.0'")
        suite_id = _identifier(raw["id"], "suite id")
        units_raw = raw["contracts"]
        if not isinstance(units_raw, list) or not units_raw or len(units_raw) > MAX_CONTRACTS:
            raise SuiteError(f"contracts must be a non-empty array of at most {MAX_CONTRACTS} items")
        units: list[SuiteUnit] = []
        ids: set[str] = set()
        for index, item in enumerate(units_raw):
            if not isinstance(item, dict) or set(item) - {"id", "path", "depends_on"}:
                raise SuiteError(f"contracts[{index}] has an invalid field set")
            unit_id = _identifier(item.get("id"), f"contracts[{index}].id")
            if unit_id in ids:
                raise SuiteError(f"duplicate contract id: {unit_id}")
            ids.add(unit_id)
            path = _safe_path(item.get("path"), f"contracts[{index}].path")
            dependencies = item.get("depends_on", [])
            if (
                not isinstance(dependencies, list)
                or len(dependencies) > MAX_CONTRACTS
                or any(not isinstance(value, str) or not value.strip() for value in dependencies)
                or len(set(dependencies)) != len(dependencies)
            ):
                raise SuiteError(f"contracts[{index}].depends_on must be a unique string array")
            units.append(SuiteUnit(unit_id, path, tuple(dependencies)))
        cls._validate_graph(units)
        return cls("1.0", suite_id, tuple(units))

    @staticmethod
    def _validate_graph(units: list[SuiteUnit]) -> None:
        ids = {unit.id for unit in units}
        graph = {unit.id: unit.depends_on for unit in units}
        for unit in units:
            unknown = sorted(set(unit.depends_on) - ids)
            if unknown:
                raise SuiteError(f"contract {unit.id} depends on unknown contracts: {', '.join(unknown)}")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(unit_id: str) -> None:
            if unit_id in visited:
                return
            if unit_id in visiting:
                raise SuiteError(f"contract dependency cycle includes {unit_id}")
            visiting.add(unit_id)
            for dependency in graph[unit_id]:
                visit(dependency)
            visiting.remove(unit_id)
            visited.add(unit_id)

        for unit_id in graph:
            visit(unit_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "suite_version": self.version,
            "id": self.id,
            "contracts": [unit.as_dict() for unit in self.contracts],
        }


def load_suite(path: str | Path) -> Suite:
    suite_path = Path(path)
    try:
        parent = suite_path.parent if suite_path.parent != Path("") else Path(".")
        encoded = read_regular_file(parent, suite_path.name, maximum=MAX_SUITE_BYTES)
        raw = strict_loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except SuiteError:
        raise
    except FileBoundError as exc:
        raise SuiteError(f"suite exceeds {MAX_SUITE_BYTES} bytes") from exc
    except (UnsafePathError, OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
        raise SuiteError(f"invalid suite JSON: {exc}") from exc
    return Suite.from_dict(raw)


@dataclass(frozen=True)
class SuiteVerdict:
    suite_id: str
    state: str
    status: str
    reason_code: str
    contracts: tuple[dict[str, Any], ...]
    suite_sha256: str

    @property
    def done(self) -> bool:
        return self.state == "DONE" and self.status == "verified"

    def as_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "state": self.state,
            "status": self.status,
            "reason_code": self.reason_code,
            "contracts": list(self.contracts),
            "suite_sha256": self.suite_sha256,
            "metrics": {
                "total": len(self.contracts),
                "done": sum(item.get("done") is True for item in self.contracts),
                "blocked": sum(item.get("done") is not True for item in self.contracts),
            },
        }


def evaluate_suite(
    suite: Suite,
    *,
    root: str | Path = ".",
    execute_commands: bool,
    journal_dir: str | Path | None = None,
    idempotency_prefix: str | None = None,
) -> SuiteVerdict:
    root_path = Path(root)
    if not root_path.is_dir():
        raise SuiteError("suite root is not a directory")
    if journal_dir is not None and not idempotency_prefix:
        raise SuiteError("idempotency_prefix is required when journal_dir is used")
    if idempotency_prefix is not None and journal_dir is None:
        raise SuiteError("journal_dir is required when idempotency_prefix is used")

    results: dict[str, dict[str, Any]] = {}
    pending = {unit.id: unit for unit in suite.contracts}
    while pending:
        progressed = False
        for unit in suite.contracts:
            if unit.id not in pending or any(dependency not in results for dependency in unit.depends_on):
                continue
            blocked_by = [dependency for dependency in unit.depends_on if results[dependency].get("done") is not True]
            if blocked_by:
                value = {
                    "id": unit.id,
                    "task_id": None,
                    "state": "WAITING",
                    "status": "blocked",
                    "reason_code": "DEPENDENCY_BLOCKED",
                    "done": False,
                    "blocked_by": blocked_by,
                    "evidence": [],
                }
            else:
                try:
                    contract = load_contract_under_root(root_path, unit.path)
                    journal = None
                    key = None
                    if journal_dir is not None:
                        journal_root = Path(journal_dir)
                        journal = EventJournal(journal_root / f"{unit.id}.jsonl")
                        key = f"{idempotency_prefix}:{unit.id}"
                    verdict = Gate(contract, root=root_path).evaluate(
                        execute_commands=execute_commands,
                        journal=journal,
                        idempotency_key=key,
                    )
                    value = {"id": unit.id, **verdict.as_dict(), "done": verdict.done}
                except (ContractError, JournalError, OSError, ValueError) as exc:
                    value = {
                        "id": unit.id,
                        "task_id": None,
                        "state": "REJECTED",
                        "status": "blocked",
                        "reason_code": "CONTRACT_EVALUATION_ERROR",
                        "done": False,
                        "error": type(exc).__name__,
                        "message": str(exc),
                        "evidence": [],
                    }
            results[unit.id] = value
            del pending[unit.id]
            progressed = True
        if not progressed:  # defensive: Suite validation rejects cycles.
            raise SuiteError("suite dependency graph made no progress")

    ordered = tuple(results[unit.id] for unit in suite.contracts)
    done = all(item["done"] is True for item in ordered)
    unsigned = {"suite": suite.as_dict(), "contracts": ordered}
    return SuiteVerdict(
        suite_id=suite.id,
        state="DONE" if done else "WAITING",
        status="verified" if done else "blocked",
        reason_code="ALL_CONTRACTS_VERIFIED" if done else "SUITE_INCOMPLETE",
        contracts=ordered,
        suite_sha256=semantic_sha256(unsigned),
    )
