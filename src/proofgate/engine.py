"""Fail-closed evidence gate and explicit task state machine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import Contract
from .evidence import EvidenceResult, evaluate_command, evaluate_file, evaluate_json
from .journal import EventJournal


@dataclass(frozen=True)
class Verdict:
    task_id: str
    state: str
    status: str
    reason_code: str
    results: tuple[EvidenceResult, ...]

    @property
    def done(self) -> bool:
        return self.state == "DONE" and self.status == "verified"

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "state": self.state,
            "status": self.status,
            "reason_code": self.reason_code,
            "evidence": [result.as_dict() for result in self.results],
            "metrics": {
                "required": len(self.results),
                "verified": sum(result.passed for result in self.results),
                "blocked": sum(not result.passed for result in self.results),
            },
        }


class Gate:
    def __init__(self, contract: Contract, *, root: str | Path = "."):
        self.contract = contract
        self.root = Path(root)

    def evaluate(
        self,
        *,
        execute_commands: bool,
        journal: EventJournal | None = None,
        idempotency_key: str | None = None,
    ) -> Verdict:
        if not self.root.is_dir():
            result = EvidenceResult(
                "evaluation-root",
                "environment",
                "blockage",
                False,
                "ROOT_INVALID",
                "evaluation root is not a directory",
                {"root": str(self.root)},
            )
            return self._finish((result,), "REJECTED", "ROOT_INVALID", journal, idempotency_key)

        if execute_commands and journal is not None:
            replay = journal.replay()
            if replay.failures >= self.contract.failure_threshold:
                result = EvidenceResult(
                    "circuit-breaker",
                    "runtime",
                    "blockage",
                    False,
                    "CIRCUIT_OPEN",
                    "failure threshold reached; command execution was not attempted",
                    {
                        "failures": replay.failures,
                        "failure_threshold": self.contract.failure_threshold,
                    },
                )
                return self._finish((result,), "REJECTED", "CIRCUIT_OPEN", journal, idempotency_key)

        results: list[EvidenceResult] = []
        for rule in self.contract.evidence:
            if rule.type == "file":
                results.append(evaluate_file(rule, self.root))
            elif rule.type == "json":
                results.append(evaluate_json(rule, self.root))
            elif execute_commands:
                results.append(evaluate_command(rule, self.root, self.contract.timeout_seconds))
            else:
                results.append(
                    EvidenceResult(
                        rule.id,
                        rule.type,
                        "inference",
                        False,
                        "COMMAND_NOT_EXECUTED",
                        "check mode does not execute commands",
                        {"command": rule.config["command"]},
                    )
                )

        if all(result.passed for result in results):
            return self._finish(tuple(results), "DONE", "ALL_EVIDENCE_VERIFIED", journal, idempotency_key)
        command_failure_codes = {"COMMAND_TIMEOUT", "COMMAND_START_FAILED", "COMMAND_EXIT_MISMATCH"}
        if any(result.code in command_failure_codes for result in results):
            return self._finish(tuple(results), "FAILED", "EVIDENCE_FAILED", journal, idempotency_key)
        return self._finish(tuple(results), "WAITING", "EVIDENCE_INCOMPLETE", journal, idempotency_key)

    def _finish(
        self,
        results: tuple[EvidenceResult, ...],
        state: str,
        reason_code: str,
        journal: EventJournal | None,
        idempotency_key: str | None,
    ) -> Verdict:
        verdict = Verdict(
            task_id=self.contract.task_id,
            state=state,
            status="verified" if state == "DONE" else "blocked",
            reason_code=reason_code,
            results=results,
        )
        if journal is not None:
            if not idempotency_key:
                raise ValueError("idempotency_key is required when a journal is used")
            journal.append(
                idempotency_key=f"{idempotency_key}:verdict",
                kind="verdict",
                data=verdict.as_dict(),
            )
        return verdict

