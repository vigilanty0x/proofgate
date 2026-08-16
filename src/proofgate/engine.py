"""Fail-closed evidence gate and explicit task state machine."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

from .contract import Contract
from .evidence import (
    EvidenceResult,
    evaluate_command,
    evaluate_directory,
    evaluate_file,
    evaluate_json,
    evaluate_receipt,
    evaluate_text,
)
from .journal import MAX_EVENT_BYTES, EventJournal, JournalError
from .jsonutil import StrictJSONError, strict_dumps

MAX_RECORDED_MESSAGE_BYTES = 512


def _bounded_recorded_message(message: str) -> str:
    encoded = message.encode("utf-8")
    if len(encoded) <= MAX_RECORDED_MESSAGE_BYTES:
        return message
    prefix = encoded[:MAX_RECORDED_MESSAGE_BYTES].decode("utf-8", "ignore")
    return f"{prefix}…"


@dataclass(frozen=True)
class Verdict:
    task_id: str
    state: str
    status: str
    reason_code: str
    results: tuple[EvidenceResult, ...]
    policy_mode: str = "all"
    minimum_verified: int | None = None

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
                "required": self.minimum_verified if self.minimum_verified is not None else len(self.results),
                "evidence_total": len(self.results),
                "verified": sum(result.passed for result in self.results),
                "blocked": sum(not result.passed for result in self.results),
                "policy_mode": self.policy_mode,
                "minimum_verified": self.minimum_verified if self.minimum_verified is not None else len(self.results),
            },
        }

    def as_journal_dict(self) -> dict[str, Any]:
        """Return a bounded replay record without persisting raw evidence output."""

        value = self.as_dict()
        evidence: list[dict[str, Any]] = []
        for result in self.results:
            try:
                encoded = strict_dumps(
                    result.details,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            except (TypeError, ValueError, StrictJSONError) as exc:
                raise JournalError(f"evidence details are not strict JSON: {exc}") from exc
            item = result.as_dict()
            item["message"] = _bounded_recorded_message(result.message)
            item["details"] = {"recorded_details_sha256": hashlib.sha256(encoded).hexdigest()}
            evidence.append(item)
        value["evidence"] = evidence
        return value

    @classmethod
    def from_journal_dict(cls, value: Any) -> "Verdict":
        """Rehydrate a completed outcome without re-running its evidence."""

        if not isinstance(value, dict):
            raise JournalError("recorded verdict must be an object")
        required = {"task_id", "state", "status", "reason_code", "evidence", "metrics"}
        if set(value) != required:
            raise JournalError("recorded verdict has an invalid field set")
        if not all(isinstance(value[field], str) and value[field] for field in ("task_id", "state", "status", "reason_code")):
            raise JournalError("recorded verdict identity or state is invalid")
        if len(value["task_id"]) > 128 or len(value["reason_code"]) > 128:
            raise JournalError("recorded verdict identity or reason is too long")
        state = value["state"]
        status = value["status"]
        reason = value["reason_code"]
        if state not in {"DONE", "WAITING", "FAILED", "REJECTED"}:
            raise JournalError("recorded verdict state is invalid")
        if status not in {"verified", "blocked"}:
            raise JournalError("recorded verdict status is invalid")
        if (state == "DONE") is not (status == "verified"):
            raise JournalError("recorded verdict state contradicts status")
        expected_reasons = {
            "DONE": {"ALL_EVIDENCE_VERIFIED", "POLICY_SATISFIED"},
            "WAITING": {"EVIDENCE_INCOMPLETE"},
            "FAILED": {"EVIDENCE_FAILED"},
            "REJECTED": {"ROOT_INVALID", "CIRCUIT_OPEN"},
        }
        if reason not in expected_reasons[state]:
            raise JournalError("recorded verdict reason_code contradicts state")
        raw_results = value["evidence"]
        metrics = value["metrics"]
        if not isinstance(raw_results, list) or not raw_results or len(raw_results) > 128 or not isinstance(metrics, dict):
            raise JournalError("recorded verdict evidence or metrics is invalid")
        results: list[EvidenceResult] = []
        seen_ids: set[str] = set()
        fields = {"id", "type", "classification", "passed", "code", "message", "details"}
        for item in raw_results:
            if not isinstance(item, dict) or set(item) != fields:
                raise JournalError("recorded verdict evidence has an invalid field set")
            if not all(isinstance(item[field], str) for field in ("id", "type", "classification", "code", "message")):
                raise JournalError("recorded verdict evidence text is invalid")
            if not isinstance(item["passed"], bool) or not isinstance(item["details"], dict):
                raise JournalError("recorded verdict evidence types are invalid")
            if (
                not item["id"]
                or len(item["id"]) > 128
                or item["id"] in seen_ids
                or not item["type"]
                or len(item["type"]) > 128
                or not item["code"]
                or len(item["code"]) > 128
                or not item["message"]
                or len(item["message"].encode("utf-8")) > MAX_RECORDED_MESSAGE_BYTES + 3
            ):
                raise JournalError("recorded verdict evidence identity or text bound is invalid")
            seen_ids.add(item["id"])
            classification = item["classification"]
            if classification not in {"proof", "inference", "blockage"}:
                raise JournalError("recorded verdict evidence classification is invalid")
            if item["passed"] is not (classification == "proof"):
                raise JournalError("recorded verdict evidence classification contradicts passed")
            if item["passed"] is not (item["code"] == "EVIDENCE_VERIFIED"):
                raise JournalError("recorded verdict evidence code contradicts passed")
            details = item["details"]
            digest = details.get("recorded_details_sha256")
            if set(details) != {"recorded_details_sha256"} or not isinstance(digest, str) or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise JournalError("recorded verdict evidence details digest is invalid")
            results.append(
                EvidenceResult(
                    item["id"],
                    item["type"],
                    item["classification"],
                    item["passed"],
                    item["code"],
                    item["message"],
                    item["details"],
                )
            )
        metric_fields = {"required", "evidence_total", "verified", "blocked", "policy_mode", "minimum_verified"}
        if set(metrics) != metric_fields:
            raise JournalError("recorded verdict metrics have an invalid field set")
        policy_mode = metrics["policy_mode"]
        minimum = metrics["minimum_verified"]
        numeric_fields = ("required", "evidence_total", "verified", "blocked", "minimum_verified")
        if policy_mode not in {"all", "any", "threshold"} or any(type(metrics[field]) is not int for field in numeric_fields):
            raise JournalError("recorded verdict policy metrics are invalid")
        verified = sum(result.passed for result in results)
        if (
            metrics["evidence_total"] != len(results)
            or metrics["verified"] != verified
            or metrics["blocked"] != len(results) - verified
            or metrics["required"] != minimum
            or minimum < 1
        ):
            raise JournalError("recorded verdict metrics contradict evidence")
        if state != "REJECTED" and (
            (policy_mode == "all" and minimum != len(results))
            or (policy_mode == "any" and minimum != 1)
            or (policy_mode == "threshold" and minimum > len(results))
        ):
            raise JournalError("recorded verdict policy mode contradicts minimum_verified")
        if state == "DONE" and verified < minimum:
            raise JournalError("recorded verdict completion contradicts policy metrics")
        if state != "DONE" and verified >= minimum:
            raise JournalError("recorded blocked verdict contradicts policy metrics")
        if reason == "ALL_EVIDENCE_VERIFIED" and verified != len(results):
            raise JournalError("recorded verdict completion contradicts all-evidence reason")
        return cls(
            task_id=value["task_id"],
            state=value["state"],
            status=value["status"],
            reason_code=value["reason_code"],
            results=tuple(results),
            policy_mode=policy_mode,
            minimum_verified=minimum,
        )


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
        if journal is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 248:
                raise ValueError("idempotency_key must be a non-empty string up to 248 characters")
            fingerprint = self._operation_fingerprint(execute_commands)
            _claim, created = journal.append_once(
                idempotency_key=f"{idempotency_key}:claim",
                kind="attempt_claim",
                data={"request_sha256": fingerprint, "task_id": self.contract.task_id},
                reserve_bytes=MAX_EVENT_BYTES,
            )
            if not created:
                recorded = journal.find(f"{idempotency_key}:verdict")
                if recorded is None:
                    raise JournalError("idempotent attempt is already in progress or ended without a verdict")
                if recorded["kind"] != "verdict":
                    raise JournalError("idempotent attempt verdict has an invalid event kind")
                verdict = Verdict.from_journal_dict(recorded["data"])
                if verdict.task_id != self.contract.task_id:
                    raise JournalError("recorded verdict task_id does not match the claimed contract")
                return verdict

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

        results_by_id: dict[str, EvidenceResult] = {}
        pending = {rule.id: rule for rule in self.contract.evidence}
        while pending:
            progressed = False
            for rule in self.contract.evidence:
                if rule.id not in pending:
                    continue
                if any(dependency not in results_by_id for dependency in rule.depends_on):
                    continue
                failed_dependencies = [
                    dependency for dependency in rule.depends_on if not results_by_id[dependency].passed
                ]
                if failed_dependencies:
                    result = EvidenceResult(
                        rule.id,
                        rule.type,
                        "blockage",
                        False,
                        "DEPENDENCY_BLOCKED",
                        "evidence was not evaluated because a dependency failed",
                        {"dependencies": list(rule.depends_on), "blocked_by": failed_dependencies},
                    )
                else:
                    result = self._evaluate_rule(rule, execute_commands=execute_commands)
                results_by_id[rule.id] = result
                del pending[rule.id]
                progressed = True
            if not progressed:  # defensive; Contract rejects cycles and unknown dependencies.
                for rule in pending.values():
                    results_by_id[rule.id] = EvidenceResult(
                        rule.id,
                        rule.type,
                        "blockage",
                        False,
                        "DEPENDENCY_GRAPH_INVALID",
                        "dependency graph could not be evaluated",
                        {"dependencies": list(rule.depends_on)},
                    )
                pending.clear()

        results = tuple(results_by_id[rule.id] for rule in self.contract.evidence)
        verified = sum(result.passed for result in results)
        required = self.contract.policy.required(len(results))
        if verified >= required:
            reason = "ALL_EVIDENCE_VERIFIED" if self.contract.policy.mode == "all" else "POLICY_SATISFIED"
            return self._finish(results, "DONE", reason, journal, idempotency_key)
        contradiction_codes = {
            "ARTIFACT_HASH_MISMATCH",
            "ARTIFACT_SIZE_MISMATCH",
            "COMMAND_EXIT_MISMATCH",
            "COMMAND_CLEANUP_INCOMPLETE",
            "COMMAND_START_FAILED",
            "COMMAND_TIMEOUT",
            "DIRECTORY_TOO_MANY_FILES",
            "FILE_TOO_SMALL",
            "HASH_MISMATCH",
            "JSON_VALUE_MISMATCH",
            "RECEIPT_NOT_DONE",
            "TEXT_LITERAL_MISSING",
        }
        if any(result.code in contradiction_codes for result in results):
            return self._finish(results, "FAILED", "EVIDENCE_FAILED", journal, idempotency_key)
        return self._finish(results, "WAITING", "EVIDENCE_INCOMPLETE", journal, idempotency_key)

    def _operation_fingerprint(self, execute_commands: bool) -> str:
        root_digest = hashlib.sha256(str(self.root.resolve()).encode("utf-8")).hexdigest()
        payload = {
            "contract": self.contract.as_dict(),
            "execute_commands": execute_commands,
            "root_sha256": root_digest,
        }
        try:
            encoded = strict_dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, StrictJSONError) as exc:
            raise JournalError(f"operation request is not strict JSON: {exc}") from exc
        return hashlib.sha256(encoded).hexdigest()

    def _evaluate_rule(self, rule: Any, *, execute_commands: bool) -> EvidenceResult:
        if rule.type == "file":
            return evaluate_file(rule, self.root)
        if rule.type == "json":
            return evaluate_json(rule, self.root)
        if rule.type == "text":
            return evaluate_text(rule, self.root)
        if rule.type == "directory":
            return evaluate_directory(rule, self.root)
        if rule.type == "receipt":
            return evaluate_receipt(rule, self.root)
        if execute_commands:
            return evaluate_command(rule, self.root, self.contract.timeout_seconds)
        return EvidenceResult(
            rule.id,
            rule.type,
            "inference",
            False,
            "COMMAND_NOT_EXECUTED",
            "check mode does not execute commands",
            {"command": rule.config["command"]},
        )

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
            policy_mode=self.contract.policy.mode,
            minimum_verified=self.contract.policy.required(len(self.contract.evidence)),
        )
        if journal is not None:
            if not idempotency_key:
                raise ValueError("idempotency_key is required when a journal is used")
            journal.append(
                idempotency_key=f"{idempotency_key}:verdict",
                kind="verdict",
                data=verdict.as_journal_dict(),
            )
        return verdict
