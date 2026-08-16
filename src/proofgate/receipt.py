"""Portable, tamper-evident completion receipts.

A receipt intentionally contains summaries and digests, not captured command output or
artifact contents.  It can therefore be handed to another gate without granting that
gate access to the original process environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
import uuid

from .contract import MAX_EVIDENCE, Contract
from .engine import Verdict
from .journal import EventJournal
from .jsonutil import StrictJSONError, strict_dumps, strict_loads
from .safeio import FileBoundError, UnsafePathError, hash_regular_file, read_regular_file

MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 1024
RECEIPT_VERSION = "1.0"


class ReceiptError(ValueError):
    """A receipt is malformed, unsafe, or cryptographically inconsistent."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return strict_dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, StrictJSONError) as exc:
        raise ReceiptError(f"value is not canonical JSON: {exc}") from exc


def semantic_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _relative_path(relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ReceiptError("artifact path must be a non-empty string")
    normalized = relative.replace("\\", "/")
    candidate_path = Path(normalized)
    if candidate_path.is_absolute() or ".." in candidate_path.parts or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ReceiptError("artifact path must be safe and relative")
    return candidate_path


def _hash_file(root: Path, relative: str) -> tuple[int, str]:
    _relative_path(relative)
    try:
        digest = hash_regular_file(root, relative, maximum=MAX_ARTIFACT_BYTES)
    except FileNotFoundError:
        raise
    except FileBoundError as exc:
        raise ReceiptError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    except UnsafePathError:
        raise
    except OSError as exc:
        raise ReceiptError(f"cannot read artifact: {exc}") from exc
    return digest.size, digest.sha256


def _result_summary(verdict: Verdict) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    for result in verdict.results:
        recorded_digest = result.details.get("recorded_details_sha256")
        if set(result.details) == {"recorded_details_sha256"} and isinstance(recorded_digest, str):
            details_digest = recorded_digest
        else:
            details_digest = semantic_sha256(result.details)
        evidence.append(
            {
                "id": result.id,
                "type": result.evidence_type,
                "classification": result.classification,
                "passed": result.passed,
                "code": result.code,
                "details_sha256": details_digest,
            }
        )
    return {
        "task_id": verdict.task_id,
        "state": verdict.state,
        "status": verdict.status,
        "reason_code": verdict.reason_code,
        "done": verdict.done,
        "evidence": evidence,
    }


def _artifact_manifest(contract: Contract, verdict: Verdict, root: Path) -> list[dict[str, Any]]:
    by_id = {result.id: result for result in verdict.results}
    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in contract.evidence:
        result = by_id.get(rule.id)
        if result is None or not result.passed or rule.type not in {"file", "json", "receipt", "text"}:
            continue
        relative = rule.config["path"].replace("\\", "/")
        if relative in seen:
            continue
        try:
            size, digest = _hash_file(root, relative)
        except (FileNotFoundError, UnsafePathError, ReceiptError) as exc:
            raise ReceiptError(
                f"verified artifact disappeared or became unsafe before receipt creation: {relative}: {exc}"
            ) from exc
        artifacts.append({"path": relative, "size": size, "sha256": digest})
        seen.add(relative)
        if len(artifacts) > MAX_ARTIFACTS:
            raise ReceiptError(f"receipt may contain at most {MAX_ARTIFACTS} artifacts")
    artifacts.sort(key=lambda item: item["path"])
    return artifacts


def create_receipt(
    contract: Contract,
    verdict: Verdict,
    *,
    root: str | Path,
    journal: EventJournal | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Create a receipt from a completed evaluation.

    Blocked verdicts may also be receipted.  Consumers can verify what happened but
    must still inspect ``verdict.done`` before treating it as successful completion.
    """

    if verdict.task_id != contract.task_id:
        raise ReceiptError("verdict task_id does not match contract")
    root_path = Path(root)
    if not root_path.is_dir():
        raise ReceiptError("receipt root is not a directory")
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise ReceiptError("created_at must be an ISO-8601 UTC string ending in Z")

    journal_summary: dict[str, Any] | None = None
    if journal is not None:
        replay = journal.replay()
        journal_summary = {
            "events": len(replay.events),
            "last_hash": replay.last_hash,
            "failures": replay.failures,
        }

    unsigned: dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "task_id": contract.task_id,
        "created_at": created_at,
        "contract_sha256": semantic_sha256(contract.as_dict()),
        "verdict": _result_summary(verdict),
        "artifacts": _artifact_manifest(contract, verdict, root_path),
        "journal": journal_summary,
    }
    receipt = {**unsigned, "receipt_sha256": semantic_sha256(unsigned)}
    return _validate_receipt_shape(receipt)


def _validate_verdict_summary(verdict: Any, *, task_id: str) -> None:
    if not isinstance(verdict, dict):
        raise ReceiptError("receipt verdict must be an object")
    required = {"task_id", "state", "status", "reason_code", "done", "evidence"}
    if set(verdict) != required or verdict["task_id"] != task_id:
        raise ReceiptError("receipt verdict has an invalid field set or task_id")
    state = verdict["state"]
    status = verdict["status"]
    reason = verdict["reason_code"]
    if state not in {"DONE", "WAITING", "FAILED", "REJECTED"}:
        raise ReceiptError("receipt verdict state is invalid")
    if status not in {"verified", "blocked"}:
        raise ReceiptError("receipt verdict status is invalid")
    if not isinstance(reason, str) or not reason or len(reason) > 128:
        raise ReceiptError("receipt verdict reason_code is invalid")
    if not isinstance(verdict["done"], bool):
        raise ReceiptError("receipt verdict done flag must be boolean")
    logical_done = state == "DONE" and status == "verified"
    if verdict["done"] is not logical_done:
        raise ReceiptError("receipt verdict done flag contradicts state or status")
    expected_reasons = {
        "DONE": {"ALL_EVIDENCE_VERIFIED", "POLICY_SATISFIED"},
        "WAITING": {"EVIDENCE_INCOMPLETE"},
        "FAILED": {"EVIDENCE_FAILED"},
        "REJECTED": {"ROOT_INVALID", "CIRCUIT_OPEN"},
    }
    if reason not in expected_reasons[state]:
        raise ReceiptError("receipt verdict reason_code contradicts state")

    evidence_items = verdict["evidence"]
    if not isinstance(evidence_items, list) or not evidence_items or len(evidence_items) > MAX_EVIDENCE:
        raise ReceiptError("receipt verdict evidence must be a non-empty bounded array")
    seen_evidence: set[str] = set()
    evidence_fields = {"id", "type", "classification", "passed", "code", "details_sha256"}
    passed_count = 0
    for index, evidence in enumerate(evidence_items):
        if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
            raise ReceiptError(f"receipt verdict evidence[{index}] has an invalid field set")
        identifier = evidence["id"]
        if (
            not isinstance(identifier, str)
            or not identifier
            or len(identifier) > 128
            or identifier in seen_evidence
        ):
            raise ReceiptError(f"receipt verdict evidence[{index}].id is invalid or duplicated")
        seen_evidence.add(identifier)
        for key in ("type", "code"):
            value = evidence[key]
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ReceiptError(f"receipt verdict evidence[{index}].{key} is invalid")
        classification = evidence["classification"]
        if classification not in {"proof", "inference", "blockage"}:
            raise ReceiptError(f"receipt verdict evidence[{index}].classification is invalid")
        if not isinstance(evidence["passed"], bool):
            raise ReceiptError(f"receipt verdict evidence[{index}].passed must be boolean")
        if evidence["passed"] is not (classification == "proof"):
            raise ReceiptError(f"receipt verdict evidence[{index}] classification contradicts passed")
        if evidence["passed"] is not (evidence["code"] == "EVIDENCE_VERIFIED"):
            raise ReceiptError(f"receipt verdict evidence[{index}] code contradicts passed")
        passed_count += int(evidence["passed"])
        digest = evidence["details_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ReceiptError(f"receipt verdict evidence[{index}].details_sha256 is invalid")

    if state == "DONE" and passed_count == 0:
        raise ReceiptError("receipt verdict completion has no verified evidence")
    if reason == "ALL_EVIDENCE_VERIFIED" and passed_count != len(evidence_items):
        raise ReceiptError("receipt verdict completion contradicts its all-evidence reason")
    if state != "DONE" and passed_count == len(evidence_items):
        raise ReceiptError("receipt blocked verdict contradicts fully verified evidence")


def _validate_receipt_shape(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt root must be an object")
    expected_fields = {
        "receipt_version",
        "task_id",
        "created_at",
        "contract_sha256",
        "verdict",
        "artifacts",
        "journal",
        "receipt_sha256",
    }
    if set(receipt) != expected_fields:
        raise ReceiptError("receipt has an invalid field set")
    if receipt["receipt_version"] != RECEIPT_VERSION:
        raise ReceiptError(f"receipt_version must be {RECEIPT_VERSION}")
    if not isinstance(receipt["task_id"], str) or not receipt["task_id"] or len(receipt["task_id"]) > 128:
        raise ReceiptError("receipt task_id is invalid")
    if not isinstance(receipt["created_at"], str) or not receipt["created_at"].endswith("Z"):
        raise ReceiptError("receipt created_at is invalid")
    for key in ("contract_sha256", "receipt_sha256"):
        value = receipt[key]
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ReceiptError(f"receipt {key} is not a lowercase SHA-256 digest")
    _validate_verdict_summary(receipt["verdict"], task_id=receipt["task_id"])
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise ReceiptError("receipt artifacts must be a bounded array")
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ReceiptError("receipt artifact has an invalid field set")
        path = item["path"]
        if not isinstance(path, str) or not path or path in seen:
            raise ReceiptError("receipt artifact path is invalid or duplicated")
        _relative_path(path)
        seen.add(path)
        if isinstance(item["size"], bool) or not isinstance(item["size"], int) or not 0 <= item["size"] <= MAX_ARTIFACT_BYTES:
            raise ReceiptError("receipt artifact size is invalid")
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ReceiptError("receipt artifact sha256 is invalid")
    journal = receipt["journal"]
    if journal is not None:
        if not isinstance(journal, dict) or set(journal) != {"events", "last_hash", "failures"}:
            raise ReceiptError("receipt journal summary is invalid")
        events = journal["events"]
        failures = journal["failures"]
        if (
            type(events) is not int
            or type(failures) is not int
            or events < 0
            or failures < 0
            or failures > events
        ):
            raise ReceiptError("receipt journal counters are invalid")
        last_hash = journal["last_hash"]
        if not isinstance(last_hash, str) or len(last_hash) != 64 or any(
            char not in "0123456789abcdef" for char in last_hash
        ):
            raise ReceiptError("receipt journal last_hash is invalid")
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_sha256")
    if semantic_sha256(unsigned) != claimed:
        raise ReceiptError("receipt hash mismatch")
    return receipt


def _load_receipt_bytes(encoded: bytes) -> dict[str, Any]:
    try:
        raw = strict_loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except ReceiptError:
        raise
    except (UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
        raise ReceiptError(f"invalid receipt JSON: {exc}") from exc
    return _validate_receipt_shape(raw)


def load_receipt_under_root(root: str | Path, relative: str) -> dict[str, Any]:
    _relative_path(relative)
    try:
        encoded = read_regular_file(root, relative, maximum=MAX_RECEIPT_BYTES)
    except FileBoundError as exc:
        raise ReceiptError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes") from exc
    return _load_receipt_bytes(encoded)


def load_receipt(path: str | Path) -> dict[str, Any]:
    receipt_path = Path(path)
    parent = receipt_path.parent if receipt_path.parent != Path("") else Path(".")
    try:
        encoded = read_regular_file(parent, receipt_path.name, maximum=MAX_RECEIPT_BYTES)
    except FileBoundError as exc:
        raise ReceiptError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes") from exc
    except (OSError, UnsafePathError) as exc:
        raise ReceiptError(f"invalid receipt JSON: {exc}") from exc
    return _load_receipt_bytes(encoded)


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    code: str
    message: str
    artifacts_verified: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "code": self.code,
            "message": self.message,
            "artifacts_verified": self.artifacts_verified,
        }


def verify_receipt(
    receipt: dict[str, Any],
    *,
    root: str | Path | None = None,
    verify_artifacts: bool = True,
) -> ReceiptVerification:
    _validate_receipt_shape(receipt)
    if not verify_artifacts:
        return ReceiptVerification(True, "RECEIPT_VERIFIED", "receipt hash and schema verified", 0)
    if root is None:
        return ReceiptVerification(False, "ROOT_REQUIRED", "artifact verification requires a root", 0)
    root_path = Path(root)
    if not root_path.is_dir():
        return ReceiptVerification(False, "ROOT_INVALID", "artifact verification root is invalid", 0)
    verified = 0
    for artifact in receipt["artifacts"]:
        relative = artifact["path"]
        try:
            size, digest = _hash_file(root_path, relative)
        except FileNotFoundError:
            return ReceiptVerification(False, "ARTIFACT_MISSING", f"artifact is missing: {relative}", verified)
        except UnsafePathError as exc:
            return ReceiptVerification(False, "UNSAFE_ARTIFACT_PATH", str(exc), verified)
        except ReceiptError as exc:
            return ReceiptVerification(False, "ARTIFACT_UNREADABLE", str(exc), verified)
        if size != artifact["size"]:
            return ReceiptVerification(False, "ARTIFACT_SIZE_MISMATCH", f"artifact size changed: {relative}", verified)
        if digest != artifact["sha256"]:
            return ReceiptVerification(False, "ARTIFACT_HASH_MISMATCH", f"artifact digest changed: {relative}", verified)
        verified += 1
    return ReceiptVerification(True, "RECEIPT_VERIFIED", "receipt and artifacts verified", verified)


def write_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    """Atomically write a receipt after validating its self-hash."""

    _validate_receipt_shape(receipt)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    encoded = strict_dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ReceiptError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ReceiptError(f"cannot write receipt: {exc}") from exc
