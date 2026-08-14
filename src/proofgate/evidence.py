"""Evidence evaluators used by the state machine."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from .contract import EvidenceRule

MAX_CAPTURE_BYTES = 64 * 1024
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class EvidenceResult:
    id: str
    evidence_type: str
    classification: str
    passed: bool
    code: str
    message: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.evidence_type,
            "classification": self.classification,
            "passed": self.passed,
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


def _resolved(root: Path, relative: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / relative).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("path escapes the evaluation root")
    return candidate


def _blocked(rule: EvidenceRule, code: str, message: str, **details: Any) -> EvidenceResult:
    return EvidenceResult(rule.id, rule.type, "blockage", False, code, message, details)


def _proof(rule: EvidenceRule, message: str, **details: Any) -> EvidenceResult:
    return EvidenceResult(rule.id, rule.type, "proof", True, "EVIDENCE_VERIFIED", message, details)


def evaluate_file(rule: EvidenceRule, root: Path) -> EvidenceResult:
    relative = rule.config["path"]
    try:
        path = _resolved(root, relative)
    except (OSError, ValueError) as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    if not path.is_file():
        return _blocked(rule, "FILE_MISSING", "required file does not exist", path=relative)
    try:
        size = path.stat().st_size
    except OSError as exc:
        return _blocked(rule, "FILE_UNREADABLE", str(exc), path=relative)
    minimum = rule.config.get("min_bytes", 1)
    if size < minimum:
        return _blocked(rule, "FILE_TOO_SMALL", "file is smaller than min_bytes", path=relative, size=size)
    expected = rule.config.get("sha256")
    actual = None
    if expected is not None:
        if size > MAX_EVIDENCE_FILE_BYTES:
            return _blocked(rule, "FILE_TOO_LARGE", "file is too large to hash", path=relative, size=size)
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            return _blocked(rule, "FILE_UNREADABLE", str(exc), path=relative)
        actual = digest.hexdigest()
        if actual.lower() != expected.lower():
            return _blocked(
                rule,
                "HASH_MISMATCH",
                "file digest does not match the contract",
                path=relative,
                expected_sha256=expected.lower(),
                actual_sha256=actual,
            )
    return _proof(rule, "file evidence verified", path=relative, size=size, sha256=actual)


def _pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise KeyError(token)
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(token)
    return current


def evaluate_json(rule: EvidenceRule, root: Path) -> EvidenceResult:
    relative = rule.config["path"]
    try:
        path = _resolved(root, relative)
    except (OSError, ValueError) as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    if not path.is_file():
        return _blocked(rule, "JSON_MISSING", "required JSON file does not exist", path=relative)
    try:
        if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
            return _blocked(rule, "JSON_TOO_LARGE", "JSON evidence is too large", path=relative)
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _blocked(rule, "JSON_INVALID", str(exc), path=relative)
    pointer = rule.config["pointer"]
    try:
        actual = _pointer(document, pointer)
    except (KeyError, IndexError) as exc:
        return _blocked(rule, "JSON_POINTER_MISSING", str(exc), path=relative, pointer=pointer)
    expected = rule.config["equals"]
    if actual != expected or type(actual) is not type(expected):
        return _blocked(
            rule,
            "JSON_VALUE_MISMATCH",
            "JSON value does not equal the contracted value",
            path=relative,
            pointer=pointer,
            expected=expected,
            actual=actual,
        )
    return _proof(rule, "JSON evidence verified", path=relative, pointer=pointer, value=actual)


def evaluate_command(rule: EvidenceRule, root: Path, global_timeout: int) -> EvidenceResult:
    command = rule.config["command"]
    timeout = min(rule.config.get("timeout_seconds", global_timeout), global_timeout)
    try:
        completed = subprocess.run(
            command,
            cwd=root.resolve(),
            shell=False,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return _blocked(
            rule,
            "COMMAND_TIMEOUT",
            f"command exceeded {timeout} seconds",
            command=command,
            timeout_seconds=timeout,
            stdout=(exc.stdout or b"")[-MAX_CAPTURE_BYTES:].decode("utf-8", "replace"),
            stderr=(exc.stderr or b"")[-MAX_CAPTURE_BYTES:].decode("utf-8", "replace"),
        )
    except OSError as exc:
        return _blocked(rule, "COMMAND_START_FAILED", str(exc), command=command)
    expected = rule.config.get("expect_exit", 0)
    details = {
        "command": command,
        "expected_exit": expected,
        "actual_exit": completed.returncode,
        "stdout": completed.stdout[-MAX_CAPTURE_BYTES:].decode("utf-8", "replace"),
        "stderr": completed.stderr[-MAX_CAPTURE_BYTES:].decode("utf-8", "replace"),
    }
    if completed.returncode != expected:
        return _blocked(rule, "COMMAND_EXIT_MISMATCH", "command returned an unexpected exit code", **details)
    return _proof(rule, "command evidence verified", **details)

