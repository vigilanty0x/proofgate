"""Evidence evaluators used by the state machine."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Any

from .contract import EvidenceRule
from .jsonutil import StrictJSONError, strict_json_equal, strict_loads
from .safeio import (
    FileBoundError,
    UnsafePathError,
    hash_regular_file,
    read_regular_file,
    stat_regular_file,
    walk_regular_files,
)

MAX_CAPTURE_BYTES = 64 * 1024
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
PROCESS_CLEANUP_SECONDS = 1.0
PROCESS_SCAN_SECONDS = 0.25


class _TailCapture:
    """Drain one child pipe while retaining only a bounded diagnostic tail."""

    def __init__(self, maximum: int = MAX_CAPTURE_BYTES):
        self.maximum = maximum
        self.buffer = bytearray()
        self.total = 0

    def drain(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                self.total += len(chunk)
                self.buffer.extend(chunk)
                overflow = len(self.buffer) - self.maximum
                if overflow > 0:
                    del self.buffer[:overflow]
        except (OSError, ValueError):
            # A timed-out process can invalidate its pipe while the reader drains.
            return
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    @property
    def text(self) -> str:
        # Stable machine-readable evidence should not change merely because the
        # child process ran on Windows.  Byte counters remain raw/unmodified.
        return bytes(self.buffer).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")

    @property
    def truncated(self) -> bool:
        return self.total > len(self.buffer)


def _linux_descendants(parent_pid: int) -> set[int]:
    """Snapshot descendants before their parent is killed and they are re-parented."""

    proc = Path("/proc")
    if not proc.is_dir():
        return set()
    children: dict[int, list[int]] = {}
    try:
        entries = list(proc.iterdir())
    except OSError:
        return set()
    deadline = time.monotonic() + PROCESS_SCAN_SECONDS
    for entry in entries:
        if time.monotonic() >= deadline:
            break
        if not entry.name.isdigit():
            continue
        try:
            lines = (entry / "status").read_text(encoding="utf-8").splitlines()
            ppid_line = next(line for line in lines if line.startswith("PPid:"))
            ppid = int(ppid_line.split()[1])
            pid = int(entry.name)
        except (OSError, StopIteration, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(pid)
    descendants: set[int] = set()
    pending = [parent_pid]
    while pending:
        current = pending.pop()
        for child in children.get(current, []):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop a timed-out command and its observable process tree."""

    descendants = _linux_descendants(process.pid) if os.name == "posix" else set()
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=PROCESS_CLEANUP_SECONDS,
                check=False,
            )
        else:
            process.kill()
    except (OSError, ProcessLookupError, subprocess.SubprocessError):
        pass
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


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


def _blocked(rule: EvidenceRule, code: str, message: str, **details: Any) -> EvidenceResult:
    return EvidenceResult(rule.id, rule.type, "blockage", False, code, message, details)


def _proof(rule: EvidenceRule, message: str, **details: Any) -> EvidenceResult:
    return EvidenceResult(rule.id, rule.type, "proof", True, "EVIDENCE_VERIFIED", message, details)


def evaluate_file(rule: EvidenceRule, root: Path) -> EvidenceResult:
    relative = rule.config["path"]
    expected = rule.config.get("sha256")
    try:
        if expected is None:
            size = stat_regular_file(root, relative).st_size
            actual = None
        else:
            file_digest = hash_regular_file(root, relative, maximum=MAX_EVIDENCE_FILE_BYTES)
            size = file_digest.size
            actual = file_digest.sha256
    except FileNotFoundError:
        return _blocked(rule, "FILE_MISSING", "required file does not exist", path=relative)
    except UnsafePathError as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    except FileBoundError:
        return _blocked(rule, "FILE_TOO_LARGE", "file is too large to hash", path=relative)
    except OSError as exc:
        return _blocked(rule, "FILE_UNREADABLE", str(exc), path=relative)
    minimum = rule.config.get("min_bytes", 1)
    if size < minimum:
        return _blocked(rule, "FILE_TOO_SMALL", "file is smaller than min_bytes", path=relative, size=size)
    if expected is not None:
        assert actual is not None
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
        raw = read_regular_file(root, relative, maximum=MAX_EVIDENCE_FILE_BYTES)
    except FileNotFoundError:
        return _blocked(rule, "JSON_MISSING", "required JSON file does not exist", path=relative)
    except UnsafePathError as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    except FileBoundError:
        return _blocked(rule, "JSON_TOO_LARGE", "JSON evidence is too large", path=relative)
    except OSError as exc:
        return _blocked(rule, "JSON_INVALID", str(exc), path=relative)
    try:
        document = strict_loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
        return _blocked(rule, "JSON_INVALID", str(exc), path=relative)
    pointer = rule.config["pointer"]
    try:
        actual = _pointer(document, pointer)
    except (KeyError, IndexError) as exc:
        return _blocked(rule, "JSON_POINTER_MISSING", str(exc), path=relative, pointer=pointer)
    expected = rule.config["equals"]
    if not strict_json_equal(actual, expected):
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


def evaluate_text(rule: EvidenceRule, root: Path) -> EvidenceResult:
    """Verify bounded literal text requirements without returning file contents."""

    relative = rule.config["path"]
    try:
        raw = read_regular_file(root, relative, maximum=MAX_EVIDENCE_FILE_BYTES)
        size = len(raw)
        content = raw.decode("utf-8")
    except FileNotFoundError:
        return _blocked(rule, "TEXT_MISSING", "required text file does not exist", path=relative)
    except UnsafePathError as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    except FileBoundError as exc:
        return _blocked(rule, "TEXT_TOO_LARGE", "text evidence is too large", path=relative, size=exc.observed)
    except (OSError, UnicodeError) as exc:
        return _blocked(rule, "TEXT_UNREADABLE", str(exc), path=relative)

    needles = rule.config["contains"]
    if isinstance(needles, str):
        needles = [needles]
    case_sensitive = rule.config.get("case_sensitive", True)
    minimum = rule.config.get("min_occurrences", 1)
    searchable = content if case_sensitive else content.casefold()
    counts: dict[str, int] = {}
    missing: list[str] = []
    for needle in needles:
        query = needle if case_sensitive else needle.casefold()
        count = searchable.count(query)
        counts[needle] = count
        if count < minimum:
            missing.append(needle)
    digest = hashlib.sha256(raw).hexdigest()
    if missing:
        return _blocked(
            rule,
            "TEXT_LITERAL_MISSING",
            "one or more required literals did not meet min_occurrences",
            path=relative,
            size=size,
            sha256=digest,
            min_occurrences=minimum,
            matches=counts,
            missing=missing,
        )
    return _proof(
        rule,
        "text evidence verified",
        path=relative,
        size=size,
        sha256=digest,
        min_occurrences=minimum,
        matches=counts,
    )


def evaluate_directory(rule: EvidenceRule, root: Path) -> EvidenceResult:
    """Verify a bounded file inventory underneath a directory."""

    relative = rule.config["path"]
    try:
        inventory = walk_regular_files(root, relative, maximum_entries=10000)
    except FileNotFoundError:
        return _blocked(rule, "DIRECTORY_MISSING", "required directory does not exist", path=relative)
    except UnsafePathError as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    except FileBoundError:
        return _blocked(
            rule,
            "DIRECTORY_LIMIT_EXCEEDED",
            "directory inventory exceeded the hard entry bound",
            path=relative,
        )
    except OSError as exc:
        return _blocked(rule, "DIRECTORY_UNREADABLE", str(exc), path=relative)
    pattern = rule.config.get("pattern", "*")
    minimum = rule.config.get("min_files", 1)
    maximum = rule.config.get("max_files", 10000)
    matches: list[str] = []
    prefix = relative.replace("\\", "/").strip("/")
    if prefix == ".":
        prefix = ""
    for within in inventory:
        name = within.rsplit("/", 1)[-1]
        if fnmatch.fnmatchcase(within, pattern) or fnmatch.fnmatchcase(name, pattern):
            matches.append(f"{prefix}/{within}" if prefix else within)
            if len(matches) > 10000:
                return _blocked(
                    rule,
                    "DIRECTORY_LIMIT_EXCEEDED",
                    "directory inventory exceeded the hard file bound",
                    path=relative,
                )
    matches.sort()
    count = len(matches)
    details = {
        "path": relative,
        "pattern": pattern,
        "count": count,
        "min_files": minimum,
        "max_files": maximum,
        "files": matches[:256],
        "files_truncated": count > 256,
    }
    if count < minimum:
        return _blocked(rule, "DIRECTORY_TOO_FEW_FILES", "directory has fewer matching files than required", **details)
    if count > maximum:
        return _blocked(rule, "DIRECTORY_TOO_MANY_FILES", "directory has more matching files than allowed", **details)
    return _proof(rule, "directory evidence verified", **details)


def evaluate_receipt(rule: EvidenceRule, root: Path) -> EvidenceResult:
    """Verify a nested ProofGate receipt and, by default, its artifacts."""

    relative = rule.config["path"]
    try:
        from .receipt import load_receipt_under_root, verify_receipt

        receipt = load_receipt_under_root(root, relative)
        expected = rule.config.get("expected_task_id")
        if expected is not None and receipt["task_id"] != expected:
            return _blocked(
                rule,
                "RECEIPT_TASK_MISMATCH",
                "receipt task_id does not match the contract",
                path=relative,
                expected_task_id=expected,
                actual_task_id=receipt["task_id"],
            )
        verification = verify_receipt(
            receipt,
            root=root,
            verify_artifacts=rule.config.get("verify_artifacts", True),
        )
    except FileNotFoundError:
        return _blocked(rule, "RECEIPT_MISSING", "required receipt does not exist", path=relative)
    except UnsafePathError as exc:
        return _blocked(rule, "UNSAFE_PATH", str(exc), path=relative)
    except (OSError, ValueError) as exc:
        return _blocked(rule, "RECEIPT_INVALID", str(exc), path=relative)
    if not verification.valid:
        return _blocked(
            rule,
            verification.code,
            verification.message,
            path=relative,
            receipt_sha256=receipt.get("receipt_sha256"),
            artifacts_verified=verification.artifacts_verified,
        )
    if receipt["verdict"]["done"] is not True:
        return _blocked(
            rule,
            "RECEIPT_NOT_DONE",
            "receipt is internally valid but does not attest verified completion",
            path=relative,
            task_id=receipt["task_id"],
            receipt_state=receipt["verdict"]["state"],
            receipt_status=receipt["verdict"]["status"],
            receipt_sha256=receipt["receipt_sha256"],
            artifacts_verified=verification.artifacts_verified,
        )
    return _proof(
        rule,
        "nested receipt verified",
        path=relative,
        task_id=receipt["task_id"],
        receipt_sha256=receipt["receipt_sha256"],
        artifacts_verified=verification.artifacts_verified,
    )


def evaluate_command(rule: EvidenceRule, root: Path, global_timeout: int) -> EvidenceResult:
    command = rule.config["command"]
    timeout = min(rule.config.get("timeout_seconds", global_timeout), global_timeout)
    try:
        process = subprocess.Popen(
            command,
            cwd=root.resolve(),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        return _blocked(rule, "COMMAND_START_FAILED", str(exc), command=command)

    stdout_capture = _TailCapture()
    stderr_capture = _TailCapture()
    stdout_thread = threading.Thread(target=stdout_capture.drain, args=(process.stdout,), daemon=True)
    stderr_thread = threading.Thread(target=stderr_capture.drain, args=(process.stderr,), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _stop_process(process)
        try:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=PROCESS_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                pass
    finally:
        cleanup_deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
        for reader in (stdout_thread, stderr_thread):
            reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
        # Each reader owns and closes its stream. Closing a buffered pipe from this
        # thread while another thread is blocked in read() can wait indefinitely.

    details = {
        "command": command,
        "timeout_seconds": timeout,
        "stdout": stdout_capture.text,
        "stderr": stderr_capture.text,
        "stdout_bytes": stdout_capture.total,
        "stderr_bytes": stderr_capture.total,
        "stdout_truncated": stdout_capture.truncated,
        "stderr_truncated": stderr_capture.truncated,
        "reader_cleanup_incomplete": stdout_thread.is_alive() or stderr_thread.is_alive(),
    }
    if timed_out:
        return _blocked(
            rule,
            "COMMAND_TIMEOUT",
            f"command exceeded {timeout} seconds",
            **details,
        )
    expected = rule.config.get("expect_exit", 0)
    details.update({"expected_exit": expected, "actual_exit": process.returncode})
    if details["reader_cleanup_incomplete"]:
        return _blocked(
            rule,
            "COMMAND_CLEANUP_INCOMPLETE",
            "command exited but a descendant kept an output stream open",
            **details,
        )
    if process.returncode != expected:
        return _blocked(rule, "COMMAND_EXIT_MISMATCH", "command returned an unexpected exit code", **details)
    return _proof(rule, "command evidence verified", **details)
