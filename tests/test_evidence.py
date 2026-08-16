from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from proofgate.contract import EvidenceRule
from proofgate.evidence import MAX_CAPTURE_BYTES, evaluate_command, evaluate_directory, evaluate_file, evaluate_json, evaluate_text


class EvidenceTests(unittest.TestCase):
    def test_file_size_and_hash_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"artifact\n"
            (root / "artifact.txt").write_bytes(content)
            rule = EvidenceRule(
                "artifact",
                "file",
                {"path": "artifact.txt", "min_bytes": 1, "sha256": hashlib.sha256(content).hexdigest()},
            )
            result = evaluate_file(rule, root)
            self.assertTrue(result.passed)
            self.assertEqual(result.classification, "proof")

    def test_wrong_hash_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("content", encoding="utf-8")
            rule = EvidenceRule("artifact", "file", {"path": "artifact.txt", "sha256": "0" * 64})
            self.assertEqual(evaluate_file(rule, root).code, "HASH_MISMATCH")

    def test_missing_file_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rule = EvidenceRule("artifact", "file", {"path": "missing", "min_bytes": 1})
            self.assertEqual(evaluate_file(rule, Path(directory)).code, "FILE_MISSING")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_escape_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as outer, tempfile.TemporaryDirectory() as inner:
            secret = Path(outer) / "secret.txt"
            secret.write_text("outside", encoding="utf-8")
            (Path(inner) / "link.txt").symlink_to(secret)
            rule = EvidenceRule("artifact", "file", {"path": "link.txt", "min_bytes": 1})
            self.assertEqual(evaluate_file(rule, Path(inner)).code, "UNSAFE_PATH")

    def test_json_pointer_value_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text(json.dumps({"checks": [{"passed": True}]}), encoding="utf-8")
            rule = EvidenceRule("report", "json", {"path": "report.json", "pointer": "/checks/0/passed", "equals": True})
            self.assertTrue(evaluate_json(rule, root).passed)

    def test_json_type_mismatch_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text('{"value":1}', encoding="utf-8")
            rule = EvidenceRule("report", "json", {"path": "report.json", "pointer": "/value", "equals": True})
            self.assertEqual(evaluate_json(rule, root).code, "JSON_VALUE_MISMATCH")

    def test_json_nested_type_mismatch_is_blocked_recursively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text(
                '{"checks":[{"passed":1}],"totals":{"failed":false}}',
                encoding="utf-8",
            )
            rule = EvidenceRule(
                "report",
                "json",
                {
                    "path": "report.json",
                    "pointer": "",
                    "equals": {
                        "checks": [{"passed": True}],
                        "totals": {"failed": 0},
                    },
                },
            )
            self.assertEqual(evaluate_json(rule, root).code, "JSON_VALUE_MISMATCH")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX no-follow opens")
    def test_concurrent_intermediate_path_replacement_cannot_redirect_file_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            trusted = b"trusted\n"
            (nested / "artifact.txt").write_bytes(trusted)
            outside = root / "outside"
            outside.mkdir()
            (outside / "artifact.txt").write_bytes(b"untrusted\n")
            held = root / "held"
            real_open = os.open
            replaced = False

            def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal replaced
                descriptor = real_open(path, flags, *args, **kwargs)
                if path == "nested" and flags & os.O_DIRECTORY and not replaced:
                    nested.rename(held)
                    nested.symlink_to(outside, target_is_directory=True)
                    replaced = True
                return descriptor

            rule = EvidenceRule(
                "artifact",
                "file",
                {
                    "path": "nested/artifact.txt",
                    "sha256": hashlib.sha256(trusted).hexdigest(),
                },
            )
            with patch("proofgate.safeio.os.open", side_effect=racing_open):
                result = evaluate_file(rule, root)
            self.assertTrue(replaced)
            self.assertTrue(result.passed)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_internal_symlink_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real.txt").write_text("inside", encoding="utf-8")
            (root / "alias.txt").symlink_to(root / "real.txt")
            rule = EvidenceRule("artifact", "file", {"path": "alias.txt", "min_bytes": 1})
            self.assertEqual(evaluate_file(rule, root).code, "UNSAFE_PATH")

    def test_command_success_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rule = EvidenceRule("command", "command", {"command": [sys.executable, "-c", "print('ok')"], "expect_exit": 0})
            result = evaluate_command(rule, Path(directory), 2)
            self.assertTrue(result.passed)
            self.assertEqual(result.details["stdout"], "ok\n")

    def test_command_failure_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rule = EvidenceRule("command", "command", {"command": [sys.executable, "-c", "raise SystemExit(7)"], "expect_exit": 0})
            result = evaluate_command(rule, Path(directory), 2)
            self.assertFalse(result.passed)
            self.assertEqual(result.code, "COMMAND_EXIT_MISMATCH")

    def test_command_timeout_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rule = EvidenceRule(
                "command",
                "command",
                {"command": [sys.executable, "-c", "import time; time.sleep(2)"], "timeout_seconds": 1},
            )
            self.assertEqual(evaluate_command(rule, Path(directory), 1).code, "COMMAND_TIMEOUT")

    def test_command_capture_is_memory_bounded_and_keeps_tail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rule = EvidenceRule(
                "command",
                "command",
                {
                    "command": [
                        sys.executable,
                        "-c",
                        f"import sys; sys.stdout.write('x' * {MAX_CAPTURE_BYTES + 100} + 'TAIL')",
                    ]
                },
            )
            result = evaluate_command(rule, Path(directory), 2)
            self.assertTrue(result.passed)
            self.assertEqual(len(result.details["stdout"].encode("utf-8")), MAX_CAPTURE_BYTES)
            self.assertTrue(result.details["stdout"].endswith("TAIL"))
            self.assertTrue(result.details["stdout_truncated"])
            self.assertEqual(result.details["stdout_bytes"], MAX_CAPTURE_BYTES + 104)

    @unittest.skipUnless(os.name == "posix" and Path("/proc").is_dir(), "requires Linux process inspection")
    def test_timeout_stops_session_detached_descendant_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            grandchild = (
                "import os,pathlib,time; os.setsid(); "
                "pathlib.Path('escaped.pid').write_text(str(os.getpid())); time.sleep(3)"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]); time.sleep(3)"
            )
            rule = EvidenceRule(
                "command",
                "command",
                {"command": [sys.executable, "-c", parent], "timeout_seconds": 1},
            )
            started = time.monotonic()
            result = evaluate_command(rule, root, 1)
            elapsed = time.monotonic() - started
            escaped_pid = int((root / "escaped.pid").read_text(encoding="utf-8"))
            process_state = Path(f"/proc/{escaped_pid}/stat")
            try:
                alive = process_state.read_text(encoding="utf-8").split()[2] != "Z"
            except OSError:
                alive = False
            if alive:  # Cleanup if the regression returns before the detached process.
                os.kill(escaped_pid, signal.SIGKILL)
            self.assertEqual(result.code, "COMMAND_TIMEOUT")
            self.assertLess(elapsed, 2.5)
            self.assertFalse(alive)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process sessions")
    def test_daemonized_descendant_cannot_be_reported_as_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            grandchild = (
                "import os,pathlib,time; os.setsid(); "
                "pathlib.Path('daemon.pid').write_text(str(os.getpid())); time.sleep(3)"
            )
            parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{grandchild!r}])"
            rule = EvidenceRule("command", "command", {"command": [sys.executable, "-c", parent]})
            result = evaluate_command(rule, root, 2)
            daemon_pid = int((root / "daemon.pid").read_text(encoding="utf-8"))
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.assertFalse(result.passed)
            self.assertEqual(result.code, "COMMAND_CLEANUP_INCOMPLETE")

    def test_json_evidence_rejects_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text('{"value":NaN}', encoding="utf-8")
            rule = EvidenceRule("report", "json", {"path": "report.json", "pointer": "/value", "equals": 1})
            self.assertEqual(evaluate_json(rule, root).code, "JSON_INVALID")

    def test_text_requires_every_literal_without_leaking_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Install safely\nSECURITY policy\n", encoding="utf-8")
            rule = EvidenceRule("docs", "text", {"path": "README.md", "contains": ["install", "security"], "case_sensitive": False})
            result = evaluate_text(rule, root)
            self.assertTrue(result.passed)
            self.assertNotIn("Install safely", json.dumps(result.as_dict()))

    def test_directory_count_is_bounded_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_text("", encoding="utf-8")
            (root / "src" / "b.py").write_text("", encoding="utf-8")
            (root / "src" / "note.txt").write_text("", encoding="utf-8")
            rule = EvidenceRule("tree", "directory", {"path": "src", "pattern": "*.py", "min_files": 2, "max_files": 2})
            result = evaluate_directory(rule, root)
            self.assertTrue(result.passed)
            self.assertEqual(result.details["files"], ["src/a.py", "src/b.py"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_directory_inventory_rejects_internal_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "real.py").write_text("", encoding="utf-8")
            (root / "src" / "alias.py").symlink_to(root / "src" / "real.py")
            rule = EvidenceRule("tree", "directory", {"path": "src", "pattern": "*.py"})
            self.assertEqual(evaluate_directory(rule, root).code, "UNSAFE_PATH")


if __name__ == "__main__":
    unittest.main()
