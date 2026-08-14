from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from proofgate.contract import EvidenceRule
from proofgate.evidence import evaluate_command, evaluate_file, evaluate_json


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


if __name__ == "__main__":
    unittest.main()

