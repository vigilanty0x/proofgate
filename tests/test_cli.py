from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from proofgate.cli import main


class CliTests(unittest.TestCase):
    def test_init_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proofgate.json"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["init", str(path)]), 0)
                self.assertEqual(main(["validate", str(path), "--json"]), 0)
            self.assertIn('"valid":true', output.getvalue())

    def test_check_returns_two_when_command_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proofgate.json"
            main(["init", str(path)])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["check", str(path), "--root", directory, "--json"]), 2)

    def test_run_requires_and_records_idempotency_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = {
                "contract_version": "1.0",
                "task": {"id": "cli-demo", "terminal_state": "DONE"},
                "evidence": [{"id": "artifact", "type": "file", "path": "artifact.txt"}],
            }
            (root / "artifact.txt").write_text("ok", encoding="utf-8")
            path = root / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            journal = root / "events.jsonl"
            with redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "run",
                        str(path),
                        "--root",
                        directory,
                        "--journal",
                        str(journal),
                        "--idempotency-key",
                        "cli-1",
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(journal.exists())

    def test_invalid_contract_returns_three(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{}", encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["validate", str(path), "--json"]), 3)

    def test_invalid_invocation_returns_three_as_json(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(main(["run", "contract.json", "--json"]), 3)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["error"], "UsageError")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["unknown", "--json"]), 3)

    def test_replay_rejects_missing_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.jsonl"
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["replay", str(missing), "--json"]), 3)
            self.assertFalse(missing.exists())

    def test_blocked_receipt_cannot_make_downstream_cli_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = {
                "contract_version": "1.0",
                "task": {"id": "upstream", "terminal_state": "DONE"},
                "evidence": [{"id": "missing", "type": "file", "path": "missing.txt"}],
            }
            downstream = {
                "contract_version": "1.0",
                "task": {"id": "downstream", "terminal_state": "DONE"},
                "evidence": [
                    {"id": "prior", "type": "receipt", "path": "blocked.json", "expected_task_id": "upstream"}
                ],
            }
            (root / "up.json").write_text(json.dumps(upstream), encoding="utf-8")
            (root / "down.json").write_text(json.dumps(downstream), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "receipt",
                            str(root / "up.json"),
                            "--root",
                            str(root),
                            "--output",
                            str(root / "blocked.json"),
                            "--json",
                        ]
                    ),
                    2,
                )
                self.assertEqual(main(["check", str(root / "down.json"), "--root", str(root), "--json"]), 2)

    def test_receipt_verify_suite_diff_and_explain_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("ok", encoding="utf-8")
            contract = {
                "contract_version": "1.0",
                "task": {"id": "release", "terminal_state": "DONE"},
                "evidence": [{"id": "artifact", "type": "file", "path": "artifact.txt"}],
            }
            contract_path = root / "contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            receipt_path = root / "receipt.json"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["receipt", str(contract_path), "--root", str(root), "--output", str(receipt_path), "--json"]), 0)
                self.assertEqual(main(["verify-receipt", str(receipt_path), "--root", str(root), "--json"]), 0)
                self.assertEqual(main(["explain", "ALL_EVIDENCE_VERIFIED", "--json"]), 0)
            self.assertIn('"receipt_sha256"', output.getvalue())

            suite_path = root / "suite.json"
            suite_path.write_text(json.dumps({"suite_version":"1.0","id":"demo","contracts":[{"id":"release","path":"contract.json"}]}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["suite", str(suite_path), "--root", str(root), "--json"]), 0)

            before = root / "before.json"
            after = root / "after.json"
            value = {"task_id":"x","state":"DONE","status":"verified","reason_code":"ok","evidence":[]}
            before.write_text(json.dumps(value), encoding="utf-8")
            after.write_text(json.dumps(value), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["diff", str(before), str(after), "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
