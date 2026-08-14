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


if __name__ == "__main__":
    unittest.main()

