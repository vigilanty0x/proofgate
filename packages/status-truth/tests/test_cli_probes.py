from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from status_truth.cli import main
from status_truth.probes import functional_counter_proof, liveness, readiness

ROOT = Path(__file__).resolve().parents[1]


class ProbeTests(unittest.TestCase):
    def test_liveness(self):
        self.assertEqual(liveness()["ok"], True)

    def test_readiness_on_empty_path(self):
        with TemporaryDirectory() as directory:
            result = readiness(Path(directory) / "journal.jsonl")
            self.assertTrue(result["ok"])
            self.assertEqual(result["entries"], 0)

    def test_functional_counter_proof(self):
        result = functional_counter_proof()
        self.assertTrue(result["ok"])
        self.assertEqual(result["control_state"], "healthy")
        self.assertEqual(result["counter_proof_state"], "failed")
        self.assertFalse(result["failure_success"])
        self.assertTrue(result["idempotent_replay"])
        self.assertTrue(result["conflict_detected"])


class CliTests(unittest.TestCase):
    def run_cli(self, args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_healthy_assessment_returns_zero(self):
        with TemporaryDirectory() as directory:
            code, output, error = self.run_cli([
                "assess", "--input", str(ROOT / "examples/healthy.json"),
                "--journal", str(Path(directory) / "j.jsonl"),
            ])
            self.assertEqual(code, 0, error)
            self.assertTrue(json.loads(output)["record"]["success"])

    def test_failure_assessment_returns_two(self):
        with TemporaryDirectory() as directory:
            code, output, _ = self.run_cli([
                "assess", "--input", str(ROOT / "examples/failure.json"),
                "--journal", str(Path(directory) / "j.jsonl"),
            ])
            self.assertEqual(code, 2)
            self.assertFalse(json.loads(output)["record"]["success"])

    def test_verify_command(self):
        with TemporaryDirectory() as directory:
            journal = Path(directory) / "j.jsonl"
            self.run_cli(["assess", "--input", str(ROOT / "examples/healthy.json"), "--journal", str(journal)])
            code, output, _ = self.run_cli(["verify", "--journal", str(journal)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["entries"], 1)

    def test_probe_command(self):
        code, output, _ = self.run_cli(["probe", "functional"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["ok"])

    def test_invalid_json_is_structured_error(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("not-json")
            code, _, error = self.run_cli(["assess", "--input", str(path), "--journal", str(Path(directory) / "j")])
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(error)["success"])

    def test_non_object_input_is_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("[]")
            code, _, error = self.run_cli(["assess", "--input", str(path), "--journal", str(Path(directory) / "j")])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(error)["error"], "ContractError")

    def test_oversize_input_is_rejected_before_parse(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_text(" " * 1_000_001)
            code, _, error = self.run_cli(["assess", "--input", str(path), "--journal", str(Path(directory) / "j")])
            self.assertEqual(code, 1)
            self.assertIn("exceeds", json.loads(error)["message"])


if __name__ == "__main__":
    unittest.main()
