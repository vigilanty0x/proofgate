from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from trustkit.cli import main
from trustkit.core import Category, Finding, FindingState, Severity, Verdict, evaluate
from trustkit.redaction import redact


class EvaluationTests(unittest.TestCase):
    def test_pass_requires_complete_measurement(self) -> None:
        result = evaluate([], measurement_complete=True)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_active_finding_fails(self) -> None:
        result = evaluate(
            [Finding("sec-1", Category.SECRET, Severity.CRITICAL, "sha256:abc")],
            measurement_complete=True,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)
        self.assertEqual(result.active_count, 1)

    def test_missing_evidence_blocks(self) -> None:
        result = evaluate(
            [Finding("ssrf-1", Category.SSRF, Severity.HIGH, "")],
            measurement_complete=True,
        )
        self.assertEqual(result.verdict, Verdict.BLOCKED)
        self.assertIn("missing_evidence:ssrf-1", result.reasons)

    def test_incomplete_measurement_blocks_even_when_empty(self) -> None:
        result = evaluate([], measurement_complete=False)
        self.assertEqual(result.verdict, Verdict.BLOCKED)

    def test_not_measured_blocks(self) -> None:
        result = evaluate(
            [Finding("hdr-unmeasured", Category.SECURITY_HEADER, Severity.INFO, "probe:unavailable", state=FindingState.NOT_MEASURED)],
            measurement_complete=True,
        )
        self.assertEqual(result.verdict, Verdict.BLOCKED)
        self.assertIn("not_measured:hdr-unmeasured", result.reasons)

    def test_not_applicable_does_not_fail(self) -> None:
        result = evaluate(
            [Finding("hdr-na", Category.SECURITY_HEADER, Severity.INFO, "policy:not-applicable", state=FindingState.NOT_APPLICABLE)],
            measurement_complete=True,
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_duplicate_id_blocks(self) -> None:
        finding = Finding("p-1", Category.PERMISSION, Severity.MEDIUM, "fixture:1", active=False)
        result = evaluate([finding, finding], measurement_complete=True)
        self.assertEqual(result.verdict, Verdict.BLOCKED)
        self.assertIn("duplicate_finding_id:p-1", result.reasons)


class RedactionTests(unittest.TestCase):
    def test_nested_sensitive_values_are_redacted(self) -> None:
        payload = {"token": "real-value", "nested": {"api-key": "other", "safe": "ok"}}
        self.assertEqual(
            redact(payload),
            {"token": "[REDACTED]", "nested": {"api-key": "[REDACTED]", "safe": "ok"}},
        )


class CliTests(unittest.TestCase):
    def _run(self, payload: object) -> tuple[int, dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            stream = StringIO()
            with redirect_stdout(stream):
                code = main([str(path)])
            return code, json.loads(stream.getvalue())

    def test_cli_pass_exit_zero(self) -> None:
        code, output = self._run({"measurement_complete": True, "findings": []})
        self.assertEqual(code, 0)
        self.assertEqual(output["verdict"], "PASS")

    def test_cli_fail_exit_one(self) -> None:
        code, output = self._run(
            {
                "measurement_complete": True,
                "findings": [
                    {
                        "id": "hdr-1",
                        "category": "security_header",
                        "severity": "medium",
                        "evidence": "fixture:header",
                        "active": True,
                    }
                ],
            }
        )
        self.assertEqual(code, 1)
        self.assertEqual(output["verdict"], "FAIL")

    def test_cli_invalid_input_is_blocked(self) -> None:
        code, output = self._run({"measurement_complete": "yes", "findings": []})
        self.assertEqual(code, 2)
        self.assertEqual(output["verdict"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
