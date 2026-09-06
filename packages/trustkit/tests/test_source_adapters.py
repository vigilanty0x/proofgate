from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/env-example-guard/src",
    "packages/permission-matrix/src",
    "packages/secrets-hygiene/src",
    "packages/security-headers-lab/src",
    "packages/ssrf-guard-demo/src",
):
    sys.path.insert(0, str(ROOT / relative))

from env_example_guard.core import run as env_run
from permission_matrix.core import run as permission_run
from secrets_hygiene.core import run as secrets_run
from security_headers_lab.core import run as headers_run
from ssrf_guard_demo.core import guard as ssrf_guard

from trustkit.adapters import (
    AdapterContractError,
    normalize_env_example,
    normalize_permission_matrix,
    normalize_secrets,
    normalize_security_headers,
    normalize_ssrf,
)
from trustkit.core import Verdict


class SourceAdapterCompatibilityTests(unittest.TestCase):
    def test_env_example_pass_fail_and_inconclusive(self) -> None:
        passing = env_run({
            "actual_keys": ["API_URL", "SECRET_TOKEN"],
            "example_text": "API_URL=example\nSECRET_TOKEN=<required>\n",
        })
        self.assertEqual(normalize_env_example(passing).evaluation().verdict, Verdict.PASS)

        failing = env_run({
            "actual_keys": ["API_URL", "SECRET_TOKEN"],
            "example_text": "API_URL=example\nSECRET_TOKEN=supersecretvalue\n",
        })
        normalized = normalize_env_example(failing)
        self.assertEqual(normalized.evaluation().verdict, Verdict.FAIL)
        self.assertEqual(normalized.findings[0].category.value, "secret")
        self.assertNotIn("supersecretvalue", normalized.findings[0].evidence)

        inconclusive = env_run({"actual_keys": [], "example_text": ""})
        self.assertEqual(normalize_env_example(inconclusive).evaluation().verdict, Verdict.BLOCKED)

    def test_secrets_pass_fail_and_incomplete(self) -> None:
        passing = secrets_run({"files": {"README.md": "hello\n"}})
        self.assertEqual(normalize_secrets(passing).evaluation().verdict, Verdict.PASS)

        failing = secrets_run({"files": {"config.txt": "key=AKIAABCDEFGHIJKLMNOP\n"}})
        normalized = normalize_secrets(failing)
        self.assertEqual(normalized.evaluation().verdict, Verdict.FAIL)
        self.assertTrue(normalized.findings)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", normalized.findings[0].evidence)

        incomplete = {
            "status": "blocked",
            "findings": [{"path": "large.bin", "kind": "size_blocked", "line": None}],
            "findings_truncated": False,
        }
        self.assertEqual(normalize_secrets(incomplete).evaluation().verdict, Verdict.BLOCKED)

    def test_security_headers_pass_and_fail(self) -> None:
        passing = headers_run({
            "headers": {
                "Content-Security-Policy": "default-src 'self'; script-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Strict-Transport-Security": "max-age=31536000",
            },
            "https": True,
        })
        self.assertEqual(normalize_security_headers(passing).evaluation().verdict, Verdict.PASS)

        failing = headers_run({"headers": {}, "https": True})
        normalized = normalize_security_headers(failing)
        self.assertEqual(normalized.evaluation().verdict, Verdict.FAIL)
        self.assertGreater(normalized.evaluation().active_count, 0)

    def test_permission_matrix_requires_exact_expectations(self) -> None:
        source = permission_run({
            "subjects": ["alice"],
            "actions": ["read"],
            "resources": ["repo"],
            "assignments": {"alice": ["reader"]},
            "rules": [
                {"role": "reader", "action": "read", "resource": "repo", "effect": "allow"}
            ],
        })
        expected_allow = [
            {"subject": "alice", "action": "read", "resource": "repo", "decision": "allowed"}
        ]
        self.assertEqual(
            normalize_permission_matrix(source, expected_decisions=expected_allow).evaluation().verdict,
            Verdict.PASS,
        )

        expected_deny = [
            {"subject": "alice", "action": "read", "resource": "repo", "decision": "denied"}
        ]
        mismatch = normalize_permission_matrix(source, expected_decisions=expected_deny)
        self.assertEqual(mismatch.evaluation().verdict, Verdict.FAIL)
        self.assertEqual(mismatch.findings[0].severity.value, "critical")
        self.assertEqual(
            normalize_permission_matrix(source, expected_decisions=None).evaluation().verdict,
            Verdict.BLOCKED,
        )

    def test_ssrf_adapter_requires_fixture_expectation(self) -> None:
        allowed = ssrf_guard(
            "https://example.com/path",
            allowed_hosts=["example.com"],
            resolver=lambda host, port: ["8.8.8.8"],
        )
        self.assertEqual(
            normalize_ssrf(allowed, expected_decision="allowed").evaluation().verdict,
            Verdict.PASS,
        )
        mismatch = normalize_ssrf(allowed, expected_decision="blocked")
        self.assertEqual(mismatch.evaluation().verdict, Verdict.FAIL)
        self.assertEqual(mismatch.findings[0].severity.value, "critical")

        blocked = ssrf_guard("http://127.0.0.1/")
        self.assertEqual(
            normalize_ssrf(blocked, expected_decision="blocked").evaluation().verdict,
            Verdict.PASS,
        )
        self.assertEqual(
            normalize_ssrf(blocked, expected_decision=None).evaluation().verdict,
            Verdict.BLOCKED,
        )

    def test_adapter_contract_rejects_fabricated_green(self) -> None:
        with self.assertRaises(AdapterContractError):
            normalize_env_example({
                "status": "verified", "missing": ["MISSING"], "extra": [], "leaked": [],
            })
        with self.assertRaises(AdapterContractError):
            normalize_security_headers({"status": "blocked", "issues": []})
        with self.assertRaises(AdapterContractError):
            normalize_ssrf({"decision": "maybe"}, expected_decision="blocked")


if __name__ == "__main__":
    unittest.main()
