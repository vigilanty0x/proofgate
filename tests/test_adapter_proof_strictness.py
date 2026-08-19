from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from trustkit.adapters import AdapterContractError, normalize_permission_matrix, normalize_ssrf

ROOT = Path(__file__).resolve().parents[1]


def git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


class SourceSeamIdentityTests(unittest.TestCase):
    def test_exact_reviewed_source_seam_blobs(self) -> None:
        expected = {
            "packages/env-example-guard/src/env_example_guard/core.py": "3d1887b2fc9586495890c419f606c3059f6f185d",
            "packages/permission-matrix/src/permission_matrix/core.py": "48330ceb53104f761691bd0902b671045fb16fdf",
            "packages/secrets-hygiene/src/secrets_hygiene/core.py": "5a941ec297c8823e5d6497710b506473c1bab1ee",
            "packages/security-headers-lab/src/security_headers_lab/core.py": "742e4e92b7b5a4536be2e7022b6597bc37741c51",
            "packages/ssrf-guard-demo/src/ssrf_guard_demo/core.py": "5e9400d5142a5f0be3fe15c2daa4c2dfb7431284",
        }
        for relative, expected_sha in expected.items():
            with self.subTest(relative=relative):
                self.assertEqual(git_blob_sha(ROOT / relative), expected_sha)


class FabricatedGreenCounterProofTests(unittest.TestCase):
    def test_permission_impossible_source_combination_is_rejected(self) -> None:
        fabricated = {
            "matrix": [
                {
                    "subject": "alice",
                    "action": "read",
                    "resource": "repo",
                    "decision": "allowed",
                    "reason": "no_rule",
                }
            ]
        }
        expectations = [
            {"subject": "alice", "action": "read", "resource": "repo", "decision": "allowed"}
        ]
        with self.assertRaises(AdapterContractError):
            normalize_permission_matrix(fabricated, expected_decisions=expectations)

    def test_ssrf_allowed_without_binding_cannot_be_green(self) -> None:
        with self.assertRaises(AdapterContractError):
            normalize_ssrf({"decision": "allowed"}, expected_decision="allowed")

    def test_ssrf_allowed_binding_must_match_resolved_addresses(self) -> None:
        fabricated = {
            "decision": "allowed",
            "host": "example.test",
            "scheme": "https",
            "port": 443,
            "resolved_addresses": ["8.8.8.8"],
            "binding": {"host": "example.test", "port": 443, "addresses": ["1.1.1.1"]},
        }
        with self.assertRaises(AdapterContractError):
            normalize_ssrf(fabricated, expected_decision="allowed")

    def test_ssrf_blocked_unknown_reason_is_rejected(self) -> None:
        with self.assertRaises(AdapterContractError):
            normalize_ssrf(
                {"decision": "blocked", "reason": "trust-me"},
                expected_decision="blocked",
            )


if __name__ == "__main__":
    unittest.main()
