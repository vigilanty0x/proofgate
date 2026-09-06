from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

from contract_lab.adapters import adapt_mock, adapt_schema_validation, adapt_webhook

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = [
    ROOT / "packages" / "schema-contract-tester" / "src",
    ROOT / "packages" / "webhook-sandbox" / "src",
    ROOT / "packages" / "api-contract-mock-server" / "src",
]
for source_dir in reversed(SOURCE_DIRS):
    sys.path.insert(0, str(source_dir))

from api_contract_mock_server.core import evaluate as evaluate_mock
from schema_contract_tester.core import run as run_schema_contract
from webhook_sandbox import inspect_webhook


def git_blob_sha(path: Path) -> str:
    content = path.read_bytes()
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


class SourceLineageTests(unittest.TestCase):
    def test_reviewed_source_seams_have_exact_blob_identity(self) -> None:
        self.assertEqual(
            git_blob_sha(ROOT / "packages/schema-contract-tester/src/schema_contract_tester/core.py"),
            "b8827fea89a7b59b9c3ae478bd9d0d08c801235f",
        )
        self.assertEqual(
            git_blob_sha(ROOT / "packages/webhook-sandbox/src/webhook_sandbox/__init__.py"),
            "4578bf4fe3f42b3e600a1663710a9997a3323363",
        )
        self.assertEqual(
            git_blob_sha(ROOT / "packages/api-contract-mock-server/src/api_contract_mock_server/core.py"),
            "23b567fae7c06b1f0800fa9ccfb05727c1c922c3",
        )


class SchemaAdapterTests(unittest.TestCase):
    def test_source_pass_and_fail_are_preserved(self) -> None:
        schema = {"name": {"type": "string", "required": True}}
        good = run_schema_contract({"records": [{"name": "ok"}], "schema": schema})
        bad = run_schema_contract({"records": [{"name": 7}], "schema": schema})
        self.assertEqual(adapt_schema_validation(good).verdict, "PASS")
        self.assertEqual(adapt_schema_validation(bad).verdict, "FAIL")

    def test_malformed_source_result_blocks(self) -> None:
        self.assertEqual(adapt_schema_validation({}).verdict, "BLOCKED")


class WebhookAdapterTests(unittest.TestCase):
    def test_source_accept_and_reject_are_preserved(self) -> None:
        good = inspect_webhook({"method": "POST", "path": "/demo", "headers": {}, "body": "{}"})
        bad = inspect_webhook({"method": "GET", "path": "../x", "headers": {}, "body": ""})
        self.assertEqual(adapt_webhook(good).verdict, "PASS")
        self.assertEqual(adapt_webhook(bad).verdict, "FAIL")
        self.assertEqual(adapt_webhook(good).payload_digest, adapt_webhook(good).payload_digest)

    def test_malformed_source_result_blocks(self) -> None:
        self.assertEqual(adapt_webhook({"accepted": True}).verdict, "BLOCKED")


class MockAdapterTests(unittest.TestCase):
    def test_source_pass_fail_and_blocked_are_preserved(self) -> None:
        good_record = {
            "contract": "synthetic-v1",
            "routes": ["GET /health"],
            "modes": ["success", "degraded", "invalid"],
            "default_status": 200,
        }
        fail_record = {
            "contract": "synthetic-v1",
            "routes": ["BAD /health"],
            "modes": ["success", "degraded", "invalid"],
            "default_status": 200,
        }
        self.assertEqual(adapt_mock(evaluate_mock(good_record)).verdict, "PASS")
        self.assertEqual(adapt_mock(evaluate_mock(fail_record)).verdict, "FAIL")
        self.assertEqual(adapt_mock(evaluate_mock({})).verdict, "BLOCKED")

    def test_malformed_source_result_blocks(self) -> None:
        self.assertEqual(adapt_mock({}).verdict, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
