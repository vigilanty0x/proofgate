from __future__ import annotations

import hashlib
import unittest

from contract_lab.adapters import adapt_mock, adapt_schema_validation, adapt_webhook
from contract_lab.canonical import canonical_bytes


class StrictSourceContractTests(unittest.TestCase):
    def test_schema_compatible_cannot_hide_truncation(self) -> None:
        receipt = adapt_schema_validation({
            "status": "compatible",
            "errors": [],
            "errors_truncated": True,
            "records": 1,
        })
        self.assertEqual(receipt.verdict, "BLOCKED")

    def test_schema_error_row_must_reference_measured_record(self) -> None:
        receipt = adapt_schema_validation({
            "status": "blocked",
            "errors": [{"row": 1, "field": "name", "error": "type"}],
            "errors_truncated": False,
            "records": 1,
        })
        self.assertEqual(receipt.verdict, "BLOCKED")

    def test_webhook_accepted_with_errors_is_not_green(self) -> None:
        receipt = adapt_webhook({
            "accepted": True,
            "errors": ["signature_mismatch"],
            "assurance": "hmac_sha256",
            "request_sha256": "0" * 64,
            "bytes": 2,
        })
        self.assertEqual(receipt.verdict, "BLOCKED")

    def test_webhook_invalid_digest_shape_is_blocked(self) -> None:
        receipt = adapt_webhook({
            "accepted": True,
            "errors": [],
            "assurance": "structural_only",
            "request_sha256": "not-a-digest",
            "bytes": 2,
        })
        self.assertEqual(receipt.verdict, "BLOCKED")

    @staticmethod
    def _mock_payload(*, network_server: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "project": "api-contract-mock-server",
            "status": "passed",
            "reason": "bounded response fixtures generated; no server was started",
            "record": {
                "contract": "synthetic-v1",
                "routes": ["GET /health"],
                "modes": ["success", "degraded", "invalid"],
                "default_status": 200,
            },
            "responses": {
                "kind": "deterministic-response-fixtures",
                "network_server": network_server,
                "routes": {
                    "GET /health": {
                        "success": {"status": 200, "body": {"ok": True}},
                        "degraded": {"status": 503, "body": {"ok": False, "state": "degraded"}},
                        "invalid": {"status": 500, "body": "invalid-contract-response"},
                    }
                },
            },
        }
        payload["evidence_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        return payload

    def test_mock_wrong_source_evidence_digest_is_blocked(self) -> None:
        payload = self._mock_payload()
        payload["evidence_sha256"] = "0" * 64
        self.assertEqual(adapt_mock(payload).verdict, "BLOCKED")

    def test_mock_recomputed_digest_cannot_hide_server_claim(self) -> None:
        payload = self._mock_payload(network_server=True)
        self.assertEqual(adapt_mock(payload).verdict, "BLOCKED")

    def test_mock_valid_source_shape_remains_pass(self) -> None:
        self.assertEqual(adapt_mock(self._mock_payload()).verdict, "PASS")


if __name__ == "__main__":
    unittest.main()
