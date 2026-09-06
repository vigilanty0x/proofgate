import unittest

from api_contract_mock_server import evaluate

GOOD = {"contract": "openapi.json", "routes": ["GET /health"], "modes": ["success", "degraded", "invalid"], "default_status": 200}


class ContractTests(unittest.TestCase):
    def test_valid_record_builds_fixtures_not_server(self):
        result = evaluate(GOOD)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["responses"]["network_server"])
        self.assertIn("GET /health", result["responses"]["routes"])

    def test_duplicate_route_is_rejected(self):
        self.assertEqual(evaluate({**GOOD, "routes": ["GET /health", "GET /health"]})["status"], "failed")

    def test_unsupported_method_is_rejected(self):
        self.assertEqual(evaluate({**GOOD, "routes": ["TRACE /health"]})["status"], "failed")

    def test_route_control_injection_is_rejected(self):
        self.assertEqual(evaluate({**GOOD, "routes": ["GET /ok\nPOST /admin"]})["status"], "failed")

    def test_modes_are_exact_and_unique(self):
        self.assertEqual(evaluate({**GOOD, "modes": ["success", "degraded", "invalid", "invalid"]})["status"], "failed")

    def test_boolean_and_non_success_default_status_are_rejected(self):
        self.assertEqual(evaluate({**GOOD, "default_status": True})["status"], "failed")
        self.assertEqual(evaluate({**GOOD, "default_status": 500})["status"], "failed")

    def test_non_object_and_missing_field_fail_closed(self):
        self.assertEqual(evaluate(None)["status"], "failed")
        self.assertEqual(evaluate({})["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
