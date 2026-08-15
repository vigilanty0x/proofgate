import unittest

from env_example_guard.core import check, parse


class EnvGuardTests(unittest.TestCase):
    def test_key_parity_with_empty_values_is_verified(self):
        self.assertEqual(check(["APP_MODE"], "APP_MODE=")["status"], "verified")

    def test_missing_extra_and_duplicate_keys_block(self):
        result = check(["A"], "B=")
        self.assertEqual(result["missing"], ["A"])
        self.assertEqual(result["extra"], ["B"])
        with self.assertRaises(ValueError):
            parse("A=\nA=")

    def test_default_sensitive_names_cannot_be_bypassed_by_empty_policy(self):
        result = check(["SERVICE_TOKEN"], "SERVICE_TOKEN=not-a-placeholder", secret_keys=[])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["leaked"], ["SERVICE_TOKEN"])

    def test_sensitive_values_are_detected_under_benign_names(self):
        token = "AKIA" + "A1B2C3D4E5F6G7H8"
        result = check(["VALUE"], f"VALUE={token}")
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn(token, repr(result))

    def test_empty_policy_surface_is_inconclusive(self):
        self.assertEqual(check([], "")["status"], "inconclusive")

    def test_shapes_are_strict(self):
        with self.assertRaises(ValueError):
            check("A", "A=")


if __name__ == "__main__":
    unittest.main()
