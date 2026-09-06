import unittest

from secrets_hygiene.core import scan


class SecretScanTests(unittest.TestCase):
    def test_provider_patterns_are_detected_without_echo(self):
        fixtures = {
            "aws": "AKIA" + "A1B2C3D4E5F6G7H8",
            "github": "github_pat_" + "Ab1_" * 8,
            "bearer": "Authorization: Bearer " + "AbCd1234" * 4,
            "jwt": "eyJhbGciOiJIUzI1NiJ9." + "ZXhhbXBsZV9wYXlsb2FkMTIzNA." + "c2lnbmF0dXJlMTIzNDU2Nzg5MA",
            "slack": "xoxb-" + "1234567890-" * 3 + "abcdef",
            "stripe": "sk_" + "live_" + "Ab12" * 8,
            "pem": "-----BEGIN " + "PRIVATE KEY-----",
            "connection": "DATABASE_URL=postgresql://user:not-a-real-password@example.invalid/db",
        }
        for expected, value in fixtures.items():
            with self.subTest(expected=expected):
                result = scan({"fixture.txt": value})
                self.assertEqual(result["status"], "blocked")
                self.assertTrue(any(expected in finding["kind"] for finding in result["findings"]))
                self.assertNotIn(value, repr(result))

    def test_entropy_heuristic_is_bounded_and_redacted(self):
        value = "aB3dE5fG7hJ9kL2mN4pQ6rS8tV1wX3yZ"
        result = scan({"fixture.txt": value})
        self.assertTrue(any(finding["kind"] == "high_entropy" for finding in result["findings"]))
        self.assertNotIn(value, repr(result))

    def test_common_public_values_do_not_trigger(self):
        text = "\n".join(("TOKEN=<replace-me>", "sha256=" + "a" * 64, "request_id=123e4567-e89b-12d3-a456-426614174000", "https://example.invalid/docs"))
        self.assertEqual(scan({"fixture.txt": text})["status"], "clean")

    def test_input_and_output_are_bounded(self):
        with self.assertRaises(ValueError):
            scan([])
        result = scan({"large.txt": "x" * 2_000_001})
        self.assertEqual(result["findings"][0]["kind"], "size_blocked")


if __name__ == "__main__":
    unittest.main()
