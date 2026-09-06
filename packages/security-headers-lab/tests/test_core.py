import unittest

from security_headers_lab.core import evaluate


class HeaderTests(unittest.TestCase):
    def good(self):
        return {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }

    def test_good_policy_is_hardened(self):
        self.assertEqual(evaluate(self.good())["status"], "hardened")

    def test_hsts_requires_parseable_documented_minimum(self):
        for value in ("max-age=0", "max-age=1", "max-age=banana", "includeSubDomains"):
            headers = self.good()
            headers["Strict-Transport-Security"] = value
            with self.subTest(value=value):
                self.assertEqual(evaluate(headers)["status"], "blocked")

    def test_csp_tokens_are_case_insensitive_and_scripts_are_restrictive(self):
        for value in ("script-src 'UNSAFE-EVAL'", "script-src *", "script-src https://*.example.com", "script-src data:", "script-src filesystem:", "default-src 'self'; script-src 'unsafe-inline'"):
            headers = self.good()
            headers["Content-Security-Policy"] = value
            with self.subTest(value=value):
                self.assertEqual(evaluate(headers)["status"], "blocked")

    def test_referrer_and_permissions_policy_are_validated(self):
        headers = self.good()
        headers["Referrer-Policy"] = "unsafe-url"
        self.assertEqual(evaluate(headers)["status"], "blocked")
        headers = self.good()
        headers["Permissions-Policy"] = "camera=*"
        self.assertEqual(evaluate(headers)["status"], "blocked")

    def test_http_does_not_require_hsts_but_other_headers_remain_required(self):
        headers = self.good()
        del headers["Strict-Transport-Security"]
        self.assertEqual(evaluate(headers, https=False)["status"], "hardened")


if __name__ == "__main__":
    unittest.main()
