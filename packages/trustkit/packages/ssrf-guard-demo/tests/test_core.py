import unittest

from ssrf_guard_demo.core import guard


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, host, port):
        self.calls.append((host, port))
        return self.answers


class SSRFGuardTests(unittest.TestCase):
    def test_dns_name_is_canonicalized_resolved_and_bound(self):
        resolver = FakeResolver(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
        result = guard("https://ExAmPle.com./path", resolver=resolver, allowed_hosts=["example.com"])
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["resolved_addresses"], sorted(resolver.answers))
        self.assertEqual(resolver.calls, [("example.com", 443)])

    def test_every_dns_answer_must_be_global(self):
        result = guard("https://example.com", resolver=FakeResolver(["93.184.216.34", "127.0.0.1"]))
        self.assertEqual(result["reason"], "non_global_ip")

    def test_local_names_alternate_numbers_and_mapped_ipv6_block(self):
        urls = ("http://localhost.", "http://service.localhost", "http://2130706433", "http://0177.0.0.1", "http://[::ffff:127.0.0.1]")
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(guard(url, resolver=FakeResolver(["93.184.216.34"]))["decision"], "blocked")

    def test_scheme_credentials_and_ports_block(self):
        self.assertEqual(guard("file:///etc/passwd")["reason"], "scheme")
        self.assertEqual(guard("https://u:p@example.com")["reason"], "authority")
        self.assertEqual(guard("https://example.com:99999")["reason"], "port")

    def test_idna_allowlist_is_canonical(self):
        resolver = FakeResolver(["93.184.216.34"])
        result = guard("https://b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example", resolver=resolver, allowed_hosts=["xn--bcher-kva.example"])
        self.assertEqual(result["decision"], "allowed")

    def test_empty_or_malformed_resolver_results_fail_closed(self):
        self.assertEqual(guard("https://example.com", resolver=FakeResolver([]))["reason"], "resolution")
        self.assertEqual(guard("https://example.com", resolver=FakeResolver(["not-an-ip"]))["reason"], "resolution")


if __name__ == "__main__":
    unittest.main()
