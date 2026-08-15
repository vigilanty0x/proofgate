import unittest
from ssrf_guard_demo.core import guard
class T(unittest.TestCase):
 def test_public(self): self.assertEqual(guard("https://example.com")["decision"],"allowed")
 def test_loopback(self): self.assertEqual(guard("http://127.0.0.1")["decision"],"blocked")
 def test_metadata(self): self.assertEqual(guard("http://169.254.169.254")["decision"],"blocked")
 def test_scheme(self): self.assertEqual(guard("file:///etc/passwd")["reason"],"scheme")
 def test_credentials(self): self.assertEqual(guard("https://u:p@example.com")["reason"],"authority")
if __name__=="__main__": unittest.main()

