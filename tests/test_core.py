import unittest
from security_headers_lab.core import evaluate
class T(unittest.TestCase):
 def good(self): return {"Content-Security-Policy":"default-src 'self'","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Permissions-Policy":"camera=()","Strict-Transport-Security":"max-age=1"}
 def test_good(self): self.assertEqual(evaluate(self.good())["status"],"hardened")
 def test_missing(self): self.assertEqual(evaluate({})["status"],"blocked")
 def test_nosniff(self): x=self.good(); x["X-Content-Type-Options"]="bad"; self.assertTrue(evaluate(x)["issues"])
 def test_hsts_http(self): x=self.good(); del x["Strict-Transport-Security"]; self.assertEqual(evaluate(x,https=False)["status"],"hardened")
 def test_csp(self): x=self.good(); x["Content-Security-Policy"]="script-src 'unsafe-inline'"; self.assertEqual(evaluate(x)["status"],"blocked")
if __name__=="__main__": unittest.main()

