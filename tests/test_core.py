import unittest
from env_example_guard.core import parse,check
class T(unittest.TestCase):
 def test_ok(self): self.assertEqual(check(["A"],"A=")["status"],"verified")
 def test_missing(self): self.assertEqual(check(["A"],"B=")["missing"],["A"])
 def test_extra(self): self.assertEqual(check([],"B=")["extra"],["B"])
 def test_leak(self): self.assertEqual(check(["TOKEN"],"TOKEN=secret",["TOKEN"])["status"],"blocked")
 def test_duplicate(self):
  with self.assertRaises(ValueError): parse("A=\nA=")
if __name__=="__main__": unittest.main()
