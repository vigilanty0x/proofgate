import unittest
from evidence_ledger.core import append,verify
class T(unittest.TestCase):
 def test_append(self): self.assertEqual(len(append([],{"x":1})),1)
 def test_verify(self): self.assertTrue(verify(append([],{"x":1}))["valid"])
 def test_tamper(self): c=append([],{"x":1}); c[0]["payload"]["x"]=2; self.assertFalse(verify(c)["valid"])
 def test_link(self): c=append(append([],1),2); self.assertEqual(c[1]["previous"],c[0]["hash"])
 def test_empty(self): self.assertTrue(verify([])["valid"])
if __name__=="__main__": unittest.main()

