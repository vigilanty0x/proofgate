import unittest
from audit_trail_lite.core import append,verify,query
class T(unittest.TestCase):
 def test_append(self): self.assertEqual(len(append([],"a","x","t")),1)
 def test_verify(self): self.assertTrue(verify(append([],"a","x","t"))["valid"])
 def test_tamper(self): e=append([],"a","x","t"); e[0]["target"]="z"; self.assertFalse(verify(e)["valid"])
 def test_query_actor(self): e=append(append([],"a","x","t"),"b","y","t"); self.assertEqual(len(query(e,actor="a")),1)
 def test_query_action(self): self.assertEqual(len(query(append([],"a","x","t"),action="x")),1)
if __name__=="__main__": unittest.main()

