import unittest
from run_replay.core import replay
class T(unittest.TestCase):
 def test_set(self): self.assertEqual(replay([{"op":"set","key":"x","value":1}])["state"]["x"],1)
 def test_increment(self): self.assertEqual(replay([{"op":"increment","key":"x","value":2}])["state"]["x"],2)
 def test_append(self): self.assertEqual(replay([{"op":"append","key":"x","value":2}])["state"]["x"],[2])
 def test_stable(self): self.assertEqual(replay([])["sha256"],replay([])["sha256"])
 def test_unknown(self):
  with self.assertRaises(ValueError): replay([{"op":"bad","key":"x"}])
if __name__=="__main__": unittest.main()

