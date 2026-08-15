import unittest
from structured_output_guard.core import validate
class T(unittest.TestCase):
 def test_valid(self): self.assertEqual(validate({"x":"a"},{"type":"object","required":["x"],"properties":{"x":{"type":"string"}}}),[])
 def test_required(self): self.assertEqual(validate({},{"type":"object","required":["x"],"properties":{}})[0]["error"],"required")
 def test_type(self): self.assertEqual(validate("x",{"type":"integer"})[0]["error"],"type")
 def test_additional(self): self.assertEqual(validate({"x":1},{"type":"object","properties":{},"additionalProperties":False})[0]["error"],"additional")
 def test_array(self): self.assertEqual(validate([1],{"type":"array","items":{"type":"integer"}}),[])
if __name__=="__main__": unittest.main()

