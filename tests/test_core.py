import unittest
from secrets_hygiene.core import scan
class T(unittest.TestCase):
 def test_clean(self): self.assertEqual(scan({"a":"hello"})["status"],"clean")
 def test_key(self): self.assertEqual(scan({"a":"BEGIN "+"PRIVATE KEY"})["status"],"blocked")
 def test_assignment(self): self.assertEqual(scan({"a":"password=abcdefgh"})["findings"][0]["kind"],"assignment")
 def test_redacted(self): self.assertNotIn("text",scan({"a":"password=abcdefgh"})["findings"][0])
 def test_line(self): self.assertEqual(scan({"a":"ok\npassword=abcdefgh"})["findings"][0]["line"],2)
if __name__=="__main__": unittest.main()
