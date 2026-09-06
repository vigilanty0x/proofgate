import json,tempfile,unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from contract_lab.canonical import canonical_digest, canonical_roundtrip
from contract_lab.cli import main
from contract_lab.evolution import compare_schemas
from contract_lab.replay import build_receipt,verify_receipt
from contract_lab.webhook import sign_sha256,verify_sha256

OLD={"type":"object","properties":{"id":{"type":"string"},"count":{"type":"integer"}},"required":["id"]}

class Tests(unittest.TestCase):
    def test_canonical_order(self):
        self.assertEqual(canonical_digest({"b":2,"a":1}),canonical_digest({"a":1,"b":2}))
        self.assertEqual(canonical_roundtrip({"b":2,"a":1}),{"a":1,"b":2})
    def test_nan_blocked(self):
        with self.assertRaises(ValueError): canonical_digest({"x":float("nan")})
    def test_optional_add_ok(self):
        new={"type":"object","properties":{**OLD["properties"],"note":{"type":"string"}},"required":["id"]}
        self.assertTrue(compare_schemas(OLD,new).compatible)
    def test_required_add_breaks(self):
        new={"type":"object","properties":{**OLD["properties"],"tenant":{"type":"string"}},"required":["id","tenant"]}
        self.assertFalse(compare_schemas(OLD,new).compatible)
    def test_remove_breaks(self):
        self.assertFalse(compare_schemas(OLD,{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}).compatible)
    def test_type_change_breaks(self):
        new={"type":"object","properties":{"id":{"type":"integer"},"count":{"type":"integer"}},"required":["id"]}
        self.assertFalse(compare_schemas(OLD,new).compatible)
    def test_invalid_required_blocks(self):
        with self.assertRaises(ValueError): compare_schemas(OLD,{"type":"object","properties":{},"required":["ghost"]})
    def test_replay_tamper(self):
        r=build_receipt(contract=OLD,request={"id":"1"},response={"ok":True})
        self.assertTrue(verify_receipt(r,contract=OLD,request={"id":"1"},response={"ok":True}))
        self.assertFalse(verify_receipt(r,contract=OLD,request={"id":"2"},response={"ok":True}))
    def test_webhook_signature_and_tamper(self):
        sig=sign_sha256("fixture-secret",b"one")
        self.assertTrue(verify_sha256("fixture-secret",b"one",sig))
        self.assertFalse(verify_sha256("fixture-secret",b"two",sig))
    def test_empty_secret_blocks(self):
        with self.assertRaises(ValueError): sign_sha256("",b"x")
    def test_cli_breaking_is_one(self):
        with tempfile.TemporaryDirectory() as t:
            p1=Path(t)/"o.json"; p2=Path(t)/"n.json"
            p1.write_text(json.dumps(OLD)); p2.write_text(json.dumps({"type":"object","properties":{"id":{"type":"integer"},"count":{"type":"integer"}},"required":["id"]}))
            s=StringIO()
            with redirect_stdout(s): code=main(["evolve",str(p1),str(p2)])
            self.assertEqual(code,1); self.assertEqual(json.loads(s.getvalue())["status"],"FAIL")
    def test_cli_invalid_is_two(self):
        with tempfile.TemporaryDirectory() as t:
            p1=Path(t)/"o.json"; p2=Path(t)/"bad.json"
            p1.write_text(json.dumps(OLD)); p2.write_text(json.dumps({"type":"array"}))
            s=StringIO()
            with redirect_stdout(s): code=main(["evolve",str(p1),str(p2)])
            self.assertEqual(code,2); self.assertEqual(json.loads(s.getvalue())["status"],"BLOCKED")

if __name__=="__main__": unittest.main()
