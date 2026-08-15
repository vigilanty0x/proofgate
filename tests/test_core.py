import json
import subprocess
import sys
import unittest

from audit_trail_lite.core import append, query, run, verify


class AuditTrailTests(unittest.TestCase):
    def events(self):
        return append(append([], "a", "create", "x"), "b", "read", "x")

    def test_exact_stored_chain_is_integrity_only_without_trusted_head(self):
        result = verify(self.events())
        self.assertTrue(result["valid"])
        self.assertEqual(result["assurance"], "integrity_only")
        self.assertEqual(result["count"], 2)

    def test_independently_trusted_head_authenticates_chain(self):
        events = self.events()
        result = verify(events, trusted_head=events[-1]["hash"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["assurance"], "authenticity_verified")

    def test_tamper_link_hash_count_and_trusted_head_fail(self):
        events = self.events()
        events[0]["target"] = "tampered"
        self.assertFalse(verify(events)["valid"])
        events = self.events()
        events[1]["previous"] = "0" * 64
        self.assertFalse(verify(events)["valid"])
        events = self.events()
        self.assertFalse(verify(events, trusted_head="f" * 64)["valid"])

    def test_public_run_verifies_attacker_input_instead_of_rebuilding_it(self):
        events = self.events()
        events[0]["target"] = "tampered"
        result = run({"events": events})
        self.assertFalse(result["verification"]["valid"])
        self.assertEqual(result["events"], events)

    def test_public_payload_cannot_self_certify_a_rewritten_chain(self):
        events = append([], "attacker", "rewrite", "chain")
        payload = {"events": events, "trusted_head": events[-1]["hash"]}
        with self.assertRaises(ValueError):
            run(payload)
        completed = subprocess.run(
            [sys.executable, "-m", "audit_trail_lite.cli"],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("authenticity_verified", completed.stdout)

    def test_query_is_bounded_and_filterable(self):
        self.assertEqual(len(query(self.events(), actor="a")), 1)
        with self.assertRaises(ValueError):
            query(self.events(), actor=1)


if __name__ == "__main__":
    unittest.main()
