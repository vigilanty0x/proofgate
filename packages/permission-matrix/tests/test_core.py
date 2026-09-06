import unittest

from permission_matrix.core import decide, matrix


class PermissionTests(unittest.TestCase):
    def inputs(self):
        return {"assignments": {"u": ["r"]}, "rules": [{"role": "r", "action": "read", "resource": "x", "effect": "allow"}]}

    def test_explicit_allow_default_deny_and_deny_precedence(self):
        values = self.inputs()
        self.assertEqual(decide("u", "read", "x", **values)["decision"], "allowed")
        self.assertEqual(decide("u", "write", "x", **values)["decision"], "denied")
        values["rules"].append({"role": "r", "action": "*", "resource": "*", "effect": "deny"})
        self.assertEqual(decide("u", "read", "x", **values)["reason"], "explicit_deny")

    def test_shapes_and_effects_are_strict(self):
        values = self.inputs()
        values["rules"][0]["extra"] = True
        with self.assertRaises(ValueError):
            decide("u", "read", "x", **values)
        values = self.inputs()
        values["rules"][0]["effect"] = "maybe"
        with self.assertRaises(ValueError):
            decide("u", "read", "x", **values)

    def test_matrix_bounds_are_checked_without_bool_or_string_iterables(self):
        values = self.inputs()
        with self.assertRaises(ValueError):
            matrix("u", ["read"], ["x"], **values)


if __name__ == "__main__":
    unittest.main()
