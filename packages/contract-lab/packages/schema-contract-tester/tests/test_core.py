import math
import unittest

from schema_contract_tester.core import test_records


class SchemaTests(unittest.TestCase):
    def test_valid_record(self):
        result = test_records([{"x": "a"}], {"x": {"type": "string", "required": True}})
        self.assertEqual(result["status"], "compatible")

    def test_missing_type_and_nullable(self):
        self.assertEqual(test_records([{}], {"x": {"type": "string", "required": True}})["errors"][0]["error"], "missing")
        self.assertEqual(test_records([{"x": 1}], {"x": {"type": "string"}})["status"], "blocked")
        self.assertEqual(test_records([{"x": None}], {"x": {"type": "string", "nullable": True}})["status"], "compatible")

    def test_bool_is_neither_integer_nor_number(self):
        for kind in ("integer", "number"):
            with self.subTest(kind=kind):
                self.assertEqual(test_records([{"x": True}], {"x": {"type": kind}})["status"], "blocked")

    def test_number_must_be_finite(self):
        with self.assertRaises(ValueError):
            test_records([{"x": math.inf}], {"x": {"type": "number"}})

    def test_nested_values_must_still_be_finite_json(self):
        with self.assertRaises(ValueError):
            test_records([{"x": {"nested": math.nan}}], {"x": {"type": "object"}})

    def test_empty_records_require_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            test_records([], {"x": {"type": "string"}})
        self.assertEqual(test_records([], {"x": {"type": "string"}}, allow_empty=True)["status"], "compatible")

    def test_rejects_invalid_schema_and_record_shapes(self):
        bad = [
            (["row"], {"x": {"type": "string"}}),
            ([{"x": "a"}], {}),
            ([{"x": "a"}], {"x": {"type": "made-up"}}),
            ([{"x": "a"}], {"x": {"type": "string", "required": 1}}),
        ]
        for records, schema in bad:
            with self.subTest(records=records, schema=schema), self.assertRaises(ValueError):
                test_records(records, schema, allow_empty=True)


if __name__ == "__main__":
    unittest.main()
