from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from proofgate.contract import Contract, ContractError, load_contract

from tests.helpers import contract_dict, write_contract


class ContractTests(unittest.TestCase):
    def test_minimal_file_contract_is_valid(self) -> None:
        contract = Contract.from_dict(contract_dict([{"id": "artifact", "type": "file", "path": "out.txt"}]))
        self.assertEqual(contract.task_id, "demo")
        self.assertEqual(contract.evidence[0].type, "file")

    def test_unknown_fields_are_rejected(self) -> None:
        value = contract_dict([{"id": "artifact", "type": "file", "path": "out.txt"}], surprise=True)
        with self.assertRaisesRegex(ContractError, "unknown top-level"):
            Contract.from_dict(value)

    def test_duplicate_rule_ids_are_rejected(self) -> None:
        value = contract_dict(
            [
                {"id": "same", "type": "file", "path": "one"},
                {"id": "same", "type": "file", "path": "two"},
            ]
        )
        with self.assertRaisesRegex(ContractError, "duplicate evidence id"):
            Contract.from_dict(value)

    def test_parent_traversal_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "parent"):
            Contract.from_dict(contract_dict([{"id": "x", "type": "file", "path": "../secret"}]))

    def test_drive_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "drive path"):
            Contract.from_dict(contract_dict([{"id": "x", "type": "file", "path": "C:\\temp\\x"}]))

    def test_command_must_be_an_argument_array(self) -> None:
        with self.assertRaisesRegex(ContractError, "string array"):
            Contract.from_dict(contract_dict([{"id": "x", "type": "command", "command": "echo unsafe"}]))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text('{"contract_version":"1.0","contract_version":"1.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "duplicate JSON key"):
                load_contract(path)

    def test_non_finite_json_numbers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(
                '{"contract_version":"1.0","task":{"id":"x","terminal_state":"DONE"},'
                '"evidence":[{"id":"j","type":"json","path":"x.json","pointer":"/x","equals":NaN}]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractError, "non-finite"):
                load_contract(path)
        value = contract_dict(
            [{"id": "j", "type": "json", "path": "x.json", "pointer": "/x", "equals": float("inf")}]
        )
        with self.assertRaisesRegex(ContractError, "strict JSON"):
            Contract.from_dict(value)

    def test_empty_evidence_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "non-empty"):
            Contract.from_dict(contract_dict([]))

    def test_json_pointer_must_be_valid_shape(self) -> None:
        value = contract_dict([{"id": "x", "type": "json", "path": "x.json", "pointer": "bad", "equals": True}])
        with self.assertRaisesRegex(ContractError, "RFC 6901"):
            Contract.from_dict(value)

    def test_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_contract(root, contract_dict([{"id": "x", "type": "file", "path": "x"}]))
            self.assertEqual(load_contract(path).version, "1.0")

    def test_threshold_policy_is_validated(self) -> None:
        value = contract_dict(
            [
                {"id": "one", "type": "file", "path": "one"},
                {"id": "two", "type": "file", "path": "two"},
                {"id": "three", "type": "file", "path": "three"},
            ],
            policy={"mode": "threshold", "minimum_verified": 2},
        )
        contract = Contract.from_dict(value)
        self.assertEqual(contract.policy.mode, "threshold")
        self.assertEqual(contract.policy.minimum_verified, 2)

    def test_invalid_policy_threshold_is_rejected(self) -> None:
        value = contract_dict(
            [{"id": "one", "type": "file", "path": "one"}],
            policy={"mode": "threshold", "minimum_verified": 2},
        )
        with self.assertRaisesRegex(ContractError, "minimum_verified"):
            Contract.from_dict(value)

    def test_dependencies_are_validated_and_cycles_rejected(self) -> None:
        valid = Contract.from_dict(
            contract_dict(
                [
                    {"id": "build", "type": "file", "path": "build.txt"},
                    {"id": "report", "type": "json", "path": "report.json", "pointer": "/ok", "equals": True, "depends_on": ["build"]},
                ]
            )
        )
        self.assertEqual(valid.evidence[1].depends_on, ("build",))
        cyclic = contract_dict(
            [
                {"id": "one", "type": "file", "path": "one", "depends_on": ["two"]},
                {"id": "two", "type": "file", "path": "two", "depends_on": ["one"]},
            ]
        )
        with self.assertRaisesRegex(ContractError, "cycle"):
            Contract.from_dict(cyclic)

    def test_new_rule_types_are_strict(self) -> None:
        value = contract_dict(
            [
                {"id": "text", "type": "text", "path": "README.md", "contains": ["Install", "Security"]},
                {"id": "tree", "type": "directory", "path": "src", "pattern": "*.py", "min_files": 1},
                {"id": "receipt", "type": "receipt", "path": "receipt.json", "expected_task_id": "upstream"},
            ]
        )
        contract = Contract.from_dict(value)
        self.assertEqual([item.type for item in contract.evidence], ["text", "directory", "receipt"])
        bad = contract_dict([{"id": "text", "type": "text", "path": "x", "contains": []}])
        with self.assertRaisesRegex(ContractError, "contains"):
            Contract.from_dict(bad)


if __name__ == "__main__":
    unittest.main()
