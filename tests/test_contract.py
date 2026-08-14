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


if __name__ == "__main__":
    unittest.main()

