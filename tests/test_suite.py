from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from proofgate.suite import SuiteError, evaluate_suite, load_suite

from tests.helpers import contract_dict


class SuiteTests(unittest.TestCase):
    def test_suite_runs_contracts_in_dependency_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_text("ok", encoding="utf-8")
            (root / "two.txt").write_text("ok", encoding="utf-8")
            (root / "one.json").write_text(json.dumps(contract_dict([{"id": "one", "type": "file", "path": "one.txt"}])), encoding="utf-8")
            (root / "two.json").write_text(json.dumps(contract_dict([{"id": "two", "type": "file", "path": "two.txt"}])), encoding="utf-8")
            suite_path = root / "suite.json"
            suite_path.write_text(json.dumps({
                "suite_version": "1.0",
                "id": "release",
                "contracts": [
                    {"id": "build", "path": "one.json"},
                    {"id": "publish", "path": "two.json", "depends_on": ["build"]},
                ],
            }), encoding="utf-8")
            result = evaluate_suite(load_suite(suite_path), root=root, execute_commands=False)
            self.assertTrue(result.done)
            self.assertEqual([item["id"] for item in result.contracts], ["build", "publish"])

    def test_failed_dependency_blocks_child_and_cycle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.json").write_text(json.dumps(contract_dict([{"id": "missing", "type": "file", "path": "missing"}])), encoding="utf-8")
            (root / "ok.json").write_text(json.dumps(contract_dict([{"id": "also", "type": "file", "path": "missing2"}])), encoding="utf-8")
            path = root / "suite.json"
            path.write_text(json.dumps({"suite_version":"1.0","id":"x","contracts":[{"id":"one","path":"bad.json"},{"id":"two","path":"ok.json","depends_on":["one"]}]}), encoding="utf-8")
            result = evaluate_suite(load_suite(path), root=root, execute_commands=False)
            self.assertEqual(result.contracts[1]["reason_code"], "DEPENDENCY_BLOCKED")
            path.write_text(json.dumps({"suite_version":"1.0","id":"x","contracts":[{"id":"one","path":"bad.json","depends_on":["two"]},{"id":"two","path":"ok.json","depends_on":["one"]}]}), encoding="utf-8")
            with self.assertRaisesRegex(SuiteError, "cycle"):
                load_suite(path)

    def test_suite_and_unit_ids_cannot_escape_journal_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text(json.dumps({
                "suite_version": "1.0",
                "id": "release",
                "contracts": [{"id": "../escape", "path": "contract.json"}],
            }), encoding="utf-8")
            with self.assertRaisesRegex(SuiteError, "must match"):
                load_suite(path)

    def test_suite_input_rejects_non_finite_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text(
                '{"suite_version":"1.0","id":"demo","contracts":[],"extra":NaN}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SuiteError, "non-finite"):
                load_suite(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_suite_never_follows_contract_symlink_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.txt").write_text("ok", encoding="utf-8")
            (root / "real.json").write_text(
                json.dumps(contract_dict([{"id": "file", "type": "file", "path": "artifact.txt"}])),
                encoding="utf-8",
            )
            (root / "alias.json").symlink_to(root / "real.json")
            suite = load_suite(
                _write_suite(root / "suite.json", [{"id": "unit", "path": "alias.json"}])
            )
            verdict = evaluate_suite(suite, root=root, execute_commands=False)
            self.assertFalse(verdict.done)
            self.assertEqual(verdict.contracts[0]["state"], "REJECTED")
            self.assertEqual(verdict.contracts[0]["error"], "ContractError")


def _write_suite(path: Path, contracts: list[dict[str, object]]) -> Path:
    path.write_text(
        json.dumps({"suite_version": "1.0", "id": "symlink-check", "contracts": contracts}),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    unittest.main()
