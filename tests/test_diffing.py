from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from proofgate.diffing import DiffError, compare_verdicts, load_json_document


class DiffTests(unittest.TestCase):
    def test_diff_exposes_regression_and_changed_evidence(self) -> None:
        before = {"task_id":"x","state":"DONE","status":"verified","reason_code":"ALL_EVIDENCE_VERIFIED","evidence":[{"id":"tests","passed":True,"code":"EVIDENCE_VERIFIED"}]}
        after = {"task_id":"x","state":"FAILED","status":"blocked","reason_code":"EVIDENCE_FAILED","evidence":[{"id":"tests","passed":False,"code":"COMMAND_EXIT_MISMATCH"}]}
        result = compare_verdicts(before, after)
        self.assertTrue(result["regression"])
        self.assertEqual(result["changed_evidence"][0]["id"], "tests")

    def test_diff_input_rejects_non_finite_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verdict.json"
            path.write_text(
                '{"state":"DONE","status":"verified","evidence":[],"value":Infinity}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DiffError, "non-finite"):
                load_json_document(path)


if __name__ == "__main__":
    unittest.main()
