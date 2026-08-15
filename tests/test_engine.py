import unittest

from status_truth import CheckOutcome, CheckResult, StatusPolicy, TruthState, normalize
from status_truth.contract import ContractError, DiagnosticKind
from helpers import NOW, provenance


def check(name, outcome, required=True, detail=""):
    prov = provenance(outcome.value) if outcome in {CheckOutcome.PASS, CheckOutcome.FAIL} else None
    return CheckResult(name, outcome, required, detail, prov)


class NormalizeTests(unittest.TestCase):
    def assess(self, checks, policy=None):
        return normalize(
            subject="svc", operation_id="op", checks=checks, policy=policy, recorded_at=NOW,
        )

    def test_all_required_pass_is_healthy(self):
        record = self.assess([check("a", CheckOutcome.PASS), check("b", CheckOutcome.PASS)])
        self.assertEqual(record.state, TruthState.HEALTHY)
        self.assertTrue(record.success)

    def test_required_fail_is_failed(self):
        record = self.assess([check("a", CheckOutcome.PASS), check("b", CheckOutcome.FAIL)])
        self.assertEqual(record.state, TruthState.FAILED)
        self.assertFalse(record.success)

    def test_failure_beats_timeout(self):
        record = self.assess([check("a", CheckOutcome.FAIL), check("b", CheckOutcome.TIMEOUT)])
        self.assertEqual(record.state, TruthState.FAILED)

    def test_required_timeout_is_blocked(self):
        self.assertEqual(self.assess([check("a", CheckOutcome.TIMEOUT)]).state, TruthState.BLOCKED)

    def test_required_open_circuit_is_blocked(self):
        self.assertEqual(self.assess([check("a", CheckOutcome.CIRCUIT_OPEN)]).state, TruthState.BLOCKED)

    def test_required_unknown_is_unknown(self):
        self.assertEqual(self.assess([check("a", CheckOutcome.UNKNOWN)]).state, TruthState.UNKNOWN)

    def test_optional_fail_degrades(self):
        record = self.assess([check("a", CheckOutcome.PASS), check("b", CheckOutcome.FAIL, False)])
        self.assertEqual(record.state, TruthState.DEGRADED)

    def test_optional_timeout_degrades(self):
        record = self.assess([check("a", CheckOutcome.PASS), check("b", CheckOutcome.TIMEOUT, False)])
        self.assertEqual(record.state, TruthState.DEGRADED)

    def test_optional_unknown_degrades(self):
        record = self.assess([check("a", CheckOutcome.PASS), check("b", CheckOutcome.UNKNOWN, False)])
        self.assertEqual(record.state, TruthState.DEGRADED)

    def test_only_optional_checks_cannot_prove_health(self):
        record = self.assess([check("a", CheckOutcome.PASS, False)])
        self.assertEqual(record.state, TruthState.UNKNOWN)
        self.assertIn("NO_REQUIRED_CHECKS", [d.code for d in record.diagnostics])

    def test_policy_can_make_named_check_required(self):
        record = self.assess(
            [check("a", CheckOutcome.PASS, False)], StatusPolicy(required_names=("a",)),
        )
        self.assertEqual(record.state, TruthState.HEALTHY)
        self.assertTrue(record.checks[0].required)

    def test_empty_checks_are_rejected(self):
        with self.assertRaisesRegex(ContractError, "at least one"):
            self.assess([])

    def test_diagnostics_separate_proof_inference_blockage(self):
        record = self.assess([
            check("pass", CheckOutcome.PASS),
            check("unknown", CheckOutcome.UNKNOWN),
            check("timeout", CheckOutcome.TIMEOUT),
        ])
        self.assertEqual(
            [d.kind for d in record.diagnostics],
            [DiagnosticKind.PROOF, DiagnosticKind.INFERENCE, DiagnosticKind.BLOCKAGE],
        )

    def test_diagnostics_preserve_detail(self):
        record = self.assess([check("a", CheckOutcome.FAIL, detail="synthetic failure")])
        self.assertEqual(record.diagnostics[0].summary, "synthetic failure")

    def test_same_input_is_reproducible(self):
        checks = [check("a", CheckOutcome.PASS), check("b", CheckOutcome.FAIL, False)]
        first = self.assess(checks)
        second = self.assess(checks)
        self.assertEqual(first.to_dict(), second.to_dict())


if __name__ == "__main__":
    unittest.main()

