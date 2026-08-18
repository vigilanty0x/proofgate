import unittest

from status_truth.contract import (
    CheckOutcome, CheckResult, ContractError, Diagnostic, DiagnosticKind,
    Provenance, StatusPolicy, StatusRecord, TruthState, canonical_json, sha256_json,
)
from helpers import NOW, provenance


class ProvenanceTests(unittest.TestCase):
    def test_evidence_digest_is_deterministic(self):
        self.assertEqual(sha256_json({"b": 2, "a": 1}), sha256_json({"a": 1, "b": 2}))

    def test_canonical_json_is_compact(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_timestamp_is_normalized_to_utc(self):
        item = Provenance("s", "2026-01-01T01:00:00+01:00", "c", "a" * 64)
        self.assertEqual(item.observed_at, NOW)

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "timezone"):
            Provenance("s", "2026-01-01T00:00:00", "c", "a" * 64)

    def test_bad_digest_length_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "64"):
            Provenance("s", NOW, "c", "abc")

    def test_bad_digest_alphabet_is_rejected(self):
        with self.assertRaises(ContractError):
            Provenance("s", NOW, "c", "z" * 64)

    def test_round_trip(self):
        item = Provenance.from_evidence(source="s", observed_at=NOW, collector="c", evidence=[1], reference="fixture://x")
        self.assertEqual(Provenance.from_dict(item.to_dict()), item)

    def test_empty_source_is_rejected(self):
        with self.assertRaises(ContractError):
            Provenance.from_evidence(source=" ", observed_at=NOW, collector="c", evidence=True)


class CheckResultTests(unittest.TestCase):
    def test_string_outcome_is_normalized(self):
        item = CheckResult("a", "pass", provenance=provenance())
        self.assertIs(item.outcome, CheckOutcome.PASS)

    def test_pass_requires_provenance(self):
        with self.assertRaisesRegex(ContractError, "require provenance"):
            CheckResult("a", CheckOutcome.PASS)

    def test_fail_requires_provenance(self):
        with self.assertRaisesRegex(ContractError, "require provenance"):
            CheckResult("a", CheckOutcome.FAIL)

    def test_timeout_does_not_fabricate_provenance(self):
        item = CheckResult("a", CheckOutcome.TIMEOUT)
        self.assertIsNone(item.provenance)

    def test_invalid_outcome_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "invalid"):
            CheckResult("a", "maybe")

    def test_required_must_be_boolean(self):
        with self.assertRaisesRegex(ContractError, "boolean"):
            CheckResult("a", CheckOutcome.UNKNOWN, required=1)

    def test_round_trip(self):
        item = CheckResult("a", CheckOutcome.FAIL, False, "down", provenance(False))
        self.assertEqual(CheckResult.from_dict(item.to_dict()), item)


class StatusContractTests(unittest.TestCase):
    def make_record(self, **changes):
        values = dict(
            subject="service", operation_id="op-1", state=TruthState.HEALTHY,
            recorded_at=NOW, policy=StatusPolicy(required_names=("a",)),
            checks=(CheckResult("a", CheckOutcome.PASS, provenance=provenance()),),
            diagnostics=(Diagnostic(DiagnosticKind.PROOF, "OK", "passed", "a"),),
        )
        values.update(changes)
        return StatusRecord(**values)

    def test_healthy_is_the_only_success(self):
        self.assertTrue(self.make_record().success)
        for state in (TruthState.DEGRADED, TruthState.FAILED, TruthState.BLOCKED, TruthState.UNKNOWN):
            with self.subTest(state=state):
                self.assertFalse(self.make_record(state=state).success)

    def test_healthy_with_required_failure_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "healthy"):
            self.make_record(checks=(CheckResult("a", CheckOutcome.FAIL, provenance=provenance(False)),))

    def test_healthy_with_timeout_is_rejected(self):
        with self.assertRaises(ContractError):
            self.make_record(checks=(CheckResult("a", CheckOutcome.TIMEOUT),))

    def test_duplicate_check_names_are_rejected(self):
        check = CheckResult("a", CheckOutcome.PASS, provenance=provenance())
        with self.assertRaisesRegex(ContractError, "unique"):
            self.make_record(checks=(check, check))

    def test_missing_policy_check_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "missing"):
            self.make_record(policy=StatusPolicy(required_names=("missing",)))

    def test_empty_checks_are_rejected(self):
        with self.assertRaisesRegex(ContractError, "1..100"):
            self.make_record(checks=())

    def test_duplicate_policy_names_are_rejected(self):
        with self.assertRaisesRegex(ContractError, "unique"):
            StatusPolicy(required_names=("a", "a"))

    def test_unknown_schema_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "unsupported"):
            self.make_record(schema_version="2.0")

    def test_logical_digest_ignores_recorded_at(self):
        first = self.make_record(recorded_at=NOW)
        second = self.make_record(recorded_at="2026-01-01T00:00:01Z")
        self.assertEqual(first.logical_sha256, second.logical_sha256)

    def test_logical_digest_detects_state(self):
        self.assertNotEqual(self.make_record().logical_sha256, self.make_record(state=TruthState.FAILED).logical_sha256)

    def test_round_trip(self):
        record = self.make_record(metadata={"region": "synthetic"})
        self.assertEqual(StatusRecord.from_dict(record.to_dict()), record)

    def test_metadata_is_sorted_in_output(self):
        record = self.make_record(metadata={"z": "2", "a": "1"})
        self.assertEqual(list(record.to_dict()["metadata"]), ["a", "z"])


if __name__ == "__main__":
    unittest.main()

