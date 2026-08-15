import time
import unittest

from status_truth import CheckOutcome, CircuitBreaker, GuardedCheck


class FakeClock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now


class CircuitBreakerTests(unittest.TestCase):
    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError): CircuitBreaker(failure_threshold=0)

    def test_invalid_reset_is_rejected(self):
        with self.assertRaises(ValueError): CircuitBreaker(reset_after_seconds=-1)

    def test_opens_at_threshold(self):
        breaker = CircuitBreaker(failure_threshold=2)
        breaker.record_failure(); breaker.record_failure()
        self.assertEqual(breaker.state, "open")

    def test_success_resets_failures(self):
        breaker = CircuitBreaker(failure_threshold=2)
        breaker.record_failure(); breaker.record_success(); breaker.record_failure()
        self.assertEqual(breaker.state, "closed")

    def test_reset_window_closes_circuit(self):
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=1, reset_after_seconds=5, clock=clock)
        breaker.record_failure(); self.assertEqual(breaker.state, "open")
        clock.now = 5
        self.assertEqual(breaker.state, "closed")


class GuardedCheckTests(unittest.TestCase):
    def guarded(self, **kwargs):
        return GuardedCheck("probe", kwargs.pop("timeout_seconds", 0.05), kwargs.pop("breaker", CircuitBreaker()), **kwargs)

    def test_literal_true_passes(self):
        result = self.guarded().run(lambda: True)
        self.assertEqual(result.outcome, CheckOutcome.PASS)
        self.assertIsNotNone(result.provenance)

    def test_false_fails(self):
        result = self.guarded().run(lambda: False)
        self.assertEqual(result.outcome, CheckOutcome.FAIL)

    def test_truthy_non_boolean_fails_closed(self):
        result = self.guarded().run(lambda: "yes")
        self.assertEqual(result.outcome, CheckOutcome.FAIL)

    def test_exception_fails_without_message_leak(self):
        def fail(): raise RuntimeError("secret detail")
        result = self.guarded().run(fail)
        self.assertEqual(result.outcome, CheckOutcome.FAIL)
        self.assertNotIn("secret detail", result.detail)

    def test_timeout_is_explicit(self):
        result = self.guarded(timeout_seconds=0.001).run(lambda: time.sleep(0.02) or True)
        self.assertEqual(result.outcome, CheckOutcome.TIMEOUT)
        self.assertIsNone(result.provenance)

    def test_open_circuit_blocks_call(self):
        breaker = CircuitBreaker(failure_threshold=1)
        breaker.record_failure()
        called = False
        def operation():
            nonlocal called
            called = True
            return True
        result = self.guarded(breaker=breaker).run(operation)
        self.assertEqual(result.outcome, CheckOutcome.CIRCUIT_OPEN)
        self.assertFalse(called)

    def test_required_flag_is_preserved(self):
        self.assertFalse(self.guarded().run(lambda: True, required=False).required)

    def test_nonpositive_timeout_is_rejected(self):
        with self.assertRaises(ValueError): self.guarded(timeout_seconds=0).run(lambda: True)


if __name__ == "__main__":
    unittest.main()

