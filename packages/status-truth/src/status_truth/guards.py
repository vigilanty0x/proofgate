"""Deterministic timeout and circuit-breaker guards."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from threading import Lock
import time
from typing import Callable

from .contract import CheckOutcome, CheckResult, Provenance, sha256_json, utc_now


class CircuitOpen(RuntimeError):
    pass


class CircuitBreaker:
    def __init__(
        self, *, failure_threshold: int = 3, reset_after_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        if reset_after_seconds < 0:
            raise ValueError("reset_after_seconds must be non-negative")
        self.failure_threshold = failure_threshold
        self.reset_after_seconds = reset_after_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return "open" if self._is_open() else "closed"

    def before_call(self) -> None:
        with self._lock:
            if self._is_open():
                raise CircuitOpen("circuit breaker is open")
            if self._opened_at is not None:
                self._opened_at = None
                self._failures = 0

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = self._clock()

    def _is_open(self) -> bool:
        return self._opened_at is not None and self._clock() - self._opened_at < self.reset_after_seconds


@dataclass(slots=True)
class GuardedCheck:
    name: str
    timeout_seconds: float
    breaker: CircuitBreaker
    collector: str = "status-truth"

    def run(self, operation: Callable[[], bool], *, required: bool = True) -> CheckResult:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        try:
            self.breaker.before_call()
        except CircuitOpen:
            return CheckResult(self.name, CheckOutcome.CIRCUIT_OPEN, required, "Circuit breaker rejected the call.")

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="status-truth-check")
        future = executor.submit(operation)
        try:
            result = future.result(timeout=self.timeout_seconds)
        except FutureTimeout:
            future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            self.breaker.record_failure()
            return CheckResult(self.name, CheckOutcome.TIMEOUT, required, "Operation exceeded the configured timeout.")
        except Exception as exc:  # checked boundary: exceptions become explicit failures
            executor.shutdown(wait=True, cancel_futures=True)
            self.breaker.record_failure()
            detail = f"Operation raised {type(exc).__name__}."
            provenance = Provenance.from_evidence(
                source="guarded-call", observed_at=utc_now(), collector=self.collector,
                evidence={"exception_type": type(exc).__name__},
            )
            return CheckResult(self.name, CheckOutcome.FAIL, required, detail, provenance)
        executor.shutdown(wait=True, cancel_futures=True)
        outcome = CheckOutcome.PASS if result is True else CheckOutcome.FAIL
        if outcome is CheckOutcome.PASS:
            self.breaker.record_success()
        else:
            self.breaker.record_failure()
        evidence = {"boolean_result": result, "type": type(result).__name__}
        provenance = Provenance(
            source="guarded-call", observed_at=utc_now(), collector=self.collector,
            evidence_sha256=sha256_json(evidence),
        )
        detail = "Operation returned true." if result is True else "Operation did not return literal true."
        return CheckResult(self.name, outcome, required, detail, provenance)

