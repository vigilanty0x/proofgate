"""Public API for Status Truth."""

from .contract import (
    CheckOutcome,
    CheckResult,
    Diagnostic,
    DiagnosticKind,
    Provenance,
    StatusPolicy,
    StatusRecord,
    TruthState,
)
from .engine import normalize
from .guards import CircuitBreaker, CircuitOpen, GuardedCheck
from .journal import AppendOnlyJournal, IdempotencyConflict, JournalCorruption
from .service import StatusTruthService

__all__ = [
    "AppendOnlyJournal",
    "CheckOutcome",
    "CheckResult",
    "CircuitBreaker",
    "CircuitOpen",
    "Diagnostic",
    "DiagnosticKind",
    "GuardedCheck",
    "IdempotencyConflict",
    "JournalCorruption",
    "Provenance",
    "StatusPolicy",
    "StatusRecord",
    "StatusTruthService",
    "TruthState",
    "normalize",
]

__version__ = "0.1.0"

