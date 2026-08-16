"""ProofGate public API."""

from .contract import Contract, ContractError, Policy, load_contract
from .diffing import DiffError, compare_verdicts
from .engine import Gate, Verdict
from .journal import EventJournal, JournalError
from .receipt import ReceiptError, create_receipt, load_receipt, verify_receipt, write_receipt
from .suite import Suite, SuiteError, SuiteVerdict, evaluate_suite, load_suite

__all__ = [
    "Contract",
    "ContractError",
    "DiffError",
    "EventJournal",
    "Gate",
    "JournalError",
    "Policy",
    "ReceiptError",
    "Suite",
    "SuiteError",
    "SuiteVerdict",
    "Verdict",
    "compare_verdicts",
    "create_receipt",
    "evaluate_suite",
    "load_contract",
    "load_receipt",
    "load_suite",
    "verify_receipt",
    "write_receipt",
]
__version__ = "0.2.0"
