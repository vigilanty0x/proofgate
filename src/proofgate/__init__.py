"""ProofGate public API."""

from .contract import Contract, ContractError, load_contract
from .engine import Gate, Verdict
from .journal import EventJournal, JournalError

__all__ = [
    "Contract",
    "ContractError",
    "EventJournal",
    "Gate",
    "JournalError",
    "Verdict",
    "load_contract",
]
__version__ = "0.1.0"

