"""TrustKit defensive policy core."""

from .adapters import (
    AdapterContractError,
    AdapterResult,
    normalize_env_example,
    normalize_permission_matrix,
    normalize_secrets,
    normalize_security_headers,
    normalize_source,
    normalize_ssrf,
)
from .core import Category, Finding, FindingState, Severity, Verdict, evaluate
from .redaction import redact

__all__ = [
    "AdapterContractError",
    "AdapterResult",
    "Category",
    "Finding",
    "FindingState",
    "Severity",
    "Verdict",
    "evaluate",
    "normalize_env_example",
    "normalize_permission_matrix",
    "normalize_secrets",
    "normalize_security_headers",
    "normalize_source",
    "normalize_ssrf",
    "redact",
]
__version__ = "0.1.0"
