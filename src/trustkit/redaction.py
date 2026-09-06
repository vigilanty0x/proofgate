from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "private_key",
    "secret",
    "token",
}
_REDACTED = "[REDACTED]"


def _is_sensitive(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or normalized.endswith("_token") or normalized.endswith("_secret")


def redact(value: Any) -> Any:
    """Return a JSON-compatible defensive copy with sensitive values removed."""

    if isinstance(value, Mapping):
        return {
            str(key): (_REDACTED if _is_sensitive(key) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    return value
