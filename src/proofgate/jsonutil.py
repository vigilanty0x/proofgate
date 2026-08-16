"""Small strict-JSON helpers shared by ProofGate's public formats."""

from __future__ import annotations

import json
import math
from typing import Any, Callable


class StrictJSONError(ValueError):
    """A value uses an extension that is not valid RFC 8259 JSON."""


def _reject_constant(token: str) -> None:
    raise StrictJSONError(f"non-finite JSON number is not allowed: {token}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictJSONError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _validate_keys_and_numbers(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StrictJSONError("JSON object keys must be strings")
            _validate_keys_and_numbers(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_keys_and_numbers(item)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError("non-finite JSON number is not allowed")


def strict_loads(source: str, *, object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] | None = None) -> Any:
    """Parse standards-compliant JSON while retaining a caller's duplicate-key hook."""

    try:
        return json.loads(
            source,
            object_pairs_hook=object_pairs_hook or _unique_object,
            parse_constant=_reject_constant,
        )
    except RecursionError as exc:
        raise StrictJSONError("JSON nesting is too deep") from exc


def strict_dumps(value: Any, **kwargs: Any) -> str:
    """Serialize only values whose keys and numbers have unambiguous JSON meaning."""

    try:
        _validate_keys_and_numbers(value)
        return json.dumps(value, allow_nan=False, **kwargs)
    except RecursionError as exc:
        raise StrictJSONError("JSON nesting is too deep") from exc


def strict_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int equality ambiguity.

    Container types and every nested scalar type must match.  This matters because
    Python otherwise considers ``True == 1`` and ``False == 0`` even inside lists
    and dictionaries.
    """

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return False
        return all(strict_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(
            strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return bool(left == right)
