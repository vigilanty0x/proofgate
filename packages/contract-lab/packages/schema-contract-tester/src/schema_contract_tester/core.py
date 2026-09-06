"""Strict bounded JSON record/schema compatibility checks."""

import json
import math

MAX_RECORDS = 100_000
MAX_FIELDS = 1_000
MAX_ERRORS = 1_000
MAX_TOTAL_BYTES = 20_000_000
TYPES = {"string", "integer", "number", "boolean", "object", "array"}


def _validate_schema(schema):
    if not isinstance(schema, dict) or not 1 <= len(schema) <= MAX_FIELDS:
        raise ValueError("schema must be a bounded nonempty object")
    for field, spec in schema.items():
        if not isinstance(field, str) or not field or len(field.encode("utf-8")) > 256:
            raise ValueError("schema field names must be bounded nonempty strings")
        if not isinstance(spec, dict) or "type" not in spec or set(spec) - {"type", "required", "nullable"}:
            raise ValueError("field specifications have an invalid shape")
        if spec["type"] not in TYPES:
            raise ValueError("unsupported schema type")
        if any(key in spec and not isinstance(spec[key], bool) for key in ("required", "nullable")):
            raise ValueError("required and nullable must be booleans")


def _matches(value, kind):
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    expected = {"string": str, "boolean": bool, "object": dict, "array": list}[kind]
    return isinstance(value, expected)


def test_records(records, schema, *, allow_empty=False):
    if not isinstance(allow_empty, bool):
        raise ValueError("allow_empty must be a boolean")
    if not isinstance(records, list) or len(records) > MAX_RECORDS or (not records and not allow_empty):
        raise ValueError("records must be a bounded list; empty input requires allow_empty")
    _validate_schema(schema)
    total_bytes = 0
    for row in records:
        if not isinstance(row, dict) or len(row) > MAX_FIELDS or any(not isinstance(key, str) for key in row):
            raise ValueError("each record must be a bounded JSON object")
        try:
            encoded = json.dumps(row, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("records must contain finite JSON values") from exc
        total_bytes += len(encoded)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("aggregate record byte limit exceeded")
    errors = []
    truncated = False
    for index, row in enumerate(records):
        for field, spec in schema.items():
            if field not in row:
                if spec.get("required", False):
                    errors.append({"row": index, "field": field, "error": "missing"})
                continue
            value = row[field]
            if value is None and spec.get("nullable", False):
                continue
            if not _matches(value, spec["type"]):
                errors.append({"row": index, "field": field, "error": "type"})
            if len(errors) >= MAX_ERRORS:
                truncated = True
                break
        if truncated:
            break
    return {
        "status": "compatible" if not errors else "blocked",
        "errors": errors,
        "errors_truncated": truncated,
        "records": len(records),
    }


def run(data):
    if not isinstance(data, dict) or not {"records", "schema"} <= set(data) or set(data) - {"records", "schema", "allow_empty"}:
        raise ValueError("input must contain records and schema with optional allow_empty")
    return test_records(**data)
