from __future__ import annotations
import hashlib, json
from typing import Any

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

def canonical_roundtrip(value: Any) -> Any:
    return json.loads(canonical_bytes(value).decode("utf-8"))
