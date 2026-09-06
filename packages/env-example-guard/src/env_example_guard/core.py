"""Environment/example parity with a non-bypassable baseline secret policy."""

import re

MAX_KEYS = 10_000
MAX_EXAMPLE_BYTES = 1_000_000
SENSITIVE_NAME = re.compile(r"(?i)(?:^|_)(?:api_?key|auth|credential|database_url|dsn|password|private_?key|secret|token)(?:$|_)")
SENSITIVE_VALUE = re.compile(
    r"(?:\bAKIA[0-9A-Z]{16}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{20,}\b|\bsk_live_[A-Za-z0-9]{20,}\b|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)",
    re.IGNORECASE,
)
PLACEHOLDERS = {"", "<replace-me>", "<required>", "changeme", "replace-me", "example"}


def parse(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_EXAMPLE_BYTES:
        raise ValueError("example text must be a bounded string")
    result = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid line {number}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            raise ValueError(f"invalid key at line {number}")
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    if len(result) > MAX_KEYS:
        raise ValueError("example key limit exceeded")
    return result


def check(actual_keys, example_text, secret_keys=()):
    if not isinstance(actual_keys, list) or len(actual_keys) > MAX_KEYS:
        raise ValueError("actual_keys must be a bounded list")
    if len(set(actual_keys)) != len(actual_keys) or any(not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key) for key in actual_keys):
        raise ValueError("actual_keys must contain unique environment names")
    if not isinstance(secret_keys, (list, tuple)) or len(secret_keys) > MAX_KEYS or any(not isinstance(key, str) for key in secret_keys):
        raise ValueError("secret_keys must be a bounded list")
    example = parse(example_text)
    actual = set(actual_keys)
    keys = set(example)
    trusted_sensitive = {key for key in keys if SENSITIVE_NAME.search(key)} | set(secret_keys)
    leaked = sorted(
        key
        for key, value in example.items()
        if (key in trusted_sensitive and value.casefold() not in PLACEHOLDERS) or SENSITIVE_VALUE.search(value)
    )
    missing = sorted(actual - keys)
    extra = sorted(keys - actual)
    if not actual and not keys:
        status = "inconclusive"
    else:
        status = "verified" if not missing and not extra and not leaked else "blocked"
    return {"status": status, "missing": missing, "extra": extra, "leaked": leaked}


def run(data):
    if not isinstance(data, dict) or not {"actual_keys", "example_text"} <= set(data) or set(data) - {"actual_keys", "example_text", "secret_keys"}:
        raise ValueError("input must contain actual_keys and example_text with optional secret_keys")
    return check(**data)
