"""Offline, bounded webhook validation with optional trusted HMAC verification."""

import argparse
import hashlib
import hmac
import json
import re
import time
from pathlib import PurePosixPath

MAX_BODY = 1_048_576
MAX_HEADERS = 100
MAX_HEADER_BYTES = 16_384
HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
EVENT_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def _failure(*errors):
    return {"accepted": False, "errors": list(errors), "assurance": "none"}


def inspect_webhook(event, max_body=65_536, *, trusted_key=None, now=None,
                    replay_window=300, seen_ids=None):
    """Validate one synthetic request; no listener or network operation occurs.

    ``trusted_key`` and ``seen_ids`` are caller-supplied trust inputs and are never
    read from the event or included in output. With no key, the result describes
    structural validity only.
    """
    if (not isinstance(event, dict) or set(event) != {"method", "path", "headers", "body"}
            or not isinstance(max_body, int) or isinstance(max_body, bool)
            or not 0 <= max_body <= MAX_BODY):
        return _failure("invalid_input")
    method, path, headers, body = (event[k] for k in ("method", "path", "headers", "body"))
    errors = []
    try:
        path_bytes = path.encode("utf-8") if isinstance(path, str) else None
    except UnicodeEncodeError:
        path_bytes = None
    if method not in {"POST", "PUT", "PATCH"}:
        errors.append("method_not_allowed")
    if (path_bytes is None or not 1 <= len(path) <= 2_048 or not path.startswith("/")
            or "\\" in path or any(ord(c) < 32 for c in path)
            or "?" in path or "#" in path or ".." in PurePosixPath(path).parts):
        errors.append("invalid_path")
    normalized = {}
    header_bytes = 0
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        errors.append("invalid_headers")
    else:
        for name, value in headers.items():
            try:
                encoded_name = name.encode("utf-8") if isinstance(name, str) else None
                encoded_value = value.encode("utf-8") if isinstance(value, str) else None
            except UnicodeEncodeError:
                encoded_name = encoded_value = None
            if (encoded_name is None or encoded_value is None or not HEADER_NAME.fullmatch(name)
                    or len(value) > 4_096 or any(ord(c) < 32 and c != "\t" for c in value)):
                errors.append("invalid_headers")
                break
            lower = name.lower()
            if lower in normalized:
                errors.append("duplicate_header")
                break
            normalized[lower] = value
            header_bytes += len(encoded_name) + len(encoded_value)
        if header_bytes > MAX_HEADER_BYTES:
            errors.append("header_limit")
    if not isinstance(body, str):
        errors.append("invalid_body")
        body_bytes = b""
    else:
        try:
            body_bytes = body.encode("utf-8")
        except UnicodeEncodeError:
            body_bytes = b""
            errors.append("invalid_body")
        if len(body_bytes) > max_body:
            errors.append("body_limit")

    assurance = "structural_only"
    event_id = None
    if trusted_key is not None:
        assurance = "hmac_sha256"
        if not isinstance(trusted_key, bytes) or not 1 <= len(trusted_key) <= 1_024:
            errors.append("invalid_trusted_key")
        if (not isinstance(replay_window, int) or isinstance(replay_window, bool)
                or not 1 <= replay_window <= 86_400
                or seen_ids is not None and not isinstance(seen_ids, set)):
            errors.append("invalid_replay_policy")
        timestamp = normalized.get("x-webhook-timestamp")
        event_id = normalized.get("x-webhook-id")
        signature = normalized.get("x-webhook-signature", "")
        if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp.isdigit():
            errors.append("invalid_timestamp")
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
            errors.append("invalid_event_id")
        if not signature.startswith("sha256=") or not HEX64.fullmatch(signature[7:]):
            errors.append("invalid_signature")
        if not errors:
            current = int(time.time()) if now is None else now
            if not isinstance(current, int) or isinstance(current, bool):
                errors.append("invalid_clock")
            elif abs(current - int(timestamp)) > replay_window:
                errors.append("stale_timestamp")
            elif seen_ids is not None and event_id in seen_ids:
                errors.append("replayed_event")
            else:
                signed = timestamp.encode() + b"." + event_id.encode() + b"." + body_bytes
                expected = hmac.new(trusted_key, signed, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, signature[7:]):
                    errors.append("signature_mismatch")
    canonical = json.dumps({"method": method if isinstance(method, str) else None,
                            "path": path if isinstance(path, str) else None,
                            "headers": normalized, "body": body if isinstance(body, str) else None},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    accepted = not errors
    if accepted and trusted_key is not None and seen_ids is not None:
        seen_ids.add(event_id)
    return {"accepted": accepted, "errors": errors, "assurance": assurance,
            "request_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "bytes": len(body_bytes)}


def probe():
    good = inspect_webhook({"method": "POST", "path": "/demo", "headers": {}, "body": "{}"})
    bad = inspect_webhook({"method": "GET", "path": "../x", "headers": {}, "body": ""})
    return {"ok": good["accepted"] and not bad["accepted"], "control": good["accepted"],
            "counter_proof": not bad["accepted"], "assurance": "structural_only"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("inspect", "probe"))
    parser.add_argument("--input")
    args = parser.parse_args(argv)
    try:
        data = json.load(open(args.input, encoding="utf-8")) if args.input else None
        out = probe() if args.command == "probe" else inspect_webhook(data)
    except (OSError, UnicodeError, json.JSONDecodeError):
        out = _failure("input_unreadable")
    print(json.dumps(out, sort_keys=True))
    return 0 if out.get("ok", out.get("accepted", False)) else 2
