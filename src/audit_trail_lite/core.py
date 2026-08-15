"""Tamper-evident audit-chain integrity and optional head authentication."""

import hashlib
import json
import re

MAX_EVENTS = 100_000
MAX_EVENT_BYTES = 100_000
EVENT_KEYS = {"index", "previous", "actor", "action", "target", "metadata", "hash"}


def _text(value, label):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1_024:
        raise ValueError(f"{label} must be a bounded nonempty string")
    return value


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("event metadata must contain finite JSON values") from exc
    if len(encoded) > MAX_EVENT_BYTES:
        raise ValueError("event byte limit exceeded")
    return encoded


def _identity(index, previous, actor, action, target, metadata):
    return {"index": index, "previous": previous, "actor": actor, "action": action, "target": target, "metadata": metadata}


def _event_shape(event):
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        raise ValueError("stored events must contain the exact chain fields")
    if isinstance(event["index"], bool) or not isinstance(event["index"], int) or event["index"] < 0:
        raise ValueError("event index must be a nonnegative integer")
    if not isinstance(event["previous"], str) or not re.fullmatch(r"[0-9a-f]{64}", event["previous"]):
        raise ValueError("event previous must be a SHA-256 digest")
    if not isinstance(event["hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", event["hash"]):
        raise ValueError("event hash must be a SHA-256 digest")
    _text(event["actor"], "actor")
    _text(event["action"], "action")
    _text(event["target"], "target")
    if not isinstance(event["metadata"], dict):
        raise ValueError("metadata must be an object")
    _canonical(event["metadata"])


def verify(events, *, trusted_head=None):
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("events must be a bounded list")
    if trusted_head is not None and (not isinstance(trusted_head, str) or not re.fullmatch(r"[0-9a-f]{64}", trusted_head)):
        raise ValueError("trusted_head must be a SHA-256 digest")
    previous = "0" * 64
    for index, event in enumerate(events):
        _event_shape(event)
        if event["index"] != index:
            return {"valid": False, "assurance": "invalid", "index": index, "reason": "index"}
        if event["previous"] != previous:
            return {"valid": False, "assurance": "invalid", "index": index, "reason": "previous"}
        identity = _identity(index, previous, event["actor"], event["action"], event["target"], event["metadata"])
        calculated = hashlib.sha256(_canonical(identity)).hexdigest()
        if event["hash"] != calculated:
            return {"valid": False, "assurance": "invalid", "index": index, "reason": "hash"}
        previous = event["hash"]
    if trusted_head is not None and trusted_head != previous:
        return {"valid": False, "assurance": "invalid", "index": len(events), "reason": "trusted_head", "count": len(events)}
    assurance = "authenticity_verified" if trusted_head is not None else "integrity_only"
    return {"valid": True, "assurance": assurance, "count": len(events), "head": previous}


def append(events, actor, action, target, metadata=None):
    if not isinstance(events, list) or len(events) >= MAX_EVENTS:
        raise ValueError("event limit exceeded")
    if events and not verify(events)["valid"]:
        raise ValueError("cannot append to an invalid chain")
    actor = _text(actor, "actor")
    action = _text(action, "action")
    target = _text(target, "target")
    metadata = {} if metadata is None else metadata
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    identity = _identity(len(events), events[-1]["hash"] if events else "0" * 64, actor, action, target, metadata)
    digest = hashlib.sha256(_canonical(identity)).hexdigest()
    return [*events, {**identity, "hash": digest}]


def query(events, actor=None, action=None):
    if actor is not None:
        _text(actor, "actor")
    if action is not None:
        _text(action, "action")
    if not verify(events)["valid"]:
        raise ValueError("cannot query an invalid chain")
    return [event for event in events if (actor is None or event["actor"] == actor) and (action is None or event["action"] == action)]


def run(data):
    if not isinstance(data, dict) or set(data) != {"events"}:
        raise ValueError("JSON input must contain exactly events; trusted heads require a separate programmatic boundary")
    events = data["events"]
    verification = verify(events)
    return {"events": events, "verification": verification}
