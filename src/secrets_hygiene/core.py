"""Bounded, provider-aware secret scanning with redacted findings."""

from collections import Counter
import math
import re

MAX_FILES = 1_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 10_000_000
MAX_FINDINGS = 1_000
MAX_ENTROPY_CANDIDATES_PER_LINE = 32

PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "bearer_token": re.compile(r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "stripe_live_key": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
    "pem_private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "connection_credential": re.compile(r"(?i)\b(?:database_url|connection_string|dsn)\s*=\s*[a-z][a-z0-9+.-]*://[^\s:/]+:[^\s@]+@"),
    "sensitive_assignment": re.compile(r"(?i)\b(?:api[_-]?key|password|secret|token)\s*=\s*(?!<[^>]+>|replace-me\b|changeme\b)[^\s]{8,}"),
}
TOKEN = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9_+/=-]{31,199})(?![A-Za-z0-9])")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _high_entropy(value):
    if UUID.fullmatch(value) or re.fullmatch(r"[0-9a-fA-F]+", value):
        return False
    if not (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value)):
        return False
    counts = Counter(value)
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
    return entropy >= 4.2


def scan(files):
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ValueError("files must be a bounded object")
    findings = []
    total_bytes = 0
    truncated = False
    for path, content in files.items():
        if not isinstance(path, str) or not path or len(path.encode("utf-8")) > 4_096 or not isinstance(content, str):
            raise ValueError("file paths and contents must be strings")
        size = len(content.encode("utf-8"))
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("aggregate file byte limit exceeded")
        if size > MAX_FILE_BYTES:
            findings.append({"path": path, "kind": "size_blocked", "line": None})
            continue
        for number, line in enumerate(content.splitlines(), 1):
            kinds = {kind for kind, pattern in PATTERNS.items() if pattern.search(line)}
            candidates = TOKEN.findall(line)[:MAX_ENTROPY_CANDIDATES_PER_LINE]
            if any(_high_entropy(candidate) for candidate in candidates):
                kinds.add("high_entropy")
            for kind in sorted(kinds):
                findings.append({"path": path, "kind": kind, "line": number})
                if len(findings) >= MAX_FINDINGS:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    return {"status": "clean" if not findings else "blocked", "findings": findings, "findings_truncated": truncated}


def run(data):
    if not isinstance(data, dict) or set(data) != {"files"}:
        raise ValueError("input must contain exactly files")
    return scan(**data)
