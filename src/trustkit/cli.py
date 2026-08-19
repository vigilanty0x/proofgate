from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import Category, Finding, FindingState, Severity, Verdict, evaluate
from .redaction import redact


def _load(path: Path) -> tuple[list[Finding], bool]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("input must be a JSON object")
    complete = payload.get("measurement_complete")
    if not isinstance(complete, bool):
        raise ValueError("measurement_complete must be boolean")
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError("findings must be an array")

    findings: list[Finding] = []
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            raise ValueError(f"findings[{index}] must be an object")
        findings.append(
            Finding(
                finding_id=str(raw.get("id", "")),
                category=Category(str(raw.get("category", ""))),
                severity=Severity(str(raw.get("severity", ""))),
                evidence=str(raw.get("evidence", "")),
                message=str(raw.get("message", "")),
                active=raw.get("active", True) if isinstance(raw.get("active", True), bool) else True,
                state=FindingState(str(raw.get("state", "measured"))),
            )
        )
    return findings, complete


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trustkit")
    parser.add_argument("input", type=Path, help="normalized TrustKit JSON input")
    args = parser.parse_args(argv)

    try:
        findings, complete = _load(args.input)
        result = evaluate(findings, measurement_complete=complete)
        output = redact(result.as_dict())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        output = {"verdict": Verdict.BLOCKED.value, "reasons": [f"invalid_input:{type(exc).__name__}"]}
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 2

    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    if result.verdict is Verdict.PASS:
        return 0
    if result.verdict is Verdict.FAIL:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
