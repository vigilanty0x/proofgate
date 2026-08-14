"""Command line interface for ProofGate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .contract import ContractError, load_contract
from .engine import Gate
from .journal import EventJournal, JournalError


EXAMPLE_CONTRACT: dict[str, Any] = {
    "contract_version": "1.0",
    "task": {"id": "example-release", "initial_state": "PENDING", "terminal_state": "DONE"},
    "timeout_seconds": 30,
    "circuit_breaker": {"failure_threshold": 3},
    "evidence": [
        {"id": "tests", "type": "command", "command": ["python", "-m", "unittest"], "expect_exit": 0},
        {"id": "artifact", "type": "file", "path": "dist/artifact.txt", "min_bytes": 1},
        {"id": "report", "type": "json", "path": "report.json", "pointer": "/passed", "equals": True},
    ],
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofgate", description="Verify task completion from explicit evidence contracts.")
    parser.add_argument("--version", action="version", version=f"proofgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="write a safe example contract")
    init.add_argument("path", nargs="?", default="proofgate.json")
    init.add_argument("--force", action="store_true")

    validate = sub.add_parser("validate", help="validate a contract without evaluating evidence")
    validate.add_argument("contract")
    validate.add_argument("--json", action="store_true", dest="json_output")

    for name, help_text in (
        ("check", "check passive evidence without running commands"),
        ("run", "evaluate all evidence, including bounded commands"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("contract")
        command.add_argument("--root", default=".")
        command.add_argument("--json", action="store_true", dest="json_output")
        if name == "run":
            command.add_argument("--journal", default=".proofgate/events.jsonl")
            command.add_argument("--idempotency-key", required=True)

    replay = sub.add_parser("replay", help="validate and summarize an event journal")
    replay.add_argument("journal")
    replay.add_argument("--json", action="store_true", dest="json_output")
    return parser


def _emit(payload: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return
    if "state" in payload:
        print(f"{payload['state']}: {payload.get('reason_code', '')}")
        for result in payload.get("evidence", []):
            marker = "PASS" if result["passed"] else "BLOCK"
            print(f"  {marker} {result['id']}: {result['code']} — {result['message']}")
    else:
        print(payload.get("message", json.dumps(payload, sort_keys=True)))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            path = Path(args.path)
            if path.exists() and not args.force:
                raise ContractError(f"refusing to overwrite existing file: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(EXAMPLE_CONTRACT, indent=2) + "\n", encoding="utf-8")
            print(f"wrote {path}")
            return 0

        if args.command == "validate":
            contract = load_contract(args.contract)
            _emit(
                {"valid": True, "task_id": contract.task_id, "evidence_rules": len(contract.evidence), "message": "contract is valid"},
                json_output=args.json_output,
            )
            return 0

        if args.command in {"check", "run"}:
            contract = load_contract(args.contract)
            journal = EventJournal(args.journal) if args.command == "run" else None
            verdict = Gate(contract, root=args.root).evaluate(
                execute_commands=args.command == "run",
                journal=journal,
                idempotency_key=getattr(args, "idempotency_key", None),
            )
            _emit(verdict.as_dict(), json_output=args.json_output)
            return 0 if verdict.done else 2

        replay = EventJournal(args.journal).replay()
        payload = {
            "valid": True,
            "events": len(replay.events),
            "last_hash": replay.last_hash,
            "failures": replay.failures,
            "states": list(replay.states),
            "message": f"journal is valid ({len(replay.events)} events)",
        }
        _emit(payload, json_output=args.json_output)
        return 0
    except (ContractError, JournalError, ValueError) as exc:
        payload = {"error": type(exc).__name__, "message": str(exc)}
        json_output = bool(getattr(args, "json_output", False))
        if json_output:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

