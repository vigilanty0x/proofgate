"""Command line interface for ProofGate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .contract import ContractError, load_contract
from .diffing import DiffError, compare_verdicts, load_json_document
from .engine import Gate
from .journal import EventJournal, JournalError
from .receipt import ReceiptError, create_receipt, load_receipt, verify_receipt, write_receipt
from .suite import SuiteError, evaluate_suite, load_suite


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

REASON_CODES: dict[str, str] = {
    "ALL_EVIDENCE_VERIFIED": "Every required evidence rule produced verified proof.",
    "POLICY_SATISFIED": "The explicit any/threshold evidence policy was satisfied; failed rules remain visible.",
    "EVIDENCE_INCOMPLETE": "The policy was not satisfied because evidence is missing, blocked, or inferred.",
    "EVIDENCE_FAILED": "An executed command contradicted its expected result or could not complete.",
    "COMMAND_CLEANUP_INCOMPLETE": "A command exited while a descendant still held a captured output stream open.",
    "DEPENDENCY_BLOCKED": "A rule or contract was not evaluated because one of its declared dependencies failed.",
    "CIRCUIT_OPEN": "Recorded failures reached the configured threshold, so command execution was refused.",
    "RECEIPT_VERIFIED": "The receipt schema, self-hash, and requested artifact hashes were verified.",
    "ARTIFACT_HASH_MISMATCH": "An artifact no longer matches the digest bound into a receipt.",
    "SUITE_INCOMPLETE": "At least one contract in the suite did not reach verified DONE.",
    "RECEIPT_NOT_DONE": "The receipt is intact but its recorded verdict did not reach verified DONE.",
}


class UsageError(ValueError):
    """Command-line arguments do not satisfy the public invocation contract."""


class _ProofGateParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _ProofGateParser(prog="proofgate", description="Verify task completion from explicit evidence contracts.")
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

    receipt = sub.add_parser("receipt", help="evaluate a contract and write a portable evidence receipt")
    receipt.add_argument("contract")
    receipt.add_argument("--root", default=".")
    receipt.add_argument("--output", required=True)
    receipt.add_argument("--execute", action="store_true", help="run bounded command evidence")
    receipt.add_argument("--journal")
    receipt.add_argument("--idempotency-key")
    receipt.add_argument("--json", action="store_true", dest="json_output")

    verify_receipt_parser = sub.add_parser("verify-receipt", help="verify a receipt and its bound artifacts")
    verify_receipt_parser.add_argument("receipt")
    verify_receipt_parser.add_argument("--root", default=".")
    verify_receipt_parser.add_argument("--no-artifacts", action="store_true")
    verify_receipt_parser.add_argument("--json", action="store_true", dest="json_output")

    suite = sub.add_parser("suite", help="evaluate a dependency-ordered suite of contracts")
    suite.add_argument("suite")
    suite.add_argument("--root", default=".")
    suite.add_argument("--execute", action="store_true")
    suite.add_argument("--journal-dir")
    suite.add_argument("--idempotency-prefix")
    suite.add_argument("--json", action="store_true", dest="json_output")

    diff = sub.add_parser("diff", help="compare two verdicts or receipt verdict summaries")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--json", action="store_true", dest="json_output")

    explain = sub.add_parser("explain", help="explain a stable ProofGate reason code")
    explain.add_argument("code")
    explain.add_argument("--json", action="store_true", dest="json_output")
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
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    try:
        args = _parser().parse_args(raw_args)
    except UsageError as exc:
        payload = {"error": "UsageError", "message": str(exc)}
        if "--json" in raw_args:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 3
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

        if args.command == "receipt":
            if bool(args.journal) != bool(args.idempotency_key):
                raise ReceiptError("--journal and --idempotency-key must be provided together")
            contract = load_contract(args.contract)
            journal = EventJournal(args.journal) if args.journal else None
            verdict = Gate(contract, root=args.root).evaluate(
                execute_commands=args.execute,
                journal=journal,
                idempotency_key=args.idempotency_key,
            )
            receipt = create_receipt(contract, verdict, root=args.root, journal=journal)
            write_receipt(args.output, receipt)
            payload = {
                "written": str(Path(args.output)),
                "task_id": contract.task_id,
                "state": verdict.state,
                "status": verdict.status,
                "reason_code": verdict.reason_code,
                "receipt_sha256": receipt["receipt_sha256"],
                "artifacts": len(receipt["artifacts"]),
            }
            _emit(payload, json_output=args.json_output)
            return 0 if verdict.done else 2

        if args.command == "verify-receipt":
            receipt = load_receipt(args.receipt)
            verification = verify_receipt(
                receipt,
                root=args.root,
                verify_artifacts=not args.no_artifacts,
            )
            payload = {**verification.as_dict(), "task_id": receipt["task_id"], "receipt_sha256": receipt["receipt_sha256"]}
            _emit(payload, json_output=args.json_output)
            return 0 if verification.valid else 2

        if args.command == "suite":
            suite = load_suite(args.suite)
            verdict = evaluate_suite(
                suite,
                root=args.root,
                execute_commands=args.execute,
                journal_dir=args.journal_dir,
                idempotency_prefix=args.idempotency_prefix,
            )
            _emit(verdict.as_dict(), json_output=args.json_output)
            return 0 if verdict.done else 2

        if args.command == "diff":
            result = compare_verdicts(load_json_document(args.before), load_json_document(args.after))
            _emit(result, json_output=args.json_output)
            return 2 if result["regression"] else 0

        if args.command == "explain":
            code = args.code.upper()
            if code not in REASON_CODES:
                raise ValueError(f"unknown reason code: {code}")
            _emit({"code": code, "message": REASON_CODES[code]}, json_output=args.json_output)
            return 0

        journal_path = Path(args.journal)
        if not journal_path.is_file():
            raise JournalError(f"journal does not exist: {journal_path}")
        replay = EventJournal(journal_path).replay()
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
    except (ContractError, DiffError, JournalError, ReceiptError, SuiteError, ValueError) as exc:
        payload = {"error": type(exc).__name__, "message": str(exc)}
        json_output = bool(getattr(args, "json_output", False))
        if json_output:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
