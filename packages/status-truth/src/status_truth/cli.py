"""Bounded JSON CLI for Status Truth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from .contract import CheckResult, ContractError, StatusPolicy, canonical_json
from .journal import AppendOnlyJournal, JournalError
from .probes import functional_counter_proof, liveness, readiness
from .service import StatusTruthService

MAX_INPUT_BYTES = 1_000_000


def _load(path: Path) -> Mapping[str, Any]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ContractError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ContractError("input root must be an object")
    return value


def _assess(args: argparse.Namespace) -> int:
    value = _load(args.input)
    checks = value.get("checks")
    if not isinstance(checks, list):
        raise ContractError("checks must be an array")
    policy_value = value.get("policy", {})
    if not isinstance(policy_value, Mapping):
        raise ContractError("policy must be an object")
    policy = StatusPolicy(
        policy_value.get("name", "fail-closed-v1"), tuple(policy_value.get("required_names", ()))
    )
    service = StatusTruthService(AppendOnlyJournal(args.journal))
    record, entry = service.assess(
        subject=value.get("subject"), operation_id=value.get("operation_id"),
        checks=[CheckResult.from_dict(item) for item in checks if isinstance(item, Mapping)],
        policy=policy, recorded_at=value.get("recorded_at"), metadata=value.get("metadata", {}),
    )
    print(canonical_json({"journal_id": entry.journal_id, "record": record.to_dict()}))
    return 0 if record.success else 2


def _verify(args: argparse.Namespace) -> int:
    print(canonical_json(AppendOnlyJournal(args.journal).verify()))
    return 0


def _probe(args: argparse.Namespace) -> int:
    if args.kind == "liveness":
        result = liveness()
    elif args.kind == "readiness":
        result = readiness(args.journal)
    else:
        result = functional_counter_proof()
    print(canonical_json(result))
    return 0 if result["ok"] else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="status-truth", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assess = commands.add_parser("assess", help="normalize and append a bounded JSON assessment")
    assess.add_argument("--input", type=Path, required=True)
    assess.add_argument("--journal", type=Path, required=True)
    assess.set_defaults(run=_assess)
    verify = commands.add_parser("verify", help="verify a journal hash chain")
    verify.add_argument("--journal", type=Path, required=True)
    verify.set_defaults(run=_verify)
    probe = commands.add_parser("probe", help="run an offline health probe")
    probe.add_argument("kind", choices=("liveness", "readiness", "functional"))
    probe.add_argument("--journal", type=Path, default=Path("status-truth.jsonl"))
    probe.set_defaults(run=_probe)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.run(args))
    except (ContractError, JournalError, OSError, json.JSONDecodeError) as exc:
        print(canonical_json({"error": type(exc).__name__, "message": str(exc), "success": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

