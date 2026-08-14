# ProofGate

ProofGate is a dependency-free Python CLI and library for one strict rule:

> A task reaches `DONE` only when every declared proof, test, and artifact satisfies its contract.

It evaluates machine-readable JSON contracts, classifies every observation as proof, inference, or blockage, and can record verdicts in a tamper-evident append-only journal. Missing or invalid evidence never becomes success.

## Why

Automation often marks work complete because a process ended, a message was posted, or an agent said it was done. ProofGate makes completion reproducible: the final state follows from explicit evidence that another person or CI runner can evaluate again.

## Install

ProofGate requires Python 3.11 or newer and has no runtime dependencies.

```bash
python -m pip install .
proofgate --version
```

For isolated command-line use:

```bash
pipx install .
```

## Five-minute demo

Clone the repository, then run the bundled synthetic example:

```bash
proofgate validate examples/proofgate.json
proofgate check examples/proofgate.json --root .
proofgate run examples/proofgate.json \
  --root . \
  --journal .proofgate/demo-events.jsonl \
  --idempotency-key demo-001
proofgate replay .proofgate/demo-events.jsonl
```

`check` intentionally refuses to execute command evidence, so it reports that evidence as an inference and exits with code 2. `run` executes the bounded argument array (never a shell string), verifies all three rules, appends a verdict, and reaches `DONE`.

## Contract

```json
{
  "contract_version": "1.0",
  "task": {
    "id": "example-release",
    "initial_state": "PENDING",
    "terminal_state": "DONE"
  },
  "timeout_seconds": 30,
  "circuit_breaker": {"failure_threshold": 3},
  "evidence": [
    {
      "id": "tests",
      "type": "command",
      "command": ["python", "-c", "print('synthetic test passed')"],
      "expect_exit": 0
    },
    {
      "id": "artifact",
      "type": "file",
      "path": "examples/artifact.txt",
      "min_bytes": 1
    },
    {
      "id": "report",
      "type": "json",
      "path": "examples/report.json",
      "pointer": "/checks/passed",
      "equals": true
    }
  ]
}
```

Rules are closed by default: unknown fields, duplicate JSON keys, parent traversal, absolute paths, invalid digests, oversized input, and unbounded timeouts are rejected.

## CLI

| Command | Purpose | Success exit |
|---|---|---:|
| `proofgate init [path]` | Write an example contract without overwriting by default | 0 |
| `proofgate validate CONTRACT` | Validate syntax, vocabulary, and safety bounds | 0 |
| `proofgate check CONTRACT --root ROOT` | Evaluate passive file/JSON evidence; do not execute commands | 0 only if all evidence is verified |
| `proofgate run CONTRACT --root ROOT --idempotency-key KEY` | Evaluate every rule and append a verdict | 0 only for `DONE` |
| `proofgate replay JOURNAL` | Verify sequence and the complete SHA-256 hash chain | 0 |

Exit code 2 means the gate blocked completion. Exit code 3 means the contract, journal, or invocation was invalid. Add `--json` for stable machine-readable output.

## Python API

```python
from proofgate import EventJournal, Gate, load_contract

contract = load_contract("proofgate.json")
verdict = Gate(contract, root=".").evaluate(
    execute_commands=True,
    journal=EventJournal(".proofgate/events.jsonl"),
    idempotency_key="release-attempt-7",
)

if not verdict.done:
    raise SystemExit(verdict.reason_code)
```

## Reliability properties

- `DONE` is produced only when every rule returns verified proof.
- Reusing an idempotency key with the same verdict returns the existing event; changing its meaning is a conflict.
- Events use a sequence number, previous hash, and canonical SHA-256 event hash.
- Command rules use `shell=False`, bounded argument arrays, a working-directory root, output limits, and timeouts.
- Reaching the configured failure threshold opens the circuit before any command runs.
- Symlinks and resolved paths cannot escape the evaluation root.
- Errors retain stable codes and cannot be silently converted into success.

See [SPEC.md](SPEC.md) for the state contract and failure semantics, [SECURITY.md](SECURITY.md) for the threat boundary, and [AI_ASSISTANCE.md](AI_ASSISTANCE.md) for construction provenance.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Contributions are welcome under the Apache-2.0 license. All examples and fixtures in this repository are synthetic.

