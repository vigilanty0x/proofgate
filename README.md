# ProofGate

ProofGate is a dependency-free Python CLI and library for evidence-gated delivery pipelines:

> A task reaches `DONE` only when its declared evidence policy is satisfied by independently verified proof.

It evaluates RFC 8259 JSON contracts, dependency-ordered evidence, threshold policies, multi-contract suites, portable receipts, and tamper-evident journals. Every observation remains classified as proof, inference, or blockage. Missing or invalid evidence never becomes hidden success.

## Concrete monorepo

ProofGate is the canonical repository for evidence gates, defensive policy, and
contract verification. The root CLI decides whether work has enough proof to
reach `DONE`; the imported suites provide the security and interface evidence
that those decisions can consume.

| Area | Location | Included tools |
|---|---|---|
| Evidence gates | `.` | `proofgate` validation, execution, replay, receipts, suites, and regression diffs |
| Evidence operations | `packages/` | `audit-trail-lite`, `evidence-ledger`, `run-replay`, `status-truth`, and `structured-output-guard` |
| Defensive policy | `packages/trustkit/` | `trustkit` plus `env-example-guard`, `permission-matrix`, `secrets-hygiene`, `security-headers-lab`, and `ssrf-guard-demo` |
| Contract verification | `packages/contract-lab/` | `contract-lab` plus `api-contract-mock-server`, `schema-contract-tester`, and `webhook-sandbox` |

[`MONOREPO.json`](MONOREPO.json) binds the 16 source repositories to their
canonical paths and immutable source revisions. It deliberately records
`delete_authorized: false`: validation proves the consolidation map without
authorizing removal of any source repository.

Validate the map and run the imported suite tests from a development checkout:

```bash
python scripts/check_monorepo.py
(cd packages/trustkit && python -m unittest discover -s tests -v)
(cd packages/contract-lab && python -m unittest discover -s tests -v)
```

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
proofgate receipt examples/proofgate.json --root . --execute \
  --journal .proofgate/receipt-events.jsonl --idempotency-key demo-receipt \
  --output .proofgate/receipt.json
proofgate verify-receipt .proofgate/receipt.json --root .
```

`check` intentionally refuses to execute command evidence, so it reports that evidence as an inference and exits with code 2. `run` first claims its idempotency key, executes the bounded argument array (never a shell string), verifies all three rules, appends a redacted verdict summary, and reaches `DONE`.

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

Rules are closed by default: unknown fields, duplicate JSON keys, non-finite numbers (`NaN`/`Infinity`), parent traversal, absolute paths, invalid digests, oversized input, and unbounded timeouts are rejected.

## CLI

| Command | Purpose | Success exit |
|---|---|---:|
| `proofgate init [path]` | Write an example contract without overwriting by default | 0 |
| `proofgate validate CONTRACT` | Validate syntax, vocabulary, and safety bounds | 0 |
| `proofgate check CONTRACT --root ROOT` | Evaluate passive file/JSON evidence; do not execute commands | 0 only if all evidence is verified |
| `proofgate run CONTRACT --root ROOT --idempotency-key KEY` | Evaluate every rule and append a verdict | 0 only for `DONE` |
| `proofgate replay JOURNAL` | Verify sequence and the complete SHA-256 hash chain | 0 |
| `proofgate receipt CONTRACT` | Evaluate and atomically write a content-bound receipt | 0 only for `DONE` |
| `proofgate verify-receipt RECEIPT` | Verify receipt integrity and bound artifacts | 0 |
| `proofgate suite SUITE` | Evaluate dependency-ordered contracts | 0 only when all are `DONE` |
| `proofgate diff BEFORE AFTER` | Detect state and evidence regressions | 0 when no regression exists |
| `proofgate explain CODE` | Explain a stable reason code | 0 |

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
- A journaled run atomically claims its idempotency key before evaluating evidence. A completed retry returns the recorded verdict without re-running commands; a concurrent or interrupted attempt fails closed, and changing request meaning is a conflict.
- Events use a sequence number, previous hash, and canonical SHA-256 event hash.
- Journal reads and appends lock the journal file and reuse the locked handle for I/O, so concurrent writers cannot reuse a sequence or chain head across the supported OS matrix. Outstanding attempts retain a maximum-event reservation until their terminal verdict is appended; competing writes cannot consume it. Recorded verdicts contain bounded messages and evidence-detail digests rather than raw command output.
- Command rules use `shell=False`, bounded argument arrays, a working-directory root, output limits, and timeouts. Captured text normalizes platform newline conventions while raw byte counts remain unchanged.
- Reaching the configured failure threshold opens the circuit before any command runs.
- File, JSON, text, receipt, artifact, suite-contract, and directory reads are confined below a caller-supplied trust root and refuse symlink/reparse components. POSIX uses descriptor-relative no-follow traversal; platforms without that facility use conservative component validation plus opened-handle identity checks where available.
- Errors retain stable codes and cannot be silently converted into success.
- Evidence can depend on earlier rules; failed prerequisites block downstream evaluation.
- `all`, `any`, and explicit threshold policies are validated and reported in every verdict.
- Receipts bind canonical contracts, verdict summaries, artifact sizes and SHA-256 digests.
- Suites validate their dependency DAG before evaluating any child contract.

## Evidence types and policies

ProofGate 0.2 supports six bounded evidence types:

- `command`: trusted argument arrays executed with `shell=False`, timeout and capture limits;
- `file`: size and optional SHA-256 requirements;
- `json`: recursively type-aware equality at an RFC 6901 pointer;
- `text`: literal requirements without returning the source contents;
- `directory`: deterministic glob inventory with lower and upper bounds;
- `receipt`: verification of another ProofGate receipt, its artifacts, and a recorded `done == true` verdict.

Rules may declare `depends_on`. The graph is validated for unknown nodes and cycles. The default policy remains `all`, preserving the 0.1 invariant. `any` and `threshold` must be explicit and retain every failed rule in the verdict instead of discarding it.

```json
{
  "policy": {"mode": "threshold", "minimum_verified": 2},
  "evidence": [
    {"id": "tests", "type": "command", "command": ["python", "-m", "unittest"]},
    {"id": "package", "type": "file", "path": "dist/package.whl"},
    {"id": "notes", "type": "text", "path": "CHANGELOG.md", "contains": "Security"}
  ]
}
```

## Suites and receipts

A suite is a small DAG of contract files. A child is never evaluated when a declared prerequisite did not reach verified `DONE`. Optional journals are separated per child and require an idempotency prefix.

A receipt is portable integrity evidence, not identity. It intentionally excludes raw command output and artifact content, retains their digests, and can be nested as `receipt` evidence only when its closed verdict schema records a semantically possible verified completion. SHA-256 detects mutation; it does not prove who created the receipt. Keep the receipt or its hash in a trusted system when authorship matters. See [receipt and suite architecture](docs/ARCHITECTURE.md).

See [SPEC.md](SPEC.md) for the state contract and failure semantics, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries, [SECURITY.md](SECURITY.md) for the threat boundary, and [AI_ASSISTANCE.md](AI_ASSISTANCE.md) for construction provenance.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Contributions are welcome under the Apache-2.0 license. All examples and fixtures in this repository are synthetic.
