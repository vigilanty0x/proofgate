# Status Truth

Status Truth is a small, dependency-free Python library for turning raw checks into
honest machine-readable states. It is designed for dashboards and agents that must
never display an error, timeout, missing proof, or open circuit as success.

The public contract distinguishes five states:

| State | Meaning | `success` |
| --- | --- | --- |
| `healthy` | Every required check has explicit passing evidence | `true` |
| `degraded` | Required proof passed, but an optional check did not | `false` |
| `failed` | A required check has explicit failure evidence | `false` |
| `blocked` | A timeout or open circuit prevented required proof | `false` |
| `unknown` | Required evidence is absent or inconclusive | `false` |

Diagnostics are also typed as `proof`, `inference`, or `blockage`, so consumers do
not have to guess how a conclusion was reached.

## Quick start

```python
from status_truth import CheckOutcome, CheckResult, Provenance, normalize

provenance = Provenance.from_evidence(
    source="synthetic-monitor",
    observed_at="2026-01-01T00:00:00Z",
    collector="demo",
    evidence={"http_status": 200},
)
record = normalize(
    subject="demo-api",
    operation_id="demo-001",
    checks=[CheckResult("http", CheckOutcome.PASS, provenance=provenance)],
    recorded_at="2026-01-01T00:00:00Z",
)
assert record.success is True
```

Run the synthetic demo without credentials or network access:

```bash
PYTHONPATH=src python -m status_truth assess \
  --input examples/healthy.json --journal /tmp/status-truth-demo.jsonl
PYTHONPATH=src python -m status_truth verify \
  --journal /tmp/status-truth-demo.jsonl
PYTHONPATH=src python -m status_truth probe functional
```

Non-healthy assessments return exit code `2`; invalid input or journal corruption
returns `1`; a failed probe returns `3`. JSON output is stable and compact.

## Guarantees

- bounded JSON input (1 MB, at most 100 uniquely named checks)
- pass/fail results require provenance with a SHA-256 evidence digest
- append-only, hash-chained JSONL journal
- idempotent operation IDs: exact logical replays return the original journal ID
- conflicting reuse of an operation ID is rejected
- timeouts, exceptions, and circuit-open calls remain non-success states
- deterministic normalization with zero runtime dependencies

See [the contract](docs/CONTRACT.md), [architecture](docs/ARCHITECTURE.md),
[failure model](docs/FAILURE_MODEL.md), and [public safety boundary](docs/SAFETY.md).

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python scripts/check.py
PIP_NO_INDEX=1 python -m pip wheel . --no-deps --no-build-isolation -w dist
```

Licensed under Apache-2.0.

