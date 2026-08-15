# Evidence Ledger

Tamper-evident append-only hash-chain evidence records.

Offline Python 3.11+ MVP with zero runtime dependencies, deterministic JSON evidence, bounded inputs, a CLI, synthetic tests, and fail-visible errors.

## Usage

```bash
python -m evidence_ledger.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

Input is a JSON object matching the public `run(data)` API in `evidence_ledger.core`. With no path, the CLI reads stdin.

Apache License 2.0.

