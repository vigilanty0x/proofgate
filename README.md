# Audit Trail Lite

Tamper-evident canonical audit trail with bounded actor/action queries.

Public offline Python MVP using only the standard library. Inputs are bounded, failures remain visible, and all examples/tests use synthetic data.

## CLI

```bash
python -m audit_trail_lite.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

The public Python API is `audit_trail_lite.core.run(data)`. The CLI accepts the same JSON object from a path or standard input and emits machine-readable JSON.

Apache License 2.0.

