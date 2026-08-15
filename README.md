# Env Example Guard

Environment/example key parity with secret-value leakage prevention.

Public offline Python MVP using only the standard library. Inputs are bounded, failures remain visible, and all examples/tests use synthetic data.

## CLI

```bash
python -m env_example_guard.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

The public Python API is `env_example_guard.core.run(data)`. The CLI accepts the same JSON object from a path or standard input and emits machine-readable JSON.

Apache License 2.0.

