# Secrets Hygiene

Offline secret-pattern and high-entropy hygiene scanner with redacted evidence.

Public offline Python MVP using only the standard library. Inputs are bounded, failures remain visible, and all examples/tests use synthetic data.

## CLI

```bash
python -m secrets_hygiene.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

The public Python API is `secrets_hygiene.core.run(data)`. The CLI accepts the same JSON object from a path or standard input and emits machine-readable JSON.

Apache License 2.0.

