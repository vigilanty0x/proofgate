# SSRF Guard Demo

Offline URL/IP policy guard blocking private, local, credentialed, and unsafe targets.

Public offline Python MVP using only the standard library. Inputs are bounded, failures remain visible, and all examples/tests use synthetic data.

## CLI

```bash
python -m ssrf_guard_demo.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

The public Python API is `ssrf_guard_demo.core.run(data)`. The CLI accepts the same JSON object from a path or standard input and emits machine-readable JSON.

Apache License 2.0.

