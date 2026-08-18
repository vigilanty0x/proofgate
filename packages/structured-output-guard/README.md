# Structured Output Guard

Fail-closed JSON structure validation using a bounded schema subset.

Offline Python 3.11+ MVP with zero runtime dependencies, deterministic JSON evidence, bounded inputs, a CLI, synthetic tests, and fail-visible errors.

## Usage

```bash
python -m structured_output_guard.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

Input is a JSON object matching the public `run(data)` API in `structured_output_guard.core`. With no path, the CLI reads stdin.

Apache License 2.0.

