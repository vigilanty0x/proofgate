# Run Replay

Deterministic state replay with event and final-state hashes.

Offline Python 3.11+ MVP with zero runtime dependencies, deterministic JSON evidence, bounded inputs, a CLI, synthetic tests, and fail-visible errors.

## Usage

```bash
python -m run_replay.cli input.json
python -m unittest discover -s tests -v
python scripts/check.py
```

Input is a JSON object matching the public `run(data)` API in `run_replay.core`. With no path, the CLI reads stdin.

Apache License 2.0.

