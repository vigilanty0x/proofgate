# Secrets Hygiene

## Purpose

Offline provider-aware secret-pattern and entropy hygiene scanning with redacted evidence. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It is not a credential validity checker, complete data-loss-prevention system, or substitute for provider-side secret scanning.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
secrets-hygiene examples/basic.json
python -m secrets_hygiene.cli examples/basic.json
```

The public API is `secrets_hygiene.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example scans two harmless synthetic public files.

```bash
secrets-hygiene examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Synthetic-aware patterns cover common AWS, GitHub, bearer/JWT, Slack, Stripe, PEM, assignment, and connection-string forms. A bounded entropy heuristic adds coverage; findings contain location and kind but never matched values.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

Pattern scanners have false positives and false negatives. Rotate any real exposed credential through its provider even if this tool reports clean.

## Tests

Run the full local contract:

```bash
python -m unittest discover -s tests -v
python scripts/check.py
python -m build --no-isolation
```

CI exercises Python 3.11 and 3.12, builds and installs the wheel, then runs tests, the public-boundary check, the module example, and the installed console command.

## AI assistance

AI-assisted contribution details and validation expectations are documented in [AI_ASSISTANCE.md](AI_ASSISTANCE.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

