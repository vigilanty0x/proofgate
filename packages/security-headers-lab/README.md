# Security Headers Lab

## Purpose

Offline HTTP response security-header policy evaluation. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It does not make network requests, modify responses, or replace browser testing and application threat modeling.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
security-headers-lab examples/basic.json
python -m security_headers_lab.cli examples/basic.json
```

The public API is `security_headers_lab.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example evaluates a synthetic hardened header set.

```bash
security-headers-lab examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Header names are normalized case-insensitively. HSTS requires a parseable minimum max-age; CSP script sources reject wildcards, unsafe keywords, and unsafe schemes; referrer and sensitive permissions policies are restrictive.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

The evaluator intentionally covers a conservative policy subset and may reject deployments that rely on nonces, hashes, or broader feature policy syntax.

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

