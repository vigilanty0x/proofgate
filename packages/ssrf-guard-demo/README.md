# SSRF Guard Demo

## Purpose

URL and resolved-address validation for SSRF-resistant outbound request design. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It is not an HTTP client and does not itself enforce which IP a separate client connects to.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
ssrf-guard-demo examples/basic.json
python -m ssrf_guard_demo.cli examples/basic.json
```

The public API is `ssrf_guard_demo.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example permits a documentation-only public IP literal without using DNS.

```bash
ssrf-guard-demo examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Hosts are IDNA/trailing-dot canonicalized; credentials, unsafe schemes, ports, local namespaces, alternate numeric forms, mapped IPv6, and non-global addresses are blocked. Every A/AAAA answer must be global, and the decision returns a connection binding.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

The caller must make its HTTP client connect only to a returned address while preserving the validated Host/TLS identity. Every redirect must be parsed, resolved, validated, and rebound again.

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

