# Audit Trail Lite

## Purpose

Tamper-evident canonical audit-chain integrity with optional trusted-head authentication. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It is not an immutable log service, timestamp authority, signer, or durable storage system.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
audit-trail-lite examples/basic.json
python -m audit_trail_lite.cli examples/basic.json
```

The JSON-facing public API is `audit_trail_lite.core.run(data)`, which accepts only stored events and always reports integrity-only assurance. Applications may call `verify(events, trusted_head=...)` programmatically only after loading the head through an independently trusted configuration or storage boundary.

## Example

The example verifies one complete stored synthetic event and reports integrity-only assurance.

```bash
audit-trail-lite examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Verification checks exact stored fields, indices, previous links, hashes, and count. JSON and CLI input cannot provide a trusted head, so a valid CLI result is always explicitly `integrity_only`. Optional authenticity verification is confined to the separate programmatic `verify` boundary.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

An attacker who can replace the entire chain can rebuild consistent hashes. Store the head independently to obtain authenticity evidence, and never copy a head from the event payload into the programmatic trusted-head argument.

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
