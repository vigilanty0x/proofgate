# Webhook Sandbox

## Purpose

Validate bounded synthetic webhook requests offline and emit deterministic SHA-256 evidence. Optional HMAC-SHA256 validation can bind a request to a separately supplied trusted key and replay store.

## Non-goals

It is not an HTTP server, delivery service, durable replay database, or substitute for provider-specific webhook verification.

## Install

Requires Python 3.11 or newer.

```console
python -m pip install .
```

## CLI and API

Run the built-in positive and negative control:

```console
webhook-sandbox probe
```

Process JSON from a file:

```console
webhook-sandbox inspect --input examples/basic.json
```

The public Python seam is `webhook_sandbox.inspect_webhook`:

```python
from webhook_sandbox import inspect_webhook
```

Functions return structured JSON-compatible results and reject malformed input without raising validation exceptions.

## Example

A runnable input is provided at `examples/basic.json`. CLI output is deterministic and includes either a SHA-256 evidence field or an explicit validation failure.

## Security and trust model

Input is untrusted. Offline acceptance proves structure only. HMAC assurance requires a trusted key supplied outside the event, a trusted clock, and a caller-owned replay-ID set; secrets and signatures are not echoed. The tool performs no network calls.

## Limitations

Bodies are UTF-8 strings capped at 1 MiB, headers and paths are bounded, and replay state is in-memory and caller-managed.

## Tests

Run the same local gates used by CI:

```console
python -m unittest discover -s tests -v
python scripts/check.py
python -m build --no-isolation
webhook-sandbox probe
webhook-sandbox inspect --input examples/basic.json
```

CI tests Python 3.11 and 3.12, installs the project and rebuilt wheel, imports the installed package, and exercises both the probe and example.

## AI disclosure

AI assistance supported defensive implementation, adversarial test design, and documentation. See [AI_ASSISTANCE.md](AI_ASSISTANCE.md) for scope and review expectations.

## License

Apache-2.0. See [LICENSE](LICENSE).

