# API Contract Mock Server

## Purpose

Generate bounded deterministic response fixtures for strict `METHOD /path` route declarations and three scenarios: success, degraded, and invalid.

## Non-goals

Despite the historical project name, this package does not listen on a socket, implement HTTP, parse OpenAPI, or test a live service.

## Install

Requires Python 3.11 or newer: `python -m pip install .`

## API

`evaluate(record)` validates `contract`, unique `routes`, exact `modes`, and a 2xx `default_status`, then returns `responses.kind = deterministic-response-fixtures` and `network_server = false`.

## CLI

Run `api-contract-mock-server examples/valid.json`. It prints JSON and exits 0 only for a valid fixture declaration.

## Example

`examples/valid.json` declares one synthetic health route. No network server is started.

## Security

Methods, route grammar, counts, text, status, generated output, and aggregate input are allowlisted or bounded. Route control characters and duplicates fail closed.

## Limits

Up to 100 routes and 64 KiB input/output. Response bodies are fixed fixtures and are not caller-configurable.

## Tests

Run `python -m unittest discover -s tests -v` and `python scripts/check.py`.

## AI assistance

See `AI_ASSISTANCE.md`; release claims require human review.

## License

Apache-2.0; see `LICENSE`.
