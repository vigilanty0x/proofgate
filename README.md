# Env Example Guard

## Purpose

Environment/example key parity with secret-value leakage prevention. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It does not read process environments, decrypt values, or decide which configuration keys an application actually uses.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
env-example-guard examples/basic.json
python -m env_example_guard.cli examples/basic.json
```

The public API is `env_example_guard.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example verifies two configuration keys whose published values are empty.

```bash
env-example-guard examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

A built-in sensitive-name and provider-value policy cannot be disabled by caller-supplied secret_keys. Empty policy surfaces are inconclusive, while key drift or leaked values block.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

The parser supports simple uppercase KEY=value example files, not shell expansion, quoting semantics, or multiline values.

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

