# Schema Contract Tester

## Purpose

Bounded record/schema compatibility checks with explicit field errors. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It is not a full JSON Schema implementation and does not coerce values or infer a schema.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
schema-contract-tester examples/basic.json
python -m schema_contract_tester.cli examples/basic.json
```

The public API is `schema_contract_tester.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example checks a synthetic record containing a required string and integer.

```bash
schema-contract-tester examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Schemas, records, field counts, error output, JSON types, and numeric finiteness are validated. Booleans never satisfy integer or number contracts, and empty inputs require allow_empty.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

Supported types are string, integer, number, boolean, object, and array; nested schemas and value constraints are outside scope.

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

