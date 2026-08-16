# Permission Matrix

## Purpose

Explicit role/resource/action permission evaluation with deny precedence. The package is standard-library-only and designed for deterministic local use with synthetic or caller-controlled JSON.

## Non-goals

It is not an identity provider, policy language, attribute engine, or authorization storage service.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install .
```

## CLI and API

Pass a JSON object by path or standard input. Success is emitted as machine-readable JSON; validation failures return exit status 2 without a traceback.

```bash
permission-matrix examples/basic.json
python -m permission_matrix.cli examples/basic.json
```

The public API is `permission_matrix.core.run(data)`. Lower-level functions remain available for focused library use; inspect their signatures for supported keyword options.

## Example

The example generates a two-action matrix for one synthetic subject.

```bash
permission-matrix examples/basic.json
```

All example content is synthetic and safe to publish.

## Security and trust model

Subjects, roles, rules, axes, effects, and output cells are strictly bounded. Deny wins over allow and unmatched requests deny by default.

The caller remains responsible for authenticating inputs and enforcing returned decisions at the real I/O or authorization boundary. Invalid and inconclusive inputs fail visibly rather than producing a healthy or verified claim.

## Limitations

Wildcard matching is exact at a single field and no hierarchy or contextual attributes are inferred.

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

