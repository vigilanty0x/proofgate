# Contributing

Status Truth accepts focused, public contributions. Open an issue describing the
observable contract change before a large patch. Never include credentials,
customer data, private endpoints, internal repository names, or production logs.

Requirements for a pull request:

1. preserve fail-closed behavior and backwards-compatible schema semantics;
2. add tests for success, failure, and counter-proof paths;
3. run `PYTHONPATH=src python -m unittest discover -s tests -v`;
4. run `PYTHONPATH=src python scripts/check.py`;
5. update docs and `CHANGELOG.md` for a public behavior change.

By contributing, you agree that your contribution is licensed under Apache-2.0.

