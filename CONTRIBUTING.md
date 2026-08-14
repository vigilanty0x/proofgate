# Contributing

Thank you for improving ProofGate.

1. Open an issue describing the invariant or failure mode.
2. Keep the change focused and add a counter-example that fails before the fix.
3. Run `python -m unittest discover -s tests -v` and `python -m compileall -q src tests`.
4. Update the specification when behavior or a stable diagnostic changes.
5. Use only synthetic fixtures; never commit credentials, customer data, or private infrastructure details.

Pull requests should explain the risk, evidence, rollback path, and compatibility impact. Changing a failing condition into success requires a specification change and tests; merely weakening a gate is not accepted.

