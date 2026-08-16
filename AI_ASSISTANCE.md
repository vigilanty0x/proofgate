# AI assistance disclosure

## Scope

AI assistance was used to draft and review the implementation, tests, documentation, and synthetic examples for ProofGate 0.1.0 and 0.2.0. The repository owner selected the public scope, authorized publication, and remains responsible for releases and maintenance.

## Human decisions

- The core invariant is fail-closed: only independently evaluated proof can produce `DONE`.
- Contracts use strict JSON and commands use argument arrays with no shell.
- The first release has no runtime dependencies and no network integration.
- All examples are synthetic and the repository is standalone.
- Version 0.2 keeps receipts as integrity records rather than claiming unsigned identity or authenticity.

## Verification performed

- Unit tests cover success, counter-evidence, detached-descendant timeout, atomic idempotency claims, typed conflicts, journal boundary enforcement, blocked-receipt chaining, path traversal, symlink escape, circuit opening, and CLI exit behavior.
- The package is compiled, built as a wheel, installed into an isolated environment, and exercised through its installed CLI.
- Repository content is scanned for credential-shaped values and prohibited private references before publication.
- Pull-request and post-merge CI must pass before the release is tagged.

## Limits

AI-generated code can contain defects. ProofGate does not sandbox trusted commands, authenticate unsigned receipts, sign event journals, provide distributed consensus, or replace an operator's review of executable contracts. Users must evaluate these boundaries for their threat model.
