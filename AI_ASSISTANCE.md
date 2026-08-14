# AI assistance disclosure

## Scope

AI assistance was used to draft the initial implementation, tests, documentation, and synthetic examples for ProofGate 0.1.0. The repository owner selected the public scope, reviewed the architecture, authorized publication, and remains responsible for releases and maintenance.

## Human decisions

- The core invariant is fail-closed: only independently evaluated proof can produce `DONE`.
- Contracts use strict JSON and commands use argument arrays with no shell.
- The first release has no runtime dependencies and no network integration.
- All examples are synthetic and the repository is standalone.

## Verification performed

- Unit tests cover success, counter-evidence, timeout, idempotency conflict, journal tampering, path traversal, symlink escape, circuit opening, and CLI exit behavior.
- The package is compiled, built as a wheel, installed into an isolated environment, and exercised through its installed CLI.
- Repository content is scanned for credential-shaped values and prohibited private references before publication.
- Pull-request and post-merge CI must pass before the release is tagged.

## Limits

AI-generated code can contain defects. ProofGate does not sandbox trusted commands, sign event journals, provide distributed consensus, or replace an operator's review of executable contracts. Users must evaluate these boundaries for their threat model.

