# Changelog

All notable changes follow Semantic Versioning.

## 0.2.0 - 2026-08-16

- Add dependency-ordered evidence and strict `all`, `any`, and threshold policies.
- Add bounded text, directory, and nested receipt evidence types.
- Add portable tamper-evident receipts with atomic writes and artifact verification.
- Add multi-contract suites with DAG validation and blocked-child semantics.
- Add verdict/receipt regression diffs and stable reason-code explanations.
- Drain command streams into bounded diagnostic tails, stop POSIX process groups on timeout, and serialize journal append/replay for concurrency safety.
- Reject filename-unsafe suite IDs and ambiguous duplicate keys across contracts, suites, receipts, and journals.
- Expand adversarial tests, architecture documentation, public API, and pinned least-privilege CI.
- Reject non-finite JSON and preserve JSON types during journal idempotency comparison.
- Claim journaled attempts before evidence execution, redact raw output from verdict events, and reject appends that cross the total journal limit.
- Require nested receipts to attest verified completion and make receipt path-shape validation independent of the caller's working directory.
- Compare JSON recursively with strict scalar/container types, reject impossible receipt and replayed-verdict completion records, retain terminal journal reservations across competing appends, and use descriptor-anchored no-follow reads for every root-scoped file path.
- Bound timeout cleanup, terminate session-detached descendants observed on Linux, reject proof while inherited pipes remain open, and normalize invalid CLI invocations to exit code 3.
- Pin the build backend and make CI install and smoke-test the built wheel outside the checkout.
- Record the five-repository ProofGate consolidation as **MERGED** at `49521b4e06e295665e9e56045389cb56f533718d`, while preserving every imported source history and tree-match proof.
- Extend the supported CI matrix through Python 3.14 and add a machine-readable release policy that keeps `0.2.0` **PREPARED**, `publishEnabled=false`, `releaseAuthorized=false`, and `archiveAuthorized=false`.
- Require manual release evidence to run only from reviewed default-branch lineage and retain wheel, sdist, SHA-256, CycloneDX SBOM, provenance, and SBOM-attestation evidence without publishing a release.

Consolidation state is **MERGED**, but release state remains **PREPARED**. `MERGED` must not be reported as `RELEASED`, and no historical source repository may be archived until release, post-release verification, consumer, redirect, rollback, and explicit human archive gates are satisfied.

## 0.1.0 - 2026-08-15

- Add strict contract 1.0 parsing and bounded file, JSON, and command evidence.
- Add explicit task states and proof, inference, and blockage diagnostics.
- Add a hash-chained append-only journal with idempotency conflict detection.
- Add command timeouts, output bounds, safe root resolution, and circuit breaking.
- Add CLI, Python API, synthetic example, adversarial tests, and public documentation.
