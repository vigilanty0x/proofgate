# TrustKit migration and rollback contract

## Current state

The five source repositories are imported under `packages/` with their histories preserved. The root `trustkit` package adds a common normalized finding/verdict contract; it does not retire source CLIs or import paths.

Source modules:

- `env-example-guard` / `env_example_guard`
- `permission-matrix` / `permission_matrix`
- `secrets-hygiene` / `secrets_hygiene`
- `security-headers-lab` / `security_headers_lab`
- `ssrf-guard-demo` / `ssrf_guard_demo`

## Compatibility adapters

`trustkit.adapters` normalizes the audited source output contracts without importing the source packages at runtime. The source tools can therefore remain independent packages during the migration window.

The adapters are deliberately fail-closed:

- env example: `verified` -> PASS; measured parity/leak problems -> FAIL; `inconclusive` -> BLOCKED;
- secret hygiene: `clean` -> PASS; measured secret findings -> FAIL; truncated/oversized measurement -> BLOCKED;
- security headers: `hardened` -> PASS; policy issues -> FAIL;
- permission matrix: the caller must provide an exact expected decision for every measured cell. A mismatch -> FAIL; absent/incomplete expectations -> BLOCKED;
- SSRF: the caller must state whether the synthetic fixture is expected to be `allowed` or `blocked`. A mismatch -> FAIL; missing expectation -> BLOCKED.

The adapters validate source output shapes before normalization and preserve only bounded, redacted evidence. No adapter is allowed to convert incomplete evidence into PASS.

`migration/adapter-receipts.json` binds each adapter to the audited source head/tree SHA. `tests/test_source_adapters.py` executes the real imported source functions from `packages/` and then checks the normalized TrustKit verdicts, including negative counter-proofs and fabricated-green rejection.

## Source retirement gate

Before any source redirect, alias removal or archive, each source still needs all of the following:

1. the SHA-bound adapter receipt to pass on the exact final TrustKit head;
2. source and target CI evidence;
3. a complete-enough consumer inventory covering manifests, workflows, documentation, registry users and explicitly known pilots;
4. migration receipts for known consumers;
5. a rollback rehearsal bound to exact baseline/candidate SHAs;
6. release artifacts/provenance and post-publication verification;
7. explicit human approval.

## Rollback

Rollback remains low-risk while source identities and consumers are untouched: remove/disable the TrustKit adapter/core candidate and continue using the five source packages directly. Once consumers migrate, rollback must be rehearsed against exact baseline/candidate SHAs and must restore the prior source CLI/import path before any source becomes archive-approved.

The adapters are additive; they do not mutate source repositories, activate redirects, or remove legacy CLIs/imports.

## Status

A candidate may be described as `PREPARED` only after exact-head package/install/test evidence exists. `PREPARED`, `MERGED`, `TAGGED`, `RELEASED` and post-publication `VERIFIED` remain distinct states.

No source is redirect- or archive-approved solely because its adapter passes. Consumer, rollback, release and human gates remain independent.
