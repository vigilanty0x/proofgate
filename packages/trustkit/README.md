# TrustKit

TrustKit is the canonical defensive policy layer for the public consolidation of five focused security tools. This branch is a **rehearsal**, not a stable release, and does not authorize source archival.

## Canonical core

The root `trustkit` package provides the shared contract that the imported tools can target without erasing their source histories:

- categories: `secret`, `env_config`, `permission`, `ssrf`, `security_header`;
- severities: `info`, `low`, `medium`, `high`, `critical`;
- measurement states: `measured`, `not_measured`, `not_applicable`;
- verdicts: `PASS`, `FAIL`, `BLOCKED`;
- fail-closed handling for missing evidence, duplicate finding IDs, incomplete measurement, or invalid input;
- recursive sensitive-key redaction before JSON output;
- deterministic CLI exit codes: `0=PASS`, `1=FAIL`, `2=BLOCKED/invalid`.

Install from a built wheel and run a synthetic fixture:

```bash
trustkit examples/pass.json
```

A negative fixture is expected to fail with exit code 1:

```bash
trustkit examples/fail.json
```

## Imported source modules

The consolidation rehearsal preserves the imported source trees and histories under `packages/`:

- `secrets-hygiene`
- `env-example-guard`
- `security-headers-lab`
- `ssrf-guard-demo`
- `permission-matrix`

The root core does **not** silently replace these CLIs. Adapter/alias activation remains a later compatibility gate.

## Safety boundary

TrustKit is defensive and synthetic-fixture-first. It does not contain production credentials, client data, private domains, or private product content. Missing measurement is `BLOCKED`, never `PASS`.

See `docs/THREAT_MODEL.md` and `docs/MIGRATION.md` for the bounded threat model and migration/rollback gates.
