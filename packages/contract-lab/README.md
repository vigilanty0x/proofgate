# Contract Lab

Contract Lab is the canonical offline contract core for three imported public tools: schema compatibility testing, webhook replay/signature evidence, and API mock scenarios.

This branch is a **consolidation rehearsal**, not a stable release. It does not authorize source redirects or archival.

## Root contract

The stdlib-only root package provides deterministic JSON canonicalization/digests, conservative object-schema evolution checks, replay receipts bound to contract/request/response, and HMAC-SHA256 webhook proof primitives.

CLI outcomes are deterministic: valid/compatible `0`, breaking/tampered `1`, invalid/unsupported input `2`.

```bash
contract-lab roundtrip examples/roundtrip.json
contract-lab evolve examples/old-schema.json examples/new-compatible-schema.json
contract-lab evolve examples/old-schema.json examples/new-breaking-schema.json  # expected exit 1
```

## Imported sources

Histories remain preserved under `packages/`:

- `schema-contract-tester`
- `webhook-sandbox`
- `api-contract-mock-server`

Their package names/imports/CLIs remain source interfaces. The root core does not silently alias or retire them.

See `docs/CONTRACT_MODEL.md` and `docs/MIGRATION.md`.
