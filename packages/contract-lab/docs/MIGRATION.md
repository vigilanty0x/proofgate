# Contract Lab migration and rollback

The three source repositories remain imported under `packages/` with histories preserved. The root `contract_lab` package adds a common portable contract but activates no legacy alias.

Before a source interface can move behind the root product, its exact source SHA needs a receipt proving fixture roundtrip or declared lossiness, schema/version mapping, negative/tamper counter-proofs, legacy CLI/import compatibility or deprecation, and a consumer inventory.

For `webhook-sandbox`, signature/replay semantics must remain byte-exact. For `schema-contract-tester`, unsupported schema features must fail closed. For `api-contract-mock-server`, conforming/degraded/invalid scenario meaning must be preserved.

Until consumers change, rollback is removal of the root consolidation commit and continued use of source packages. After migration, rollback must be rehearsed against exact baseline/candidate SHAs and restore prior CLI/import paths before source retirement.

PREPARED, MERGED, TAGGED, RELEASED and VERIFIED remain separate states.
