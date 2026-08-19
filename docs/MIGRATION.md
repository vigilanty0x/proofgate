# TrustKit migration and rollback contract

## Current state

The five source repositories are imported under `packages/` with their histories preserved. The root `trustkit` package adds a common normalized finding/verdict contract; it does not activate legacy aliases or retire source CLIs.

## Compatibility gate

Before any source redirect or archive, each source tool needs a SHA-bound adapter receipt proving:

1. source input/output fixture compatibility;
2. category and severity mapping;
3. evidence preservation without secret leakage;
4. legacy CLI/import behavior or an explicit deprecation contract;
5. a negative counter-proof that forces FAIL or BLOCKED;
6. an enumerated consumer inventory.

## Rollback

Rollback remains trivial while aliases and consumers are untouched: remove the root adapter/core commit and continue using the source packages. Once consumers migrate, rollback must be rehearsed against exact baseline/candidate SHAs and must restore the prior CLI/import path before any source can become archive-approved.

## Status

This rehearsal may become PREPARED after package/install/test evidence exists. It is not MERGED, TAGGED, RELEASED, VERIFIED-after-publication, REDIRECTED, or ARCHIVED without the corresponding human and evidence gates.
