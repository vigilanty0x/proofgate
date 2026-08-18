# ProofGate consolidation migration

This document records the migration boundary prepared by the portfolio-consolidation rehearsal. It is not an archive authorization and it does not claim compatibility that has not been tested.

## Canonical target

The canonical product target is `vigilanty0x/proofgate`.

The rehearsal imports these source repositories with preserved history and verified source-tree identity:

| Source repository | Imported path | Current migration state |
|---|---|---|
| `status-truth` | `packages/status-truth` | source imported; archive blocked |
| `structured-output-guard` | `packages/structured-output-guard` | source imported; archive blocked |
| `evidence-ledger` | `packages/evidence-ledger` | source imported; archive blocked |
| `run-replay` | `packages/run-replay` | source imported; archive blocked |
| `audit-trail-lite` | `packages/audit-trail-lite` | source imported; archive blocked |

The exact source SHAs and tree SHAs are recorded in `.portfolio-rehearsal.json`.

## Package and CLI boundary

The root Python distribution remains `proofgate` and the root CLI remains `proofgate`.

The imported repositories under `packages/` are preserved source modules. Their presence in the repository does **not** mean that their Python distributions, import names or CLIs are re-exported by the root `proofgate` wheel. Until explicit compatibility tests prove otherwise, consumers of an old package or CLI must treat compatibility as **unverified**.

This prevents a repository-level consolidation from being misrepresented as a package-level migration.

## Required compatibility evidence

Before any source repository may be deprecated or archived, the migration needs evidence for the interfaces that actually have consumers:

- inventory of downstream repositories/workflows/scripts that reference each old repository, package, CLI or schema;
- install smoke for each compatibility path that is promised;
- old-import and old-CLI tests when aliases are intentionally supported;
- schema round-trip or migration tests for public machine-readable contracts;
- documentation redirects or deprecation notes where a public entry point changes;
- explicit support/deprecation window;
- rollback path to the last verified source/release state.

No compatibility alias is invented merely to make the migration appear complete.

## Archive gate

All source repositories remain active until the shared archive gates are satisfied:

1. target release evidence is verified;
2. compatibility claims are tested;
3. consumer inventory is complete;
4. redirects/deprecation notes are prepared where applicable;
5. rollback is documented and rehearsable;
6. human approval is recorded.

A missing consumer inventory or compatibility proof is a `BLOCKED` state, not success.

## Current status

**PREPARED / BLOCKED FOR ARCHIVE.**

The repository consolidation is a reviewable candidate. It does not authorize merge, release, tag creation, package publication, redirect creation, source-repository closure or archival.
