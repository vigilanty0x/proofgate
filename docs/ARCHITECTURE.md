# ProofGate architecture

ProofGate separates untrusted declarations, bounded observation, policy decisions, and durable evidence so that no component can silently turn uncertainty into success.

## Components

1. **Contract parser** rejects duplicate JSON keys, unknown fields, unsafe paths, excessive bounds, unknown dependencies, and graph cycles before evaluation.
2. **Evidence evaluators** return one typed result: `proof`, `inference`, or `blockage`. File access uses component-by-component no-follow opens anchored to the configured root, so path replacement cannot redirect a read. Command execution uses an argument array, no shell, a timeout, and capped output.
3. **Gate engine** evaluates dependencies first, records blocked descendants without invoking them, applies the declared policy, and produces stable states and reason codes.
4. **Event journal** atomically claims an attempt and persistently reserves its terminal-event capacity before execution, then appends a redacted verdict linked by SHA-256. Canonical, type-aware JSON equality enforces idempotency; replay detects line, sequence, identity, link, and payload mutation.
5. **Receipt layer** redacts result details to digests, rejects structurally or semantically contradictory verdict summaries, binds direct artifacts by size and SHA-256 through no-follow handles, optionally binds the journal head, and writes atomically.
6. **Suite engine** validates a DAG of contract files, evaluates parents before children, and never upgrades partial completion into suite success.
7. **Diff engine** compares verdicts or receipt summaries and identifies removed, regressed, improved, added, and changed evidence.

## Trust boundaries

- A contract controls what is observed and, in `run` mode, which trusted command is executed. It is code and requires review.
- The root confines file evidence but is not an OS sandbox.
- A journal or receipt hash detects mutation relative to a trusted head; it is not a digital signature.
- A suite coordinates contracts but does not create privilege or distribute secrets.
- No module performs network requests, loads plugins from contracts, or reads credential values.

## Failure sequence

1. Parse the complete contract or suite.
2. Reject invalid structure before any evaluator runs.
3. Atomically claim a journaled operation before any command can run.
4. Resolve dependencies and refuse blocked descendants.
5. Evaluate each reachable rule under its bounds.
6. Apply the explicit policy without hiding failures.
7. Append a bounded verdict summary only when the journal remains replayable.
8. Create a receipt only after artifact paths are re-resolved and re-hashed.

## Compatibility

Contract version remains `1.0`. Existing 0.1 contracts use the implicit `all` policy and require no migration. New rule types, dependencies, suites, and receipts are additive. Stable CLI exit codes remain 0 for verified success, 2 for a valid but blocked gate, and 3 for invalid input or unsafe operation.
