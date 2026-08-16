# ProofGate contract specification 1.0

## Invariant

`state == DONE` if and only if the explicit evidence policy is satisfied by rules returning `passed == true` with classification `proof`.

The default policy is `all`, which preserves the original invariant that every rule must pass. `any` and `threshold` are opt-in and the verdict always retains non-passing evidence.

No exception, missing file, skipped command, timeout, inferred claim, malformed response, or journal failure can satisfy this invariant.

## State model

| State | Meaning | Terminal |
|---|---|---:|
| `PENDING` | Contract accepted but not evaluated | No |
| `RUNNING` | Active bounded evaluation | No |
| `WAITING` | Evidence is missing or a command was intentionally not run | No |
| `FAILED` | Observed evidence contradicted the contract (for example a hash/value mismatch or failed command) | Yes for that attempt |
| `REJECTED` | Evaluation could not start safely or the circuit is open | Yes for that attempt |
| `DONE` | All required evidence was independently verified | Yes |

The public API returns the final attempt state. The journal records final verdicts, preserving failed attempts for replay and circuit-breaker accounting.

## Evidence classifications

- `proof`: directly evaluated evidence that satisfies its rule.
- `inference`: a known but unexecuted claim, such as command evidence in `check` mode.
- `blockage`: missing, contradictory, unsafe, timed-out, or unreadable evidence.

Only `proof` can contribute to `DONE`.

## Rule types

Every rule may declare a unique `depends_on` array. Unknown dependencies, self-dependencies, and cycles invalidate the contract. A failed prerequisite produces `DEPENDENCY_BLOCKED`; the dependent evaluator is not invoked.

### `command`

`command` is a non-empty JSON array of program and arguments. Shell strings are invalid. `expect_exit` defaults to 0. `timeout_seconds` is capped by the contract-wide timeout. Standard output and error are retained only up to a bounded tail. A nominally successful parent cannot produce proof while a descendant still holds a capture pipe open; that condition returns `COMMAND_CLEANUP_INCOMPLETE`.

### `file`

`path` is relative to the evaluation root. `min_bytes` defaults to 1. An optional lowercase or uppercase SHA-256 digest binds the exact content. File reads open every path component relative to an already-open parent and refuse symlinks. A concurrent rename or link replacement therefore cannot redirect an accepted read outside the opened root.

### `json`

`path` follows the same root rule. `pointer` is an RFC 6901 JSON Pointer; the empty string addresses the entire document. `equals` recursively compares container and scalar types, so nested `true` never equals `1` and nested `false` never equals `0`.

### `text`

`contains` is one literal or a bounded unique array. Each literal must occur at least `min_occurrences`; comparison can be case-sensitive or Unicode case-folded. Reports include counts and a file digest, never the file contents.

### `directory`

The rule counts files matching a safe relative glob below a descriptor-anchored directory. `min_files` and `max_files` are explicit. Inventories are sorted and report output is capped; every encountered symlink blocks the rule rather than being followed.

### `receipt`

The rule verifies a strict ProofGate receipt self-hash, optional expected task identity, and by default each bound artifact under the current root. The receipt contributes proof only when its internally consistent verdict has `done == true`; a valid receipt for a blocked attempt returns `RECEIPT_NOT_DONE`. This is an integrity chain, not an author signature.

## Evidence policy

- `{"mode":"all"}` requires every rule and is the default.
- `{"mode":"any"}` requires at least one verified rule.
- `{"mode":"threshold","minimum_verified":N}` requires exactly the declared minimum, bounded by the rule count.

Policy satisfaction never removes failed evidence from the verdict. `metrics.required`, `evidence_total`, `verified`, and `blocked` state the decision inputs.

## Multi-contract suites

Suite contract 1.0 lists strict relative contract paths and dependency IDs. The complete DAG is validated before evaluation. Failed parents block children, suite ordering is deterministic, and the suite reaches `DONE` only when every child does.

## Portable receipts

Receipt 1.0 includes the canonical contract digest, a redacted verdict summary, direct artifact manifests, an optional journal head, creation time, and a self-hash. Artifact bytes and captured command output are excluded. Verification checks the closed schema, state/status/reason/evidence semantics, self-hash, no-follow paths, sizes, and content digests. Recomputing a self-hash cannot make an impossible completion record valid.

## Event journal

Each line is canonical JSON with exactly these fields:

- `event_id`: unique UUID.
- `idempotency_key`: unique caller-controlled operation identity.
- `sequence`: one-based contiguous sequence.
- `kind`: event category.
- `timestamp`: UTC creation time.
- `data`: event payload.
- `previous_hash`: prior event hash, or 64 zeroes for the first event.
- `hash`: SHA-256 of the canonical event without `hash`.

Replay fails on malformed JSON, blank lines, unknown fields, duplicate identities, sequence gaps, broken links, or changed content. The file is append-only by API contract; filesystem access control remains the operator's responsibility.

Readers and writers coordinate with an operating-system lock on the journal file. An append replays and verifies the complete journal while holding an exclusive lock, verifies that the encoded event will not cross the total journal bound, then assigns the next sequence and chain head before one flushed append. Library replay treats a missing path as an empty snapshot for coordination; the CLI rejects a missing journal to avoid silently accepting path typos.

Journaled gate runs produce an `attempt_claim` before any evidence executes and a `verdict` afterward. Verdict events retain stable result fields and SHA-256 digests of details, not raw command output. This keeps every valid contract outcome below the event bound.

## Idempotency

Event equality uses canonical JSON bytes, so JSON types remain distinct (`true` is not `1`). The same idempotency key and identical event meaning return the stored event without appending; different data is an error.

For a gate run, the claim binds the canonical contract, resolved-root digest, and execution mode before commands run. It also reserves one maximum-sized event until its matching verdict is appended. Every later append accounts for all outstanding reservations, so an unrelated or concurrent writer cannot consume terminal capacity. If the reservation cannot be created, ProofGate rejects before command execution. Exactly one concurrent caller creates the claim. A later caller returns the recorded redacted verdict when present, or fails closed when the attempt is still running or was interrupted before its verdict. Recovery from an interrupted attempt requires an intentionally new key after inspection.

## Circuit breaker

Before a command-capable run, ProofGate replays the journal. If recorded `FAILED` or `REJECTED` verdicts meet the contract threshold, it emits `CIRCUIT_OPEN`, reaches `REJECTED`, and executes no commands. Operators recover by investigating the evidence and intentionally starting a new journal or raising the threshold in a reviewed contract change.

## Bounds

- Contract: 1 MiB.
- Evidence rules or suite contracts: 128.
- Journal: 64 MiB.
- Event: 256 KiB.
- Hashed or parsed evidence file: 64 MiB.
- Command capture: 64 KiB per stream.
- Receipt: 16 MiB, at most 1024 direct artifacts, each at most 64 MiB.
- Global timeout: 1 to 3600 seconds.

All persisted formats reject duplicate object keys and the non-standard `NaN`, `Infinity`, and `-Infinity` tokens.

These conservative bounds make resource use predictable. Larger workflows should store external artifacts and gate compact reports or digests.
