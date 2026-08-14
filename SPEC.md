# ProofGate contract specification 1.0

## Invariant

`state == DONE` if and only if every required evidence rule is evaluated and returns `passed == true` with classification `proof`.

No exception, missing file, skipped command, timeout, inferred claim, malformed response, or journal failure can satisfy this invariant.

## State model

| State | Meaning | Terminal |
|---|---|---:|
| `PENDING` | Contract accepted but not evaluated | No |
| `RUNNING` | Active bounded evaluation | No |
| `WAITING` | Evidence is missing or a command was intentionally not run | No |
| `FAILED` | Executed evidence contradicted the contract | Yes for that attempt |
| `REJECTED` | Evaluation could not start safely or the circuit is open | Yes for that attempt |
| `DONE` | All required evidence was independently verified | Yes |

The public API returns the final attempt state. The journal records final verdicts, preserving failed attempts for replay and circuit-breaker accounting.

## Evidence classifications

- `proof`: directly evaluated evidence that satisfies its rule.
- `inference`: a known but unexecuted claim, such as command evidence in `check` mode.
- `blockage`: missing, contradictory, unsafe, timed-out, or unreadable evidence.

Only `proof` can contribute to `DONE`.

## Rule types

### `command`

`command` is a non-empty JSON array of program and arguments. Shell strings are invalid. `expect_exit` defaults to 0. `timeout_seconds` is capped by the contract-wide timeout. Standard output and error are retained only up to a bounded tail.

### `file`

`path` is relative to the evaluation root. `min_bytes` defaults to 1. An optional lowercase or uppercase SHA-256 digest binds the exact content. Resolved symlinks must remain inside the root.

### `json`

`path` follows the same root rule. `pointer` is an RFC 6901 JSON Pointer; the empty string addresses the entire document. `equals` uses both value and JSON-derived Python type so `true` does not equal `1`.

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

## Idempotency

The same idempotency key and identical event meaning return the stored event without appending. Reusing a key with different data is an error. Callers should use a stable attempt identifier, then choose a new identifier when inputs or expected evidence change.

## Circuit breaker

Before a command-capable run, ProofGate replays the journal. If recorded `FAILED` or `REJECTED` verdicts meet the contract threshold, it emits `CIRCUIT_OPEN`, reaches `REJECTED`, and executes no commands. Operators recover by investigating the evidence and intentionally starting a new journal or raising the threshold in a reviewed contract change.

## Bounds

- Contract: 1 MiB.
- Evidence rules: 128.
- Journal: 64 MiB.
- Event: 256 KiB.
- Hashed or parsed evidence file: 64 MiB.
- Command capture: 64 KiB per stream.
- Global timeout: 1 to 3600 seconds.

These conservative bounds make resource use predictable. Larger workflows should store external artifacts and gate compact reports or digests.

