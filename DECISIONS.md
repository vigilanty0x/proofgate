# Decision log

## D-001 — JSON contracts

JSON was selected for version 1.0 because it is machine-readable, deterministic to parse with the standard library, easy to emit from other languages, and supports duplicate-key rejection. A future front-end may compile YAML or TOML into this canonical representation.

## D-002 — No shell execution

Command evidence is an argument array passed with `shell=False`. This removes quoting ambiguity and prevents shell metacharacters from changing meaning across platforms. Contracts remain executable and must still be trusted.

## D-003 — Fail closed

Skipped commands are `inference`, missing or contradictory evidence is `blockage`, and only verified `proof` reaches `DONE`. This makes the unsafe outcome visible and preserves the central invariant.

## D-004 — Local hash chain

The journal uses canonical JSON and SHA-256 links to detect edits and reordering without external services. This is tamper-evident, not a signature. Higher-assurance deployments should persist the trusted head hash elsewhere.

