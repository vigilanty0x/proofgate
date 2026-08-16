# Security policy

## Supported versions

Security fixes are provided for the latest tagged minor release.

## Threat boundary

ProofGate validates contracts but does not make untrusted commands safe. A `run` contract is executable code expressed as an argument array and must be reviewed at the same trust level as a CI workflow or script. Run it with least privilege, in a disposable workspace when possible, and never on an untrusted pull request with production credentials.

The implementation deliberately:

- never invokes a shell for command rules;
- drains command output continuously while retaining only the final 64 KiB of each stream;
- journals only digests of evidence details, never captured stdout or stderr;
- rejects absolute, drive, and parent-traversal paths;
- opens root-relative paths component by component with no-follow semantics and refuses symlinks, including concurrent path replacement;
- validates filename-safe suite/unit identifiers before unit IDs may become journal filenames;
- bounds contract, journal, event, evidence, output, and timeout sizes;
- fails closed on malformed evidence and journal tampering;
- avoids network access and runtime dependencies.
- validates dependency graphs before evaluation and never evaluates blocked children;
- writes receipts atomically and verifies safe artifact paths before hashing.
- serializes journal readers and appenders with an OS-level lock on the journal file;
- claims an operation identity and persistently reserves terminal journal capacity before executing journaled commands, preventing duplicate execution and post-side-effect journal exhaustion by concurrent callers.
- validates receipt and replayed-verdict state, status, reason, evidence classification, pass flags, and metrics as one coherent completion record.

On POSIX, a timeout kills the isolated command process group. On Linux, ProofGate also snapshots observable descendants through `/proc` before killing the parent, so a child that created a new session is terminated in the tested case. Reader cleanup has its own wall-clock bound and cannot make the evaluator wait indefinitely for inherited pipes; an open inherited pipe after a successful parent exit blocks proof with `COMMAND_CLEANUP_INCOMPLETE`. This remains process hygiene, not a sandbox: a deliberately double-forked/re-parented process can escape ancestry tracking. On Windows, ProofGate requests `taskkill /T`; use an outer sandbox, container, or job-object boundary whenever descendant containment is a hard requirement.

The append-only guarantee is enforced by the API and detected by replay; it is not protection against an attacker who can replace the entire journal and its trust anchor. Preserve the last trusted hash externally when stronger audit assurance is required.

Receipts have the same limitation: their SHA-256 self-hash proves internal consistency, not authorship. An attacker who can replace both a receipt and every referenced artifact can create a new consistent set. Store trusted receipt or journal hashes in an independently protected system, or wrap them in your organization’s signing process. ProofGate 0.2 deliberately does not invent key management or accept secrets in contracts.

## Reporting

Please report vulnerabilities privately through GitHub's security advisory interface for this repository. Include the affected version, a minimal synthetic reproduction, impact, and any proposed mitigation. Do not include real credentials or private data.
