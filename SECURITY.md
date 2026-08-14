# Security policy

## Supported versions

Security fixes are provided for the latest tagged minor release.

## Threat boundary

ProofGate validates contracts but does not make untrusted commands safe. A `run` contract is executable code expressed as an argument array and must be reviewed at the same trust level as a CI workflow or script. Run it with least privilege, in a disposable workspace when possible, and never on an untrusted pull request with production credentials.

The implementation deliberately:

- never invokes a shell for command rules;
- rejects absolute, drive, and parent-traversal paths;
- resolves symlinks and enforces the evaluation root;
- bounds contract, journal, event, evidence, output, and timeout sizes;
- fails closed on malformed evidence and journal tampering;
- avoids network access and runtime dependencies.

The append-only guarantee is enforced by the API and detected by replay; it is not protection against an attacker who can replace the entire journal and its trust anchor. Preserve the last trusted hash externally when stronger audit assurance is required.

## Reporting

Please report vulnerabilities privately through GitHub's security advisory interface for this repository. Include the affected version, a minimal synthetic reproduction, impact, and any proposed mitigation. Do not include real credentials or private data.

