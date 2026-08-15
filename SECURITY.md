# Security policy

## Supported versions

Security fixes target the latest released minor version.

## Reporting

Please report vulnerabilities through GitHub private vulnerability reporting when
available. Do not publish secrets, private data, or exploit details in a public issue.

Status Truth protects status integrity, not authorization or secret storage. Journal
files can contain user-supplied metadata and diagnostic text; protect them with normal
filesystem access controls and never put secrets in those fields. Evidence content is
represented by a digest, not stored by the library.

