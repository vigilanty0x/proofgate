# TrustKit threat model

## Assets

TrustKit protects configuration secrets, environment examples, permission policy, outbound-request policy, and security-header policy. Evidence integrity is itself an asset: a missing or stale measurement must not become a green verdict.

## Trust boundaries

1. Input JSON and imported-tool output are untrusted until normalized.
2. Filesystem and network targets are outside the root core; adapters must supply bounded evidence.
3. CLI output may enter CI logs, so sensitive values must be redacted before serialization.
4. Imported source packages retain their own behavior until a compatibility adapter is separately proven.

## Required security properties

- deny/fail closed when measurement is incomplete or a required finding is `not_measured`;
- preserve `not_applicable` distinctly instead of treating it as measured-compliant;
- no PASS with missing evidence or duplicate finding identifiers;
- deterministic verdict and exit-code semantics;
- no secret values intentionally emitted by the root serializer;
- no network access in the root evaluator;
- no archive/redirect/release authorization derived from this package alone.

## Non-goals

This core is not a secret vault, WAF, network scanner, credential rotator, penetration-testing framework, or production compliance certification system.
