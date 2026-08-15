# Failure model

Required explicit failure is `failed`. A required timeout or open circuit is
`blocked`. Missing/inconclusive required evidence is `unknown`. Optional failure,
timeout, or unknown is `degraded` only after all required checks pass. None of those
states is successful.

The circuit breaker opens after a configurable number of consecutive failures and
closes after the reset window. The timeout guard returns promptly; Python threads
cannot forcibly terminate arbitrary user work, so callers must still design their
operations to be cancellation-safe and side-effect bounded.

The JSONL journal detects malformed lines, partial writes, entry mutation, broken
hash chains, and duplicate operation IDs. It provides integrity evidence, not
cryptographic authenticity; sign or externally anchor the head hash when authenticity
against a privileged local attacker is required.

