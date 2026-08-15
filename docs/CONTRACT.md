# Machine-readable contract

Schema version `1.0` produces a JSON object with `subject`, `operation_id`, `state`,
`success`, `recorded_at`, `policy`, `checks`, `diagnostics`, and `metadata`.

- `success` is derived and true only when `state == "healthy"`.
- `pass` and `fail` require provenance; timeout/open/unknown explicitly document the
  lack of a conclusive observation.
- check names and policy-required names are unique and capped at 100.
- timestamps are timezone-aware ISO-8601 and normalized to UTC.
- evidence is represented by a canonical JSON SHA-256 digest.
- `logical_sha256` excludes only `recorded_at`, allowing a later exact replay to
  return the original journal entry without changing its logical meaning.

Minor `1.x` versions may add optional fields. A change to state semantics or a
required field needs a new major schema version.

