# Architecture

`contract.py` owns the stable schema and input bounds. `engine.py` is a pure,
deterministic normalizer. `guards.py` converts timeouts, exceptions, circuit state,
and boolean results into checks. `journal.py` appends hash-chained records and
rejects conflicting idempotency keys. `service.py` is the API seam. `cli.py` exposes
the same seam to local tools, while `probes.py` verifies it without network access.

The producer of a check does not decide the dashboard status. It supplies a typed
outcome plus provenance; the normalizer applies the shared policy. This avoids the
common failure mode in which exceptions or missing evidence become truthy success.

