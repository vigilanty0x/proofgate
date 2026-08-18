# ProofGate release contract

ProofGate uses an evidence-first release state machine. A green build is necessary, but it is not a release.

## States

| State | Meaning |
|---|---|
| `PREPARED` | Candidate source and artifacts exist; required evidence is not yet complete. |
| `MERGED` | The candidate commit is on the approved release branch. |
| `TAGGED` | A human-approved immutable version tag points to the intended commit. |
| `RELEASED` | Distribution or GitHub Release publication was performed by an authorized human-controlled process. |
| `VERIFIED` | Published artifacts, tag, source SHA, checksums, SBOM and attestations were independently re-checked. |
| `BLOCKED` | One or more required gates are missing, stale, conflicting or failed. |
| `ROLLED_BACK` | The candidate or release was withdrawn from active recommendation using the documented rollback decision. |

`PREPARED != RELEASED` and `RELEASED != VERIFIED`.

## Candidate build

The normal CI workflow is the first release gate. It must pass on the declared matrix before a candidate can advance:

- Ubuntu, Windows and macOS;
- Python 3.11, 3.12 and 3.13;
- wheel and sdist build;
- wheel installation;
- unit tests against the installed artifact;
- CLI smoke outside the repository checkout;
- a negative counter-proof where passive `check` must fail closed with exit code 2;
- a positive synthetic gate run and journal replay;
- generation of checksums, CycloneDX SBOM and `RELEASE_EVIDENCE.json`.

The generated `RELEASE_EVIDENCE.json` remains `PREPARED` and explicitly records that it is not signed, attested, published or released.

## Manual attestation gate

After the candidate is reviewed on the default branch, a human may invoke **Release evidence** manually. The workflow:

1. rebuilds wheel and sdist from the selected source SHA;
2. reruns unit tests, the negative counter-proof and the outside-checkout smoke;
3. regenerates SHA-256 checksums and the CycloneDX SBOM;
4. creates GitHub artifact provenance attestations for wheel and sdist;
5. creates an SBOM attestation for the wheel;
6. uploads the evidence bundle for review.

The workflow has no package-publishing, release-creation, tag-creation, archive, deletion or merge step.

## Human release gate

No release may be declared until a human reviewer has verified all of the following against the same source SHA:

- required CI jobs are green;
- wheel and sdist exist and install cleanly;
- SHA-256 checksum file matches the artifacts;
- SBOM exists and is bound to the candidate;
- provenance/SBOM attestations are retrievable and verify;
- README version/product identity matches package metadata;
- migration notes are present when compatibility changes;
- consumer inventory is reviewed before any source repository is deprecated or archived;
- rollback procedure below is applicable to the intended publication channel;
- the final release action is explicitly approved by a human.

If any item is absent or stale, the candidate is `BLOCKED`.

## Rollback contract

Rollback is decided before publication, not after an incident.

### Before publication

The safe rollback is to stop promotion and return to the last `VERIFIED` release. Do not create a tag or publish artifacts. Record the rejected candidate SHA and the failed gate.

### After publication

A published release must not be silently rewritten. If verification fails after publication:

1. mark the release `DEGRADED` or `BLOCKED` in release notes/status records;
2. stop recommending the affected version;
3. preserve the original tag, artifacts, logs and attestations as evidence;
4. identify the last `VERIFIED` version and document the user-facing downgrade path;
5. prepare a corrective version from an explicit source SHA;
6. run the complete candidate and attestation gates again;
7. require a new human approval before publishing the corrective version;
8. mark the incident `ROLLED_BACK` only when the selected recovery state is independently verified.

Deletion, force-moving a tag, rewriting provenance, or hiding failed evidence is not a rollback.

## Required handoff

Every release-related handoff records:

`Target; repo; base SHA; head SHA; files; commands; results; artifacts; decisions; limits; next action; status VERIFIED/BLOCKED.`

A release handoff without the exact source SHA and artifact digests is incomplete.
