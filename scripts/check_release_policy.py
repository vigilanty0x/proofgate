#!/usr/bin/env python3
"""Fail-closed release and consolidation state checks for ProofGate."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTION_REF = re.compile(r"^\s*- uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$", re.MULTILINE)
EXPECTED_SOURCES = {
    "audit-trail-lite",
    "evidence-ledger",
    "run-replay",
    "status-truth",
    "structured-output-guard",
}
EXPECTED_EVIDENCE = [
    "wheel",
    "sdist",
    "sha256sums",
    "cyclonedx-sbom",
    "wheel-provenance",
    "sdist-provenance",
    "wheel-sbom-attestation",
]


class ReleasePolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Receipt:
    version: str
    consolidation_state: str
    source_count: int
    publish_enabled: bool
    release_authorized: bool
    archive_authorized: bool


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleasePolicyError(f"cannot parse {path.name}") from exc
    if type(value) is not dict:
        raise ReleasePolicyError(f"{path.name} root must be an object")
    return value


def _require(value: object, expected: object, field: str) -> None:
    if value != expected:
        raise ReleasePolicyError(f"{field} must equal {expected!r}; got {value!r}")


def _workflow_contract(text: str) -> None:
    if "on:\n  workflow_dispatch:" not in text:
        raise ReleasePolicyError("release-evidence workflow must be manual-only")
    if "\n  push:" in text or "\n  pull_request:" in text:
        raise ReleasePolicyError("release-evidence workflow must not run automatically")
    required = (
        "runs-on: ubuntu-24.04",
        "permissions:\n  contents: read",
        "CURRENT_REF: ${{ github.ref_name }}",
        "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
        'if [[ "$CURRENT_REF" != "$DEFAULT_BRANCH" ]]',
        "python scripts/check_release_policy.py",
        "python scripts/release_evidence.py --dist dist",
        "subject-path: dist/*.whl",
        "subject-path: dist/*.tar.gz",
        "sbom-path: dist/proofgate.cdx.json",
        "name: proofgate-release-evidence-${{ github.sha }}",
    )
    for fragment in required:
        if fragment not in text:
            raise ReleasePolicyError(f"release-evidence workflow missing {fragment!r}")
    forbidden = ("contents: write", "gh release create", "pull_request_target:")
    for fragment in forbidden:
        if fragment in text:
            raise ReleasePolicyError(f"release-evidence workflow contains forbidden authority {fragment!r}")
    uses_lines = [line for line in text.splitlines() if line.lstrip().startswith("- uses:")]
    if not uses_lines:
        raise ReleasePolicyError("release-evidence workflow has no external actions")
    for line in uses_lines:
        if ACTION_REF.fullmatch(line) is None:
            raise ReleasePolicyError(f"action is not pinned to a full commit SHA: {line.strip()}")


def validate(root: Path = ROOT) -> Receipt:
    root = Path(root)
    policy = _json(root / "release-policy.v1.json")
    rehearsal = _json(root / ".portfolio-rehearsal.json")
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        workflow = (root / ".github" / "workflows" / "release-evidence.yml").read_text(encoding="utf-8")
        ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise ReleasePolicyError("cannot read release policy inputs") from exc

    _require(policy.get("schemaVersion"), 1, "release policy schemaVersion")
    _require(policy.get("product"), "proofgate", "release policy product")
    version = policy.get("version")
    if type(version) is not str or re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
        raise ReleasePolicyError("release policy version must be X.Y.Z")
    _require(project.get("name"), "proofgate", "pyproject project.name")
    _require(project.get("version"), version, "pyproject project.version")
    _require(policy.get("state"), "PREPARED", "release policy state")
    _require(policy.get("publishEnabled"), False, "release policy publishEnabled")
    _require(policy.get("releaseAuthorized"), False, "release policy releaseAuthorized")
    _require(policy.get("archiveAuthorized"), False, "release policy archiveAuthorized")
    _require(policy.get("sourceBranch"), "main", "release policy sourceBranch")
    _require(
        policy.get("humanReleaseApprovalRequired"),
        True,
        "release policy humanReleaseApprovalRequired",
    )
    _require(policy.get("requiredEvidence"), EXPECTED_EVIDENCE, "release policy requiredEvidence")

    _require(rehearsal.get("schemaVersion"), 1, "portfolio schemaVersion")
    _require(rehearsal.get("target"), "proofgate", "portfolio target")
    _require(rehearsal.get("state"), "MERGED", "portfolio state")
    _require(rehearsal.get("archiveGate"), "BLOCKED", "portfolio archiveGate")
    merge_sha = rehearsal.get("mergeCommitSha")
    if type(merge_sha) is not str or GIT_SHA.fullmatch(merge_sha) is None:
        raise ReleasePolicyError("portfolio mergeCommitSha must be a full Git SHA")
    sources = rehearsal.get("sources")
    if type(sources) is not list:
        raise ReleasePolicyError("portfolio sources must be an array")
    names: set[str] = set()
    for index, source in enumerate(sources):
        if type(source) is not dict:
            raise ReleasePolicyError(f"portfolio source {index} must be an object")
        name = source.get("repository")
        if type(name) is not str or not name:
            raise ReleasePolicyError(f"portfolio source {index} has invalid repository")
        if name in names:
            raise ReleasePolicyError(f"duplicate portfolio source: {name}")
        names.add(name)
        for field in ("headSha", "treeSha"):
            value = source.get(field)
            if type(value) is not str or GIT_SHA.fullmatch(value) is None:
                raise ReleasePolicyError(f"{name}.{field} must be a full Git SHA")
        _require(source.get("ancestor"), True, f"{name}.ancestor")
        _require(source.get("treeMatch"), True, f"{name}.treeMatch")
    _require(names, EXPECTED_SOURCES, "portfolio source set")

    _workflow_contract(workflow)
    if 'python-version: ["3.11", "3.12", "3.13", "3.14"]' not in ci:
        raise ReleasePolicyError("CI must explicitly test Python 3.11 through 3.14")
    if "python scripts/check_release_policy.py" not in ci:
        raise ReleasePolicyError("CI must execute the release-policy checker")
    if f"## {version} - " not in changelog:
        raise ReleasePolicyError(f"CHANGELOG.md has no section for {version}")
    if "PREPARED" not in changelog:
        raise ReleasePolicyError("CHANGELOG.md must keep PREPARED release semantics explicit")
    if "MERGED" not in changelog:
        raise ReleasePolicyError("CHANGELOG.md must record merged consolidation semantics")

    return Receipt(
        version=version,
        consolidation_state=str(rehearsal["state"]),
        source_count=len(sources),
        publish_enabled=False,
        release_authorized=False,
        archive_authorized=False,
    )


def main() -> int:
    try:
        receipt = validate()
    except ReleasePolicyError as exc:
        raise SystemExit(f"release policy gate: {exc}") from exc
    print(
        "release policy verified: "
        f"version={receipt.version} consolidation={receipt.consolidation_state} "
        f"sources={receipt.source_count} publish_enabled=false release_authorized=false archive_authorized=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
