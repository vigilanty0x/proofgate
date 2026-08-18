#!/usr/bin/env python3
"""Generate local, deterministic release evidence for ProofGate artifacts.

This script does not sign, publish, upload, or release anything. It binds the
built wheel and source distribution to SHA-256 digests and emits a small
CycloneDX SBOM plus a machine-readable PREPARED record. GitHub's release
evidence workflow may subsequently attest these files after human invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tomllib
import uuid


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_project(root: Path) -> tuple[str, str]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    return str(project["name"]), str(project["version"])


def collect_artifacts(dist: Path) -> list[Path]:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel, found {len(wheels)}")
    if len(sdists) != 1:
        raise SystemExit(f"expected exactly one sdist, found {len(sdists)}")
    return [*wheels, *sdists]


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_bundle(root: Path, dist: Path) -> dict[str, object]:
    name, version = load_project(root)
    artifacts = collect_artifacts(dist)
    subjects = [
        {
            "name": artifact.name,
            "digest": {"sha256": sha256_file(artifact)},
            "size": artifact.stat().st_size,
        }
        for artifact in artifacts
    ]

    checksum_lines = [
        f"{subject['digest']['sha256']}  {subject['name']}"  # type: ignore[index]
        for subject in subjects
    ]
    (dist / "SHA256SUMS.txt").write_text(
        "\n".join(checksum_lines) + "\n", encoding="utf-8", newline="\n"
    )

    package_ref = f"pkg:pypi/{name}@{version}"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, package_ref)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": package_ref,
                "name": name,
                "version": version,
                "purl": package_ref,
            }
        },
        "components": [
            {
                "type": "file",
                "bom-ref": f"artifact:{subject['name']}",
                "name": subject["name"],
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": subject["digest"]["sha256"],  # type: ignore[index]
                    }
                ],
            }
            for subject in subjects
        ],
    }
    write_json(dist / "proofgate.cdx.json", sbom)

    source_sha = os.environ.get("GITHUB_SHA") or "UNRECORDED"
    evidence = {
        "schemaVersion": 1,
        "product": name,
        "version": version,
        "state": "PREPARED",
        "source": {
            "repository": "https://github.com/vigilanty0x/proofgate",
            "sha": source_sha,
        },
        "subjects": subjects,
        "sbom": {
            "path": "proofgate.cdx.json",
            "sha256": sha256_file(dist / "proofgate.cdx.json"),
            "format": "CycloneDX-1.6",
        },
        "checksums": {
            "path": "SHA256SUMS.txt",
            "sha256": sha256_file(dist / "SHA256SUMS.txt"),
        },
        "claims": {
            "signed": False,
            "attested": False,
            "published": False,
            "released": False,
        },
        "nextGate": "Run the manual release-evidence workflow, verify attestations, then obtain human release approval.",
    }
    write_json(dist / "RELEASE_EVIDENCE.json", evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", default="dist", help="directory containing wheel and sdist")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    dist = Path(args.dist)
    if not dist.is_absolute():
        dist = root / dist
    if not dist.is_dir():
        raise SystemExit(f"dist directory does not exist: {dist}")

    evidence = build_bundle(root, dist)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
