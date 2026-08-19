from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.check_release_policy import ReleasePolicyError, validate


ROOT = Path(__file__).resolve().parents[1]


class ReleasePolicyTests(unittest.TestCase):
    def test_current_repository_policy_is_fail_closed(self) -> None:
        receipt = validate(ROOT)
        self.assertEqual(receipt.version, "0.2.0")
        self.assertEqual(receipt.consolidation_state, "MERGED")
        self.assertEqual(receipt.source_count, 5)
        self.assertFalse(receipt.publish_enabled)
        self.assertFalse(receipt.release_authorized)
        self.assertFalse(receipt.archive_authorized)

    def fixture(self, root: Path) -> None:
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / "release-policy.v1.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "product": "proofgate",
                    "version": "0.2.0",
                    "state": "PREPARED",
                    "publishEnabled": False,
                    "releaseAuthorized": False,
                    "archiveAuthorized": False,
                    "sourceBranch": "main",
                    "humanReleaseApprovalRequired": True,
                    "requiredEvidence": [
                        "wheel",
                        "sdist",
                        "sha256sums",
                        "cyclonedx-sbom",
                        "wheel-provenance",
                        "sdist-provenance",
                        "wheel-sbom-attestation",
                    ],
                }
            ),
            encoding="utf-8",
        )
        source_names = [
            "audit-trail-lite",
            "evidence-ledger",
            "run-replay",
            "status-truth",
            "structured-output-guard",
        ]
        (root / ".portfolio-rehearsal.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "target": "proofgate",
                    "base": "proofgate",
                    "baseHeadSha": "b" * 40,
                    "mergeCommitSha": "c" * 40,
                    "sources": [
                        {
                            "repository": name,
                            "prefix": f"packages/{name}",
                            "headSha": "d" * 40,
                            "treeSha": "e" * 40,
                            "ancestor": True,
                            "treeMatch": True,
                        }
                        for name in source_names
                    ],
                    "state": "MERGED",
                    "archiveGate": "BLOCKED",
                    "reason": "Release and human gates remain blocked.",
                }
            ),
            encoding="utf-8",
        )
        (root / "pyproject.toml").write_text(
            '[project]\nname = "proofgate"\nversion = "0.2.0"\n', encoding="utf-8"
        )
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## 0.2.0 - 2026-08-16\n\n- Consolidation state is MERGED.\n- Release remains PREPARED.\n",
            encoding="utf-8",
        )
        (root / ".github" / "workflows" / "ci.yml").write_text(
            'python-version: ["3.11", "3.12", "3.13", "3.14"]\n'
            "python scripts/check_release_policy.py\n",
            encoding="utf-8",
        )
        (root / ".github" / "workflows" / "release-evidence.yml").write_text(
            """name: Release evidence
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  attest-release-candidate:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - name: Require default branch
        env:
          CURRENT_REF: ${{ github.ref_name }}
          DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
        run: |
          if [[ "$CURRENT_REF" != "$DEFAULT_BRANCH" ]]; then exit 2; fi
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          persist-credentials: false
      - uses: actions/setup-python@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      - run: python scripts/check_release_policy.py
      - run: python scripts/release_evidence.py --dist dist
      - uses: actions/attest@cccccccccccccccccccccccccccccccccccccccc
        with:
          subject-path: dist/*.whl
      - uses: actions/attest@cccccccccccccccccccccccccccccccccccccccc
        with:
          subject-path: dist/*.tar.gz
      - uses: actions/attest@cccccccccccccccccccccccccccccccccccccccc
        with:
          subject-path: dist/*.whl
          sbom-path: dist/proofgate.cdx.json
      - uses: actions/upload-artifact@dddddddddddddddddddddddddddddddddddddddd
        with:
          name: proofgate-release-evidence-${{ github.sha }}
""",
            encoding="utf-8",
        )

    def test_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            receipt = validate(root)
            self.assertEqual(receipt.source_count, 5)

    def test_rehearsal_only_state_is_rejected_after_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            payload = json.loads((root / ".portfolio-rehearsal.json").read_text(encoding="utf-8"))
            payload["state"] = "REHEARSAL_ONLY"
            (root / ".portfolio-rehearsal.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReleasePolicyError, "portfolio state"):
                validate(root)

    def test_archive_authorization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            payload = json.loads((root / "release-policy.v1.json").read_text(encoding="utf-8"))
            payload["archiveAuthorized"] = True
            (root / "release-policy.v1.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReleasePolicyError, "archiveAuthorized"):
                validate(root)

    def test_release_write_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            path = root / ".github" / "workflows" / "release-evidence.yml"
            path.write_text(path.read_text(encoding="utf-8") + "\n# contents: write\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleasePolicyError, "forbidden authority"):
                validate(root)

    def test_missing_python_314_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            path = root / ".github" / "workflows" / "ci.yml"
            path.write_text(
                'python-version: ["3.11", "3.12", "3.13"]\npython scripts/check_release_policy.py\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleasePolicyError, "3.11 through 3.14"):
                validate(root)


if __name__ == "__main__":
    unittest.main()
