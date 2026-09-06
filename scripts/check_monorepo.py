from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MONOREPO.json"
SHA = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"monorepo manifest: {message}")


def main() -> None:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))

    if data.get("schema_version") != 1:
        fail("schema_version must be 1")
    if data.get("delete_authorized") is not False:
        fail("source deletion must remain explicitly unauthorized")

    target = data.get("target")
    if not isinstance(target, dict):
        fail("target must be an object")
    sources = target.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("target.sources must be a non-empty list")

    seen: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            fail(f"source {index} must be an object")
        repository = source.get("repository")
        if not isinstance(repository, str) or repository.count("/") != 1:
            fail(f"source {index} has an invalid repository")
        if repository in seen:
            fail(f"duplicate source {repository}")
        seen.add(repository)

        metadata = source.get("source")
        if not isinstance(metadata, dict):
            fail(f"{repository} has no source metadata")
        if not SHA.fullmatch(str(metadata.get("head", ""))):
            fail(f"{repository} has an invalid source head")
        if not SHA.fullmatch(str(metadata.get("tree", ""))):
            fail(f"{repository} has an invalid source tree")
        if metadata.get("visibility") not in {"PUBLIC", "PRIVATE", "INTERNAL"}:
            fail(f"{repository} has an invalid visibility")

        raw_path = source.get("target_path")
        if not isinstance(raw_path, str) or "\\" in raw_path:
            fail(f"{repository} has an invalid target path")
        pure = PurePosixPath(raw_path)
        if pure.is_absolute() or ".." in pure.parts:
            fail(f"{repository} target path escapes the repository")
        local = ROOT if raw_path == "." else ROOT.joinpath(*pure.parts)
        if not local.exists():
            fail(f"{repository} target path is missing: {raw_path}")

    print(f"monorepo manifest: {len(sources)} sources mapped for {target['repository']}")


if __name__ == "__main__":
    main()
