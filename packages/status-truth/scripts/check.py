"""Dependency-free repository and public-boundary checks."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".json"}
FORBIDDEN = (
    "sk" + "yom",
    "private" + "_token",
    "api" + "_key=",
    "authorization:" + " bearer",
)


def main() -> int:
    failures: list[str] = []
    files = sorted(path for path in ROOT.rglob("*") if path.is_file())
    for path in files:
        if any(part in {"dist", "build", "__pycache__"} for part in path.parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", ".gitignore"}:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for marker in FORBIDDEN:
                if marker in lowered:
                    failures.append(f"{path.relative_to(ROOT)} contains forbidden boundary marker")
            if path.suffix == ".py":
                try:
                    ast.parse(text, filename=str(path))
                except SyntaxError as exc:
                    failures.append(f"{path.relative_to(ROOT)}: {exc}")
    required = (
        "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "AI_ASSISTANCE.md",
        "CHANGELOG.md", "pyproject.toml", ".github/workflows/ci.yml",
    )
    for name in required:
        if not (ROOT / name).is_file():
            failures.append(f"missing required file: {name}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"public-boundary: ok ({len(files)} files inspected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
