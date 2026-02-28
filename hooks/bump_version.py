#!/usr/bin/env python3
"""Pre-commit hook: auto-bump minor version if unchanged from origin/main.

When the version in pyproject.toml matches origin/main, bumps the minor
segment (e.g. 0.1.7 → 0.2.0) and stages pyproject.toml so the bump is
included in the current commit.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PYPROJECT_PATH = Path(__file__).parent.parent / "pyproject.toml"
_VERSION_RE = re.compile(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', re.MULTILINE)


def parse_version(content: str) -> tuple[int, int, int]:
    """Extract (major, minor, patch) from pyproject.toml content."""
    m = _VERSION_RE.search(content)
    if not m:
        print("bump-version: ERROR: could not find version in pyproject.toml", flush=True)
        sys.exit(1)
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def bump_minor(version: tuple[int, int, int]) -> tuple[int, int, int]:
    """Increment minor, reset patch to 0."""
    major, minor, _ = version
    return major, minor + 1, 0


def write_version(content: str, version: tuple[int, int, int]) -> str:
    """Return content with version replaced."""
    new = f"{version[0]}.{version[1]}.{version[2]}"
    return _VERSION_RE.sub(f'version = "{new}"', content, count=1)


def get_main_version() -> tuple[int, int, int] | None:
    """Read version from origin/main:pyproject.toml. Returns None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "show", "origin/main:pyproject.toml"],
            capture_output=True,
            text=True,
            check=True,
        )
        return parse_version(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(
            "bump-version: WARNING: could not read origin/main — skipping version check",
            flush=True,
        )
        return None


def main() -> int:
    content = PYPROJECT_PATH.read_text(encoding="utf-8")
    current = parse_version(content)
    main_ver = get_main_version()

    if main_ver is None:
        return 0  # offline or no remote — non-blocking

    if current != main_ver:
        return 0  # already bumped

    new_ver = bump_minor(current)
    new_content = write_version(content, new_ver)
    PYPROJECT_PATH.write_text(new_content, encoding="utf-8")

    try:
        subprocess.run(["git", "add", str(PYPROJECT_PATH)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"bump-version: ERROR: git add failed: {e}", flush=True)
        return 1

    old_str = f"{current[0]}.{current[1]}.{current[2]}"
    new_str = f"{new_ver[0]}.{new_ver[1]}.{new_ver[2]}"
    print(f"bump-version: auto-bumped {old_str} → {new_str}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
