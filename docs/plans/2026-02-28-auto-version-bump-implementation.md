# Auto Version Bump Pre-Commit Hook — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a pre-commit hook that auto-bumps the minor version in `pyproject.toml` when the working branch version matches `origin/main`, staging the change so it lands in the current commit.

**Architecture:** A standalone Python script (`hooks/bump_version.py`) reads both versions via regex and `git show origin/main:pyproject.toml`, bumps minor+resets patch when they match, then re-stages `pyproject.toml`. A new local hook entry in `.pre-commit-config.yaml` wires it into the existing pre-commit pipeline.

**Tech Stack:** Python 3.10 stdlib only (`re`, `subprocess`, `pathlib`), pytest, pre-commit framework.

---

### Task 1: Write `hooks/bump_version.py` (TDD)

**Files:**
- Create: `hooks/bump_version.py`
- Create: `tests/test_bump_version.py`

---

**Step 1: Write the failing tests**

Create `tests/test_bump_version.py`:

```python
"""Tests for hooks/bump_version.py"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# bump_version.py lives in hooks/, not src/ — import it directly
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))
import bump_version  # noqa: E402


PYPROJECT_SAME = '[project]\nname = "controlgate"\nversion = "0.1.7"\n'
PYPROJECT_MAIN = '[project]\nname = "controlgate"\nversion = "0.1.7"\n'
PYPROJECT_BUMPED = '[project]\nname = "controlgate"\nversion = "0.2.0"\n'
PYPROJECT_HIGHER = '[project]\nname = "controlgate"\nversion = "0.2.0"\n'


class TestParseVersion:
    def test_parses_version_from_content(self):
        assert bump_version.parse_version(PYPROJECT_SAME) == (0, 1, 7)

    def test_raises_on_missing_version(self):
        with pytest.raises(SystemExit):
            bump_version.parse_version("[project]\nname = 'x'\n")


class TestBumpMinor:
    def test_bumps_minor_and_resets_patch(self):
        assert bump_version.bump_minor((0, 1, 7)) == (0, 2, 0)

    def test_bumps_minor_on_zero_patch(self):
        assert bump_version.bump_minor((0, 2, 0)) == (0, 3, 0)

    def test_preserves_major(self):
        assert bump_version.bump_minor((1, 5, 3)) == (1, 6, 0)


class TestWriteVersion:
    def test_replaces_version_in_content(self):
        result = bump_version.write_version(PYPROJECT_SAME, (0, 2, 0))
        assert 'version = "0.2.0"' in result
        assert 'version = "0.1.7"' not in result


class TestGetMainVersion:
    def test_returns_tuple_when_origin_available(self):
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with patch("subprocess.run", return_value=mock_result):
            assert bump_version.get_main_version() == (0, 1, 7)

    def test_returns_none_when_origin_unavailable(self, capsys):
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, "git")):
            result = bump_version.get_main_version()
        assert result is None
        captured = capsys.readouterr()
        assert "warning" in captured.out.lower()

    def test_returns_none_when_git_not_found(self, capsys):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = bump_version.get_main_version()
        assert result is None


class TestMain:
    def test_bumps_and_stages_when_versions_match(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_SAME)
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", return_value=mock_result),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        assert 'version = "0.2.0"' in pyproject.read_text()

    def test_skips_when_versions_differ(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_HIGHER)
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", return_value=mock_result),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        assert 'version = "0.2.0"' in pyproject.read_text()  # unchanged

    def test_passes_when_origin_unavailable(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_SAME)
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, "git")),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        # Version unchanged since we couldn't compare
        assert 'version = "0.1.7"' in pyproject.read_text()
```

**Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_bump_version.py -v
```

Expected: `ModuleNotFoundError: No module named 'bump_version'`

---

**Step 3: Implement `hooks/bump_version.py`**

Create `hooks/bump_version.py`:

```python
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
    new = f'{version[0]}.{version[1]}.{version[2]}'
    return _VERSION_RE.sub(f'version = "{new}"', content)


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

    subprocess.run(["git", "add", str(PYPROJECT_PATH)], check=True)

    old_str = f"{current[0]}.{current[1]}.{current[2]}"
    new_str = f"{new_ver[0]}.{new_ver[1]}.{new_ver[2]}"
    print(f"bump-version: auto-bumped {old_str} → {new_str}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_bump_version.py -v
```

Expected: all tests PASS.

**Step 5: Confirm 100% coverage still holds**

```bash
pytest --cov=controlgate --cov-report=term-missing -q
```

Expected: `Total coverage: 100%` (bump_version.py is in `hooks/`, not `src/controlgate/`, so it doesn't affect the coverage target).

**Step 6: Commit**

```bash
git add hooks/bump_version.py tests/test_bump_version.py
git commit -m "feat: add auto-bump minor version pre-commit hook"
```

---

### Task 2: Wire hook into `.pre-commit-config.yaml`

**Files:**
- Modify: `.pre-commit-config.yaml`

---

**Step 1: Add the local hook entry**

Append to `.pre-commit-config.yaml`:

```yaml
  - repo: local
    hooks:
      - id: bump-version
        name: Auto-bump version if unchanged from main
        entry: python hooks/bump_version.py
        language: python
        always_run: true
        pass_filenames: false
```

The full file should look like:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.0
    hooks:
      - id: ruff
        args: [ --fix ]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [ types-PyYAML, pytest ]
        args: [ --config-file, pyproject.toml ]

  - repo: local
    hooks:
      - id: bump-version
        name: Auto-bump version if unchanged from main
        entry: python hooks/bump_version.py
        language: python
        always_run: true
        pass_filenames: false
```

**Step 2: Verify the hook is recognised by pre-commit**

```bash
pre-commit run bump-version --all-files
```

Expected output contains: `Auto-bump version if unchanged from main...Passed` (or the bump message if versions matched).

**Step 3: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "chore: register bump-version as a local pre-commit hook"
```

---

### Task 3: Smoke-test end-to-end

**Step 1: Simulate a fresh commit with matching versions**

Reset your local `pyproject.toml` version to match `origin/main` (`0.1.7`), stage a trivial change, and commit:

```bash
# Check what main has
git show origin/main:pyproject.toml | grep '^version'

# If current version already differs, temporarily set it to match
# (edit pyproject.toml manually to version = "0.1.7")
git add pyproject.toml
echo "# smoke test" >> README.md
git add README.md
git commit -m "test: smoke test auto-bump hook"
```

Expected: pre-commit output includes `bump-version: auto-bumped 0.1.7 → 0.2.0` and the commit contains the bumped `pyproject.toml`.

**Step 2: Verify the committed version**

```bash
git show HEAD:pyproject.toml | grep '^version'
```

Expected: `version = "0.2.0"`

**Step 3: Revert smoke-test changes if needed**

```bash
git revert HEAD --no-edit
```

---

## Notes

- `hooks/bump_version.py` uses only stdlib — no extra install needed.
- The hook runs **before** ruff/mypy so a bumped `pyproject.toml` is linted too.
  If ordering matters, place the `local` repo block first in `.pre-commit-config.yaml`.
- The coverage config in `pyproject.toml` sources only `controlgate` (`source = ["controlgate"]`), so `hooks/` is outside coverage scope by design.
- If a developer is on a branch where `origin/main` hasn't been fetched recently, run `git fetch origin main` once to refresh the cached ref.
