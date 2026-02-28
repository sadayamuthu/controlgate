# Full Scan Mode & Init Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `controlgate scan --mode full` (whole-repo scan) and `controlgate init` (interactive bootstrap) to the CLI.

**Architecture:** Full scan creates synthetic `DiffFile` objects from real files — all content becomes `added_lines` — so all 18 gates run unchanged. Init is a new `init_command.py` module with inline templates for all generated files; wired into the existing CLI parser.

**Tech Stack:** Python 3.10+, argparse, pathlib, subprocess (existing); no new dependencies.

**Design doc:** `docs/plans/2026-02-27-full-scan-and-init-design.md`

---

## Task 1: Extend `ControlGateConfig` with `full_scan` fields

**Files:**
- Modify: `src/controlgate/config.py`
- Test: `tests/test_config.py` (create new)

### Step 1: Write the failing test

```python
# tests/test_config.py
from controlgate.config import ControlGateConfig

class TestFullScanConfig:
    def test_default_full_scan_extensions(self):
        config = ControlGateConfig.load()
        assert ".py" in config.full_scan_extensions
        assert ".tf" in config.full_scan_extensions

    def test_default_full_scan_skip_dirs(self):
        config = ControlGateConfig.load()
        assert ".git" in config.full_scan_skip_dirs
        assert "node_modules" in config.full_scan_skip_dirs

    def test_full_scan_extensions_override(self, tmp_path):
        cfg_file = tmp_path / ".controlgate.yml"
        cfg_file.write_text("full_scan:\n  extensions: [.py, .rb]\n")
        config = ControlGateConfig.load(cfg_file)
        assert config.full_scan_extensions == [".py", ".rb"]

    def test_full_scan_skip_dirs_override(self, tmp_path):
        cfg_file = tmp_path / ".controlgate.yml"
        cfg_file.write_text("full_scan:\n  skip_dirs: [vendor]\n")
        config = ControlGateConfig.load(cfg_file)
        assert config.full_scan_skip_dirs == ["vendor"]
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_config.py -v
```
Expected: `AttributeError: 'ControlGateConfig' object has no attribute 'full_scan_extensions'`

### Step 3: Add fields to `_DEFAULT_CONFIG` dict in `config.py`

In `_DEFAULT_CONFIG`, add after the `"reporting"` key:
```python
"full_scan": {
    "extensions": [
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".go", ".java", ".rb", ".rs", ".c", ".cpp", ".h",
        ".tf", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        ".sh", ".bash", ".zsh", ".env", ".xml", ".sql",
    ],
    "skip_dirs": [
        ".git", "node_modules", ".venv", "venv", "env",
        "__pycache__", "dist", "build", ".tox",
        ".mypy_cache", ".ruff_cache", ".pytest_cache",
        ".eggs", "*.egg-info",
    ],
},
```

### Step 4: Add fields to `ControlGateConfig` dataclass

After `output_dir: str = ".controlgate/reports"` add:
```python
full_scan_extensions: list[str] = field(
    default_factory=lambda: [
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".go", ".java", ".rb", ".rs", ".c", ".cpp", ".h",
        ".tf", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        ".sh", ".bash", ".zsh", ".env", ".xml", ".sql",
    ]
)
full_scan_skip_dirs: list[str] = field(
    default_factory=lambda: [
        ".git", "node_modules", ".venv", "venv", "env",
        "__pycache__", "dist", "build", ".tox",
        ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ]
)
```

### Step 5: Parse the new section in `_from_raw()`

At the end of `_from_raw()`, before `return cfg`, add:
```python
# Full scan
full_scan = raw.get("full_scan", {})
cfg.full_scan_extensions = full_scan.get("extensions", cfg.full_scan_extensions)
cfg.full_scan_skip_dirs = full_scan.get("skip_dirs", cfg.full_scan_skip_dirs)
```

### Step 6: Run tests to verify they pass

```bash
pytest tests/test_config.py -v
```
Expected: 4 tests PASS

### Step 7: Commit

```bash
git add src/controlgate/config.py tests/test_config.py
git commit -m "feat: add full_scan config fields (extensions, skip_dirs)"
```

---

## Task 2: Add `_get_full_files()` to `__main__.py`

**Files:**
- Modify: `src/controlgate/__main__.py`
- Test: `tests/test_full_scan.py` (create new)

### Step 1: Write the failing test

```python
# tests/test_full_scan.py
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from controlgate.__main__ import _get_full_files
from controlgate.config import ControlGateConfig
from controlgate.models import DiffFile


class TestGetFullFiles:
    def test_returns_diff_files(self, tmp_path):
        (tmp_path / "app.py").write_text('x = 1\ny = 2\n')
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert any(f.path.endswith("app.py") for f in files)

    def test_all_lines_are_added(self, tmp_path):
        (tmp_path / "app.py").write_text('line1\nline2\nline3\n')
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        py_file = next(f for f in files if f.path.endswith("app.py"))
        assert len(py_file.all_added_lines) == 3
        assert py_file.all_added_lines[0] == (1, "line1")
        assert py_file.all_added_lines[2] == (3, "line3")

    def test_skips_excluded_paths(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "readme.md").write_text("# Docs")
        config = ControlGateConfig.load()
        # docs/** is in default exclusions
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        paths = [f.path for f in files]
        assert not any("docs" in p for p in paths)

    def test_skips_skip_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text("module.exports = {}")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any("node_modules" in f.path for f in files)

    def test_skips_unlisted_extensions(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith(".png") for f in files)

    def test_skips_binary_files(self, tmp_path):
        (tmp_path / "app.py").write_bytes(b"normal\x00binary\x00content")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith("app.py") for f in files)

    def test_uses_git_ls_files_when_available(self, tmp_path):
        (tmp_path / "tracked.py").write_text("x = 1")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run") as mock_run:
            mock_run.return_value.stdout = "tracked.py\n"
            mock_run.return_value.returncode = 0
            files = _get_full_files(tmp_path, config)
        assert any(f.path.endswith("tracked.py") for f in files)

    def test_skips_empty_files(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith("empty.py") for f in files)
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_full_scan.py -v
```
Expected: `ImportError: cannot import name '_get_full_files'`

### Step 3: Implement `_get_full_files()` in `__main__.py`

Add this import at the top of `__main__.py` (after existing imports):
```python
import os
```

Add this function after `_get_diff()`:

```python
def _get_full_files(root: Path, config: "ControlGateConfig") -> list["DiffFile"]:
    """Enumerate all project files for full-repo scan mode.

    Tries ``git ls-files`` first (respects .gitignore). Falls back to
    directory walk when not in a git repo.

    Args:
        root: Project root directory to scan.
        config: ControlGate config (for extension/skip_dir filters).

    Returns:
        List of DiffFile objects with all content as added_lines.
    """
    from controlgate.models import DiffFile, DiffHunk

    root = root.resolve()
    candidate_paths: list[Path] = []

    # 1. Try git ls-files (honors .gitignore automatically)
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=True,
            cwd=root,
        )
        candidate_paths = [root / p for p in result.stdout.strip().splitlines() if p.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back: walk directory
        candidate_paths = [p for p in root.rglob("*") if p.is_file()]

    diff_files: list[DiffFile] = []

    for abs_path in candidate_paths:
        try:
            rel_path = str(abs_path.relative_to(root))
        except ValueError:
            rel_path = str(abs_path)

        # Skip paths excluded by config glob patterns
        if config.is_path_excluded(rel_path):
            continue

        # Skip any path component that is in skip_dirs
        path_parts = Path(rel_path).parts
        if any(part in config.full_scan_skip_dirs for part in path_parts):
            continue

        # Filter by extension allowlist (empty list = allow all)
        if config.full_scan_extensions and abs_path.suffix not in config.full_scan_extensions:
            continue

        # Skip binary files (null-byte heuristic)
        try:
            sample = abs_path.read_bytes()[:8192]
            if b"\x00" in sample:
                continue
        except (OSError, PermissionError):
            continue

        # Read text content
        try:
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        lines = content.splitlines()
        if not lines:
            continue

        hunk = DiffHunk(
            start_line=1,
            line_count=len(lines),
            added_lines=list(enumerate(lines, start=1)),
        )
        df = DiffFile(path=rel_path)
        df.hunks = [hunk]
        diff_files.append(df)

    return diff_files
```

### Step 4: Run tests to verify they pass

```bash
pytest tests/test_full_scan.py -v
```
Expected: 8 tests PASS

### Step 5: Commit

```bash
git add src/controlgate/__main__.py tests/test_full_scan.py
git commit -m "feat: add _get_full_files() for full-repo scan mode"
```

---

## Task 3: Wire `full` mode into `scan_command()` and parser

**Files:**
- Modify: `src/controlgate/__main__.py`
- Test: `tests/test_full_scan.py` (extend), `tests/test_cli.py` (extend)

### Step 1: Write failing tests

Add to `tests/test_full_scan.py`:

```python
class TestFullScanMode:
    def test_parser_accepts_full_mode(self):
        from controlgate.__main__ import build_parser
        parser = build_parser()
        args = parser.parse_args(["scan", "--mode", "full"])
        assert args.mode == "full"

    def test_full_scan_finds_secrets(self, tmp_path):
        """Full scan detects hardcoded secrets in a real file."""
        from controlgate.__main__ import build_parser, scan_command
        secret_file = tmp_path / "config.py"
        secret_file.write_text('DB_PASSWORD = "super_secret_123"\n')
        parser = build_parser()
        args = parser.parse_args(["scan", "--mode", "full", "--format", "json"])
        args.path = str(tmp_path)
        exit_code = scan_command(args)
        assert exit_code == 1  # BLOCK due to secrets

    def test_full_scan_clean_directory(self, tmp_path):
        """Full scan passes for directory with no security issues."""
        from controlgate.__main__ import build_parser, scan_command
        clean_file = tmp_path / "utils.py"
        clean_file.write_text("import os\nenv = os.environ.get('KEY')\n")
        parser = build_parser()
        args = parser.parse_args(["scan", "--mode", "full", "--format", "json"])
        args.path = str(tmp_path)
        exit_code = scan_command(args)
        assert exit_code == 0  # PASS

    def test_full_scan_empty_directory(self, tmp_path):
        """Full scan on empty directory returns 0."""
        from controlgate.__main__ import build_parser, scan_command
        parser = build_parser()
        args = parser.parse_args(["scan", "--mode", "full", "--format", "json"])
        args.path = str(tmp_path)
        exit_code = scan_command(args)
        assert exit_code == 0
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/test_full_scan.py::TestFullScanMode -v
```
Expected: FAIL — `argument --mode: invalid choice: 'full'` for parser test

### Step 3: Update `build_parser()` — add `full` to `--mode` choices and `--path` arg

In `build_parser()`, change:
```python
# OLD
choices=["pre-commit", "pr"],
```
to:
```python
# NEW
choices=["pre-commit", "pr", "full"],
```

Add `--path` arg after `--output-dir`:
```python
scan_parser.add_argument(
    "--path",
    type=str,
    default=None,
    help="Root directory for full scan mode (default: current directory)",
)
```

### Step 4: Update `scan_command()` — handle `full` mode

In `scan_command()`, replace the block that gets the diff:

```python
# OLD
if args.diff_file:
    diff_text = Path(args.diff_file).read_text(encoding="utf-8")
else:
    diff_text = _get_diff(args.mode, args.target_branch)

if not diff_text.strip():
    print("ℹ️  No changes to scan.", file=sys.stderr)
    return 0

diff_files = parse_diff(diff_text)
print(
    f"📄 Scanning {len(diff_files)} changed file(s)...",
    file=sys.stderr,
)
```

with:

```python
if args.mode == "full":
    scan_root = Path(getattr(args, "path", None) or ".").resolve()
    diff_files = _get_full_files(scan_root, config)
    if not diff_files:
        print("ℹ️  No files found to scan.", file=sys.stderr)
        return 0
    print(
        f"📄 Full scan: {len(diff_files)} file(s) in {scan_root}...",
        file=sys.stderr,
    )
elif args.diff_file:
    diff_text = Path(args.diff_file).read_text(encoding="utf-8")
    if not diff_text.strip():
        print("ℹ️  No changes to scan.", file=sys.stderr)
        return 0
    diff_files = parse_diff(diff_text)
    print(f"📄 Scanning {len(diff_files)} changed file(s)...", file=sys.stderr)
else:
    diff_text = _get_diff(args.mode, args.target_branch)
    if not diff_text.strip():
        print("ℹ️  No changes to scan.", file=sys.stderr)
        return 0
    diff_files = parse_diff(diff_text)
    print(f"📄 Scanning {len(diff_files)} changed file(s)...", file=sys.stderr)
```

### Step 5: Run tests to verify they pass

```bash
pytest tests/test_full_scan.py -v
```
Expected: all PASS (the `test_full_scan_finds_secrets` test may be slow — acceptable)

### Step 6: Run full test suite to confirm no regressions

```bash
pytest tests/test_cli.py tests/test_full_scan.py -v
```
Expected: all PASS

### Step 7: Commit

```bash
git add src/controlgate/__main__.py tests/test_full_scan.py
git commit -m "feat: add controlgate scan --mode full with --path option"
```

---

## Task 4: Create `src/controlgate/init_command.py` with all templates

**Files:**
- Create: `src/controlgate/init_command.py`
- Test: `tests/test_init_command.py` (create new)

### Step 1: Write failing tests

```python
# tests/test_init_command.py
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from controlgate.init_command import (
    _build_controlgate_yml,
    _build_precommit_config,
    _build_controlgate_md,
    _build_github_workflow,
    _build_gitlab_ci,
    _build_bitbucket_pipelines,
)


class TestTemplates:
    def test_controlgate_yml_contains_all_18_gates(self):
        content = _build_controlgate_yml("moderate")
        for gate in ["secrets", "crypto", "iam", "sbom", "iac", "input_validation",
                     "audit", "change_control", "deps", "api", "privacy", "resilience",
                     "incident", "observability", "memsafe", "license", "aiml", "container"]:
            assert gate in content, f"Gate '{gate}' missing from template"

    def test_controlgate_yml_has_chosen_baseline(self):
        content = _build_controlgate_yml("high")
        assert "baseline: high" in content

    def test_precommit_config_has_controlgate_hook(self):
        content = _build_precommit_config()
        assert "controlgate" in content
        assert "pre-commit" in content

    def test_controlgate_md_has_all_modes(self):
        content = _build_controlgate_md()
        assert "--mode pre-commit" in content
        assert "--mode pr" in content
        assert "--mode full" in content

    def test_controlgate_md_has_18_gates_table(self):
        content = _build_controlgate_md()
        for gate_name in ["Secrets", "Crypto", "IAM", "Supply Chain", "IaC",
                          "Input Validation", "Audit", "Change Control",
                          "Dependencies", "API Security", "Privacy", "Resilience",
                          "Incident Response", "Observability", "Memory Safety",
                          "License Compliance", "AI/ML Security", "Container Security"]:
            assert gate_name in content, f"Gate '{gate_name}' missing from CONTROLGATE.md"

    def test_github_workflow_has_pr_trigger(self):
        content = _build_github_workflow()
        assert "pull_request" in content
        assert "controlgate scan" in content

    def test_gitlab_ci_has_controlgate_job(self):
        content = _build_gitlab_ci()
        assert "controlgate" in content
        assert "controlgate scan" in content

    def test_bitbucket_pipelines_has_controlgate_step(self):
        content = _build_bitbucket_pipelines()
        assert "controlgate" in content
        assert "controlgate scan" in content


class TestInitCommand:
    def test_creates_controlgate_yml(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".controlgate.yml").exists()

    def test_creates_precommit_config(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".pre-commit-config.yaml").exists()

    def test_creates_controlgate_md_by_default(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / "CONTROLGATE.md").exists()

    def test_no_docs_skips_controlgate_md(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=True)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert not (tmp_path / "CONTROLGATE.md").exists()

    def test_creates_github_workflow_when_confirmed(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "y", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".github" / "workflows" / "controlgate.yml").exists()

    def test_skips_github_workflow_when_denied(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert not (tmp_path / ".github" / "workflows" / "controlgate.yml").exists()

    def test_overwrite_prompt_on_existing_file(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        (tmp_path / ".controlgate.yml").write_text("existing: true\n")
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        # First input = baseline, second = overwrite .controlgate.yml (n), rest = CI prompts
        inputs = iter(["moderate", "n", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        # Original content preserved
        assert "existing: true" in (tmp_path / ".controlgate.yml").read_text()

    def test_returns_zero_on_success(self, tmp_path):
        from controlgate.init_command import init_command
        import argparse
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            result = init_command(args)
        assert result == 0
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/test_init_command.py -v
```
Expected: `ModuleNotFoundError: No module named 'controlgate.init_command'`

### Step 3: Create `src/controlgate/init_command.py`

```python
"""ControlGate init command — bootstrap project configuration files."""

from __future__ import annotations

import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Template builders
# ---------------------------------------------------------------------------

def _build_controlgate_yml(baseline: str) -> str:
    return f"""\
# .controlgate.yml — ControlGate Configuration
# Reference: https://github.com/sadayamuthu/controlgate
#
# Baseline: low | moderate | high | privacy | li-saas
baseline: {baseline}

# Set to true to evaluate against FedRAMP baselines instead of NIST
gov: false

# NIST control catalog path (auto-managed; change only if self-hosting)
# catalog: baseline/nist80053r5_full_catalog_enriched.json

# ---------------------------------------------------------------------------
# Security Gates — 18 gates mapped to NIST SP 800-53 Rev. 5 controls
# action: block | warn | disabled
# ---------------------------------------------------------------------------
gates:
  # Gate 1 — Secrets & Credentials (IA-5, SC-12, SC-28)
  secrets:        {{ enabled: true,  action: block }}

  # Gate 2 — Cryptography (SC-8, SC-13, SC-17)
  crypto:         {{ enabled: true,  action: block }}

  # Gate 3 — IAM & Access Control (AC-3, AC-5, AC-6)
  iam:            {{ enabled: true,  action: warn  }}

  # Gate 4 — Supply Chain / SBOM (SR-3, SR-11, SA-10)
  sbom:           {{ enabled: true,  action: warn  }}

  # Gate 5 — Infrastructure as Code (CM-2, CM-6, SC-7)
  iac:            {{ enabled: true,  action: block }}

  # Gate 6 — Input Validation (SI-10, SI-11)
  input_validation: {{ enabled: true, action: block }}

  # Gate 7 — Audit Logging (AU-2, AU-3, AU-12)
  audit:          {{ enabled: true,  action: warn  }}

  # Gate 8 — Change Control (CM-3, CM-4, CM-5)
  change_control: {{ enabled: true,  action: warn  }}

  # Gate 9 — Dependency Management (SA-12, RA-5, SI-2)
  deps:           {{ enabled: true,  action: warn  }}

  # Gate 10 — API Security (SC-8, AC-3, SI-10)
  api:            {{ enabled: true,  action: warn  }}

  # Gate 11 — Privacy (AR-2, DM-1, IP-1)
  privacy:        {{ enabled: true,  action: warn  }}

  # Gate 12 — Resilience & Reliability (CP-2, CP-10, SC-5)
  resilience:     {{ enabled: true,  action: warn  }}

  # Gate 13 — Incident Response (IR-2, IR-4, IR-6)
  incident:       {{ enabled: true,  action: warn  }}

  # Gate 14 — Observability (AU-6, SI-4, CA-7)
  observability:  {{ enabled: true,  action: warn  }}

  # Gate 15 — Memory Safety (SI-16, SA-11, SA-15)
  memsafe:        {{ enabled: true,  action: warn  }}

  # Gate 16 — License Compliance (SA-4, SR-3)
  license:        {{ enabled: true,  action: warn  }}

  # Gate 17 — AI/ML Security (SA-11, SI-7, AC-3)
  aiml:           {{ enabled: true,  action: warn  }}

  # Gate 18 — Container Security (CM-6, AC-6, SC-7)
  container:      {{ enabled: true,  action: warn  }}

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------
thresholds:
  block_on: [CRITICAL, HIGH]   # Exit code 1, blocks commit/merge
  warn_on:  [MEDIUM]           # Reported but non-blocking
  ignore:   [LOW]              # Suppressed

# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
exclusions:
  paths:
    - "tests/**"
    - "docs/**"
    - "*.md"
  controls: []                 # e.g. [AC-13, AC-15]

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
reporting:
  format: [json, markdown]
  sarif: false
  output_dir: .controlgate/reports

# ---------------------------------------------------------------------------
# Full scan mode (controlgate scan --mode full)
# ---------------------------------------------------------------------------
full_scan:
  extensions:
    - .py
    - .js
    - .ts
    - .jsx
    - .tsx
    - .go
    - .java
    - .rb
    - .rs
    - .tf
    - .yaml
    - .yml
    - .json
    - .toml
    - .sh
    - .env
    - .sql
  skip_dirs:
    - .git
    - node_modules
    - .venv
    - venv
    - __pycache__
    - dist
    - build
    - .tox
"""


def _build_precommit_config() -> str:
    return """\
# .pre-commit-config.yaml — ControlGate pre-commit hook
# Install: pip install pre-commit && pre-commit install
repos:
  - repo: local
    hooks:
      - id: controlgate
        name: ControlGate Security Scan
        # For FedRAMP baselines, add: --gov --baseline moderate
        entry: python -m controlgate scan --mode pre-commit --format markdown
        language: python
        always_run: true
        pass_filenames: false
"""


def _build_controlgate_md() -> str:
    return """\
# ControlGate — Security Compliance Guide

ControlGate enforces **NIST SP 800-53 Rev. 5** (and **FedRAMP**) security controls
on every commit and merge through automated gate scanning.

---

## Quick Start

```bash
# Install
pip install controlgate

# Bootstrap this project (creates all config files)
controlgate init

# Baseline audit — scan the entire repo
controlgate scan --mode full --format markdown

# Pre-commit scan (staged changes only)
controlgate scan --mode pre-commit --format markdown

# PR scan (branch diff vs main)
controlgate scan --mode pr --target-branch main --format json markdown sarif
```

---

## Scan Modes

| Mode | Command | What It Scans |
|------|---------|---------------|
| `pre-commit` | `controlgate scan --mode pre-commit` | Staged changes (`git diff --cached`) |
| `pr` | `controlgate scan --mode pr --target-branch main` | Branch diff vs target branch |
| `full` | `controlgate scan --mode full [--path ./src]` | Entire project directory |

### Full Scan Mode

Use `--mode full` to audit the whole repository — ideal for:
- Onboarding: establish a security baseline before enforcing pre-commit hooks
- CI scheduled scans: weekly full-repo compliance reports
- New team members: run once to understand the codebase's compliance posture

```bash
# Scan current directory
controlgate scan --mode full --format markdown

# Scan a specific subdirectory
controlgate scan --mode full --path ./src --format json

# FedRAMP High full scan with reports
controlgate scan --mode full --gov --baseline high --output-dir .controlgate/reports
```

---

## The 18 Security Gates

| # | Gate | NIST Families | What It Catches | Default Action |
|---|------|---------------|-----------------|----------------|
| 1 | 🔑 Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys | BLOCK |
| 2 | 🔒 Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, `ssl_verify=False` | BLOCK |
| 3 | 🛡️ IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles | WARN |
| 4 | 📦 Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering | WARN |
| 5 | 🏗️ IaC | CM-2, CM-6, SC-7 | Public buckets, `0.0.0.0/0` rules, root containers | BLOCK |
| 6 | ✅ Input Validation | SI-10, SI-11 | SQL injection, `eval()`, exposed stack traces | BLOCK |
| 7 | 📋 Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs | WARN |
| 8 | 🔄 Change Control | CM-3, CM-4, CM-5 | Unauthorized config changes, missing CODEOWNERS | WARN |
| 9 | 🧩 Dependencies | SA-12, RA-5, SI-2 | Vulnerable packages, missing lockfiles | WARN |
| 10 | 🌐 API Security | SC-8, AC-3, SI-10 | Unauthenticated endpoints, missing rate limits | WARN |
| 11 | 🔐 Privacy | AR-2, DM-1, IP-1 | PII exposure, missing data classification | WARN |
| 12 | 🔁 Resilience | CP-2, CP-10, SC-5 | Missing retry logic, no circuit breakers | WARN |
| 13 | 🚨 Incident Response | IR-2, IR-4, IR-6 | Missing error handlers, no alerting hooks | WARN |
| 14 | 👁️ Observability | AU-6, SI-4, CA-7 | Missing health checks, no structured logging | WARN |
| 15 | 🧠 Memory Safety | SI-16, SA-11, SA-15 | Buffer overflows, unsafe memory ops | WARN |
| 16 | ⚖️ License Compliance | SA-4, SR-3 | GPL contamination, unlicensed dependencies | WARN |
| 17 | 🤖 AI/ML Security | SA-11, SI-7, AC-3 | Untrusted model sources, prompt injection risk | WARN |
| 18 | 🐳 Container Security | CM-6, AC-6, SC-7 | Root containers, privileged mode, latest tags | WARN |

---

## Configuration Reference (`.controlgate.yml`)

```yaml
baseline: moderate              # low | moderate | high | privacy | li-saas
gov: false                      # true = evaluate against FedRAMP baselines

gates:
  secrets: { enabled: true, action: block }   # block | warn | disabled
  # ... (all 18 gates)

thresholds:
  block_on: [CRITICAL, HIGH]    # Exit 1 — blocks commit/merge
  warn_on:  [MEDIUM]            # Reported, non-blocking
  ignore:   [LOW]               # Suppressed from output

exclusions:
  paths: ["tests/**", "docs/**", "*.md"]
  controls: []                  # Suppress specific NIST control IDs

reporting:
  format: [json, markdown]      # Output formats
  sarif: false                  # Enable SARIF (for GitHub Code Scanning)
  output_dir: .controlgate/reports

full_scan:
  extensions: [.py, .js, .ts, .tf, .yaml, .yml, .json, .sh]
  skip_dirs: [.git, node_modules, .venv, dist, build]
```

---

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Markdown | `--format markdown` | PR comments, terminal output |
| JSON | `--format json` | Dashboards, programmatic consumption |
| SARIF | `--format sarif` | GitHub Code Scanning integration |

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/controlgate.yml
- name: Run ControlGate scan
  run: |
    controlgate scan \\
      --mode pr \\
      --target-branch ${{ github.base_ref || 'main' }} \\
      --format json markdown sarif \\
      --output-dir .controlgate/reports
```

### GitLab CI

```yaml
controlgate:
  image: python:3.12-slim
  script:
    - pip install controlgate
    - controlgate scan --mode pr --target-branch $CI_MERGE_REQUEST_TARGET_BRANCH_NAME --format json markdown
  artifacts:
    paths: [.controlgate/reports/]
```

### Bitbucket Pipelines

```yaml
- step:
    name: ControlGate Security Scan
    image: python:3.12-slim
    script:
      - pip install controlgate
      - controlgate scan --mode pr --target-branch main --format json markdown
    artifacts:
      - .controlgate/reports/**
```

---

## All CLI Options

```bash
controlgate init [--path PATH] [--baseline LEVEL] [--no-docs]
controlgate scan [--mode pre-commit|pr|full] [--path PATH]
                 [--target-branch BRANCH] [--diff-file FILE]
                 [--format json|markdown|sarif] [--output-dir DIR]
                 [--baseline LEVEL] [--gov] [--config FILE]
controlgate update-catalog
controlgate catalog-info
```
"""


def _build_github_workflow() -> str:
    return """\
name: ControlGate Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  controlgate:
    name: 🛡️ ControlGate Compliance Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for diff

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ControlGate
        run: pip install controlgate

      - name: Run ControlGate scan
        id: scan
        run: |
          controlgate scan \\
            --mode pr \\
            --target-branch ${{ github.base_ref || 'main' }} \\
            --format json markdown sarif \\
            --output-dir .controlgate/reports
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .controlgate/reports/verdict.sarif
        continue-on-error: true

      - name: Comment on PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const reportPath = '.controlgate/reports/verdict.md';
            if (fs.existsSync(reportPath)) {
              const body = fs.readFileSync(reportPath, 'utf8');
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: body,
              });
            }

      - name: Enforce gate
        if: steps.scan.outcome == 'failure'
        run: |
          echo "🚫 ControlGate blocked this change due to security findings."
          echo "Review the scan results above and fix the issues before merging."
          exit 1
"""


def _build_gitlab_ci() -> str:
    return """\
# GitLab CI — ControlGate Security Scan
# Add this job to your existing .gitlab-ci.yml or use as a starting point

stages:
  - security

controlgate:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install controlgate
  script:
    - >
      controlgate scan
      --mode pr
      --target-branch ${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-main}
      --format json markdown sarif
      --output-dir .controlgate/reports
  artifacts:
    paths:
      - .controlgate/reports/
    when: always
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


def _build_bitbucket_pipelines() -> str:
    return """\
# Bitbucket Pipelines — ControlGate Security Scan
# Add the controlgate step to your existing bitbucket-pipelines.yml
# or use this as a starting point.

image: python:3.12-slim

pipelines:
  pull-requests:
    '**':
      - step:
          name: 🛡️ ControlGate Security Scan
          script:
            - pip install controlgate
            - >
              controlgate scan
              --mode pr
              --target-branch main
              --format json markdown
              --output-dir .controlgate/reports
          artifacts:
            - .controlgate/reports/**
  branches:
    main:
      - step:
          name: 🛡️ ControlGate Full Scan
          script:
            - pip install controlgate
            - >
              controlgate scan
              --mode full
              --format json markdown
              --output-dir .controlgate/reports
          artifacts:
            - .controlgate/reports/**
"""


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

def _prompt(question: str, default: str = "") -> str:
    """Prompt with an optional default value."""
    if default:
        answer = input(f"  {question} [{default}]: ").strip()
        return answer if answer else default
    return input(f"  {question}: ").strip()


def _prompt_yn(question: str, default: bool = False) -> bool:
    """Yes/no prompt."""
    default_str = "Y/n" if default else "y/N"
    answer = input(f"  {question} [{default_str}]: ").strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def _write_file(path: Path, content: str) -> bool:
    """Write file, prompting if it already exists. Returns True if written."""
    if path.exists():
        if not _prompt_yn(f"{path} already exists. Overwrite?", default=False):
            print(f"  ↳ Skipped: {path}")
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  Creating {path} ... ✅")
    return True


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------

def init_command(args) -> int:
    """Execute the init command — interactive project bootstrap."""
    root = Path(getattr(args, "path", None) or ".").resolve()
    no_docs = getattr(args, "no_docs", False)

    print()
    print("🛡️  ControlGate Init")
    print("─" * 50)

    # Baseline
    default_baseline = getattr(args, "baseline", None) or "moderate"
    baseline = _prompt(
        "Baseline? (low/moderate/high/privacy/li-saas)", default=default_baseline
    )
    if baseline not in ("low", "moderate", "high", "privacy", "li-saas"):
        print(f"  ⚠️  Unknown baseline '{baseline}', defaulting to 'moderate'")
        baseline = "moderate"

    # CI/CD choices
    gen_github = _prompt_yn("Generate GitHub Actions workflow?", default=False)
    gen_gitlab = _prompt_yn("Generate GitLab CI job?", default=False)
    gen_bitbucket = _prompt_yn("Generate Bitbucket Pipelines step?", default=False)

    print("─" * 50)

    # Write files
    _write_file(root / ".controlgate.yml", _build_controlgate_yml(baseline))
    _write_file(root / ".pre-commit-config.yaml", _build_precommit_config())

    if not no_docs:
        _write_file(root / "CONTROLGATE.md", _build_controlgate_md())

    if gen_github:
        _write_file(
            root / ".github" / "workflows" / "controlgate.yml",
            _build_github_workflow(),
        )

    if gen_gitlab:
        _write_file(root / ".gitlab-ci.yml", _build_gitlab_ci())

    if gen_bitbucket:
        _write_file(root / "bitbucket-pipelines.yml", _build_bitbucket_pipelines())

    print("─" * 50)
    print("✅  Done! ControlGate is configured for this project.")
    print()
    print("  Next steps:")
    print("    1. Review .controlgate.yml and adjust gate settings")
    print("    2. pip install pre-commit && pre-commit install")
    print("    3. controlgate scan --mode full   (baseline audit)")
    print()
    return 0
```

### Step 4: Run tests to verify they pass

```bash
pytest tests/test_init_command.py -v
```
Expected: all PASS

### Step 5: Run full suite to catch regressions

```bash
pytest --tb=short -q
```
Expected: all PASS

### Step 6: Commit

```bash
git add src/controlgate/init_command.py tests/test_init_command.py
git commit -m "feat: add init_command with templates for all generated files"
```

---

## Task 5: Wire `init` subcommand into parser and `main()`

**Files:**
- Modify: `src/controlgate/__main__.py`
- Test: `tests/test_cli.py` (extend), `tests/test_init_command.py` (extend)

### Step 1: Write failing tests

Add to `tests/test_cli.py`:

```python
class TestInitCommand:
    def test_parser_has_init_command(self):
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"

    def test_init_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.baseline is None
        assert args.no_docs is False

    def test_init_with_baseline(self):
        parser = build_parser()
        args = parser.parse_args(["init", "--baseline", "high"])
        assert args.baseline == "high"

    def test_init_with_no_docs(self):
        parser = build_parser()
        args = parser.parse_args(["init", "--no-docs"])
        assert args.no_docs is True

    def test_main_init_command(self, tmp_path):
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            with patch("sys.argv", ["controlgate", "init", "--path", str(tmp_path)]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/test_cli.py::TestInitCommand -v
```
Expected: `argument command: invalid choice: 'init'`

### Step 3: Add `init` subcommand to `build_parser()`

After the `catalog-info` subparser block, add:

```python
# init subcommand
init_parser = subparsers.add_parser(
    "init",
    help="Bootstrap ControlGate config files for this project",
)
init_parser.add_argument(
    "--path",
    type=str,
    default=None,
    help="Target directory to initialize (default: current directory)",
)
init_parser.add_argument(
    "--baseline",
    type=str,
    choices=["low", "moderate", "high", "privacy", "li-saas"],
    default=None,
    help="Pre-select the NIST/FedRAMP baseline level",
)
init_parser.add_argument(
    "--no-docs",
    action="store_true",
    default=False,
    help="Skip generating CONTROLGATE.md",
)
```

### Step 4: Wire `init_command` in `main()`

Add import at top of `__main__.py`:
```python
from controlgate.init_command import init_command
```

In `main()`, add after the `catalog-info` branch:
```python
elif args.command == "init":
    sys.exit(init_command(args))
```

### Step 5: Run tests to verify they pass

```bash
pytest tests/test_cli.py::TestInitCommand -v
```
Expected: all PASS

### Step 6: Run full suite

```bash
pytest --tb=short -q
```
Expected: all PASS

### Step 7: Commit

```bash
git add src/controlgate/__main__.py tests/test_cli.py
git commit -m "feat: wire controlgate init subcommand into CLI"
```

---

## Task 6: Update `README.md` and `hooks/github_action.yml`

**Files:**
- Modify: `README.md`
- Modify: `hooks/github_action.yml`

No tests needed (docs only).

### Step 1: Update `README.md`

**a. Quick Start section** — add `--mode full` and `init` examples:

```markdown
## Quick Start

```bash
# Install
pip install controlgate

# Bootstrap project (creates .controlgate.yml, pre-commit hook, CI workflows)
controlgate init

# Full repo audit (first-time scan)
controlgate scan --mode full --format markdown

# Scan staged changes (NIST baseline)
controlgate scan --mode pre-commit --format markdown

# Scan staged changes (FedRAMP baseline)
controlgate scan --gov --baseline moderate --mode pre-commit --format markdown

# Scan PR diff against main
controlgate scan --mode pr --target-branch main --format json markdown
```
```

**b. How It Works section** — update "8 Security Gates" to "18 Security Gates":

```markdown
8 Security Gates scan against 370 non-negotiable NIST controls
```
→
```markdown
18 Security Gates scan against 370 non-negotiable NIST controls
```

**c. Replace "The Eight Security Gates" section** with a full 18-gate table:

```markdown
## The 18 Security Gates

| # | Gate | NIST Families | What It Catches |
|---|------|---------------|-----------------|
| 1 | 🔑 Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys |
| 2 | 🔒 Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, `ssl_verify=False` |
| 3 | 🛡️ IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles |
| 4 | 📦 Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering |
| 5 | 🏗️ IaC | CM-2, CM-6, SC-7 | Public buckets, `0.0.0.0/0` rules, root containers |
| 6 | ✅ Input Validation | SI-10, SI-11 | SQL injection, `eval()`, exposed stack traces |
| 7 | 📋 Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs |
| 8 | 🔄 Change Control | CM-3, CM-4, CM-5 | Unauthorized config changes, missing CODEOWNERS |
| 9 | 🧩 Dependencies | SA-12, RA-5, SI-2 | Vulnerable packages, missing lockfiles |
| 10 | 🌐 API Security | SC-8, AC-3, SI-10 | Unauthenticated endpoints, missing rate limiting |
| 11 | 🔐 Privacy | AR-2, DM-1, IP-1 | PII exposure, missing data classification |
| 12 | 🔁 Resilience | CP-2, CP-10, SC-5 | Missing retry logic, no circuit breakers |
| 13 | 🚨 Incident Response | IR-2, IR-4, IR-6 | Missing error handlers, no alerting integration |
| 14 | 👁️ Observability | AU-6, SI-4, CA-7 | Missing health checks, no structured logging |
| 15 | 🧠 Memory Safety | SI-16, SA-11, SA-15 | Buffer overflows, unsafe memory operations |
| 16 | ⚖️ License Compliance | SA-4, SR-3 | GPL contamination, unlicensed dependencies |
| 17 | 🤖 AI/ML Security | SA-11, SI-7, AC-3 | Untrusted model sources, prompt injection risk |
| 18 | 🐳 Container Security | CM-6, AC-6, SC-7 | Root containers, privileged mode, `latest` tags |
```

**d. Update Configuration section** — replace the 8-gate `.controlgate.yml` example with the full 18-gate version (use output of `_build_controlgate_yml("moderate")` from `init_command.py`).

**e. Update CLI Usage section** — add `init` command and `--mode full`:

```markdown
## CLI Usage

```bash
# Bootstrap project
controlgate init
controlgate init --baseline high --no-docs

# Scan staged changes (pre-commit mode)
controlgate scan --mode pre-commit --format markdown

# Full repository scan
controlgate scan --mode full --format markdown
controlgate scan --mode full --path ./src --format json

# Scan PR diff
controlgate scan --mode pr --target-branch main --format json markdown sarif

# Scan PR diff explicitly against FedRAMP baselines
controlgate scan --gov --baseline high --mode pr --target-branch main --format json markdown sarif

# Scan a saved diff file
controlgate scan --diff-file path/to/diff --format json

# Output reports to directory
controlgate scan --output-dir .controlgate/reports --format json markdown sarif

# Catalog management
controlgate update-catalog
controlgate catalog-info
```
```

**f. Update Test Suite section** — bump "8 Security Gates" → "18 Security Gates".

### Step 2: Update `hooks/github_action.yml`

No functional changes needed — the existing file is already the source of truth and matches the template in `init_command.py`.

### Step 3: Verify README renders correctly

```bash
# Quick sanity check — count gate rows in README
grep -c "| [0-9]" README.md
```
Expected: `18`

### Step 4: Commit

```bash
git add README.md hooks/github_action.yml
git commit -m "docs: update README for 18 gates, full scan mode, and init command"
```

---

## Task 7: Final validation

### Step 1: Run full test suite with coverage

```bash
pytest --tb=short -q
```
Expected: all PASS, no regressions

### Step 2: Smoke test the CLI

```bash
# Verify --mode full is accepted
python -m controlgate scan --mode full --help

# Verify init command is available
python -m controlgate init --help

# Verify build_parser has all commands
python -m controlgate --help
```
Expected: `full` appears in mode choices; `init` appears in command list

### Step 3: Smoke test init in a temp directory

```bash
cd /tmp && mkdir cg-test && cd cg-test
echo "moderate
n
n
n" | python -m controlgate init
ls -la
```
Expected: `.controlgate.yml`, `.pre-commit-config.yaml`, `CONTROLGATE.md` all created

### Step 4: Commit and summarise

```bash
git add -p  # stage any remaining changes
git commit -m "chore: final cleanup and validation"
```
