# Design: Full Scan Mode & Init Command

**Date:** 2026-02-27
**Status:** Approved
**Branch:** develop

---

## Overview

Two new features:

1. **`controlgate scan --mode full`** — scan the entire project directory instead of just staged changes or a PR diff.
2. **`controlgate init`** — interactive bootstrap command that creates `.controlgate.yml`, `.pre-commit-config.yaml`, CI/CD workflow files, and a `CONTROLGATE.md` usage guide.

---

## Feature 1: Full Scan Mode

### Motivation

The existing scan modes (`pre-commit`, `pr`) only surface findings in changed lines. Teams onboarding ControlGate to an existing codebase need a one-shot full-repo audit to establish a baseline before enforcing gate checks on every commit.

### Approach: Synthetic DiffFile

Walk the project directory and create `DiffFile` objects where each file's entire content is a single hunk with all lines as `added_lines`. The engine and all 18 gates run unchanged — they already operate on `added_lines` as the "lines to scan".

```
for each file in project directory:
    diff_file = DiffFile(path=file)
    all_lines = file.read_text().splitlines()
    diff_file.hunks = [DiffHunk(
        start_line=1,
        line_count=len(all_lines),
        added_lines=list(enumerate(all_lines, start=1))
    )]

engine.scan(diff_files)  # unchanged
```

### CLI Change

`--mode` gains a third choice: `full`.

```bash
controlgate scan --mode full --format markdown
controlgate scan --mode full --baseline high --output-dir .controlgate/reports
```

No `--target-branch` or `--diff-file` needed for full mode.

### File Discovery: `_get_full_files()`

New function in `__main__.py`:

1. Try `git ls-files` first (respects `.gitignore` automatically) — falls back to `Path.rglob("*")` if not in a git repo.
2. Apply `config.excluded_paths` glob patterns (existing mechanism).
3. Filter by a configurable extension allowlist (from `full_scan.extensions` config key).
4. Skip binary files via `_is_binary()` heuristic (null-byte check on first 8 KB).

### Config Extension: `full_scan` Section

```yaml
full_scan:
  extensions:
    - .py
    - .js
    - .ts
    - .go
    - .java
    - .rb
    - .tf
    - .yaml
    - .yml
    - .json
    - .sh
    - .env
    - .toml
    - .ini
    - .cfg
  skip_dirs:
    - .git
    - node_modules
    - .venv
    - venv
    - __pycache__
    - dist
    - build
    - .tox
    - .mypy_cache
    - .ruff_cache
    - .pytest_cache
```

`ControlGateConfig` gains two new fields: `full_scan_extensions` and `full_scan_skip_dirs`.

### Output Difference

Full-mode reports label themselves as `"mode": "full"` in JSON output. The markdown report header notes "Full Repository Scan" vs "Pre-Commit Scan" / "PR Scan".

---

## Feature 2: `controlgate init`

### Motivation

New users need a zero-friction path to set up ControlGate. Running one command should produce a complete, working configuration.

### CLI

```bash
controlgate init [--path PATH] [--baseline low|moderate|high|privacy|li-saas] [--no-docs]
```

- `--path`: target directory (default: current directory)
- `--baseline`: pre-select baseline without prompting
- `--no-docs`: skip CONTROLGATE.md generation

### Interactive Flow

```
$ controlgate init

🛡️  ControlGate Init
───────────────────────────────────────────
Baseline? [moderate]: high
Generate GitHub Actions workflow? [y/N]: y
Generate GitLab CI job? [y/N]: n
Generate Bitbucket Pipelines step? [y/N]: n
───────────────────────────────────────────
Creating .controlgate.yml ... ✅
Creating .pre-commit-config.yaml ... ✅
Creating CONTROLGATE.md ... ✅
Creating .github/workflows/controlgate.yml ... ✅
───────────────────────────────────────────
✅ Done! ControlGate is configured for this project.

Next steps:
  1. Review .controlgate.yml and adjust gate settings
  2. Run: pip install pre-commit && pre-commit install
  3. Run: controlgate scan --mode full  (baseline audit)
```

When a file already exists:
```
  .controlgate.yml already exists. Overwrite? [y/N]: n
  ↳ Skipped.
```

### Files Generated

| File | Description |
|------|-------------|
| `.controlgate.yml` | Full config with all 18 gates, inline comments |
| `.pre-commit-config.yaml` | pre-commit hook for pre-commit and full scan modes |
| `CONTROLGATE.md` | Usage guide: all 18 gates, CLI reference, config reference |
| `.github/workflows/controlgate.yml` | GitHub Actions PR scan + SARIF upload (optional) |
| `.gitlab-ci.yml` | GitLab CI job appended/created (optional) |
| `bitbucket-pipelines.yml` | Bitbucket Pipelines step appended/created (optional) |

### Template Strategy

Templates are inline strings inside `src/controlgate/init_command.py`. This keeps the package self-contained with no additional data files to distribute.

### `.controlgate.yml` Template

Full config with all 18 gates listed with inline comments explaining each gate and default action. Baseline is interpolated from user input.

### `.pre-commit-config.yaml` Template

```yaml
repos:
  - repo: local
    hooks:
      - id: controlgate
        name: ControlGate Security Scan
        entry: python -m controlgate scan --mode pre-commit --format markdown
        language: python
        always_run: true
```

### GitHub Actions Template

Extends the existing `hooks/github_action.yml` with an added full-scan option:
- Trigger: `pull_request`, `push` to main
- Steps: checkout, setup-python, install, scan (pr mode), SARIF upload, PR comment, enforce gate

### GitLab CI Template / Merge Strategy

- If `.gitlab-ci.yml` exists: read it, append the `controlgate` job block
- If it doesn't exist: create a minimal file with just the controlgate job

### Bitbucket Pipelines Strategy

- If `bitbucket-pipelines.yml` exists: append a `controlgate` step to the default pipeline
- If it doesn't exist: create a minimal pipelines file

### CONTROLGATE.md Content

1. **Overview** — what ControlGate is
2. **Quick Start** — install, init, first scan
3. **Scan Modes** — pre-commit, pr, full (with examples)
4. **All 18 Security Gates** — table with gate name, NIST controls, what it catches, default action
5. **Configuration Reference** — every key in `.controlgate.yml` explained
6. **CI/CD Integration** — GitHub, GitLab, Bitbucket setup notes
7. **Output Formats** — markdown, json, sarif

---

## Implementation Plan Summary

### Files to Create
- `src/controlgate/init_command.py` — init command implementation + all templates

### Files to Modify
- `src/controlgate/__main__.py` — add `full` mode to scan, add `init` subcommand, wire up `init_command`
- `src/controlgate/config.py` — add `full_scan_extensions` and `full_scan_skip_dirs` fields + defaults
- `README.md` — update gates table (8 → 18), update `.controlgate.yml` example, add `--mode full` and `init` to CLI usage
- `hooks/github_action.yml` — minor: add full-scan step (optional, used as template source)

### Files to Create (Tests)
- `tests/test_full_scan.py` — test `_get_full_files()`, synthetic DiffFile construction, engine integration
- `tests/test_init_command.py` — test file generation, overwrite prompts, template rendering

---

## Non-Goals

- No AST-level full-file analysis (gates remain regex/pattern-based)
- No `--watch` mode for continuous scanning
- No parallel gate execution (future optimization)
- No auto-fix / remediation in `init` output
