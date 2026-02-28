# Auto Version Bump Pre-Commit Hook — Design

**Date:** 2026-02-28
**Status:** Approved

## Problem

The CI pipeline enforces a version bump at PR time, but developers only discover the missing bump when the PR check fails. The fix requires an extra commit just to update the version. Moving version management to commit time eliminates this friction.

## Goal

Add a pre-commit hook that automatically bumps the minor version in `pyproject.toml` when the current branch version matches the `main` branch version, stages the change, and includes it in the commit being made.

## Approach

Use a local pre-commit hook (`hooks/bump_version.py`) that compares versions using `git show origin/main:pyproject.toml` — the cached remote ref. No network call is needed after the initial fetch, so it works offline and adds negligible latency.

## Components

### `hooks/bump_version.py`

Self-contained Python script (no third-party deps):

1. Read current version from `pyproject.toml` via regex on `version = "X.Y.Z"`
2. Read main-branch version via `git show origin/main:pyproject.toml`
3. If versions match → bump minor (e.g. `0.1.7 → 0.2.0`, patch resets to 0), write file, `git add pyproject.toml`, print notice
4. If versions differ → exit 0 (already bumped, nothing to do)
5. If `origin/main` unavailable → exit 0 with warning (don't block offline commits)

### `.pre-commit-config.yaml` addition

New `local` repo entry:

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

## Bump Rule

| Before | After |
|--------|-------|
| `0.1.7` | `0.2.0` |
| `0.2.0` | `0.3.0` |
| `1.5.3` | `1.6.0` |

Minor segment incremented, patch reset to `0`, major unchanged.

## Error Handling

| Condition | Behaviour |
|-----------|-----------|
| `origin/main` not reachable | Warn, exit 0 (non-blocking) |
| `pyproject.toml` missing version line | Exit 1 with clear error |
| `git add` fails | Exit 1 with error |
| Versions already differ | Exit 0 silently |

## Testing

- Unit tests in `tests/test_bump_version.py` using `tmp_path` and mocked `subprocess`
- Cases: same version (bumps), different version (skips), origin unavailable (warns, passes), malformed version (errors)

## Out of Scope

- Major version bumps (manual only)
- Configurable bump type (always minor)
- CHANGELOG updates
