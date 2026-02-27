# Gate 4 — Supply Chain & SBOM Gate: Implementation Reference

**Source file:** `src/controlgate/gates/sbom_gate.py`
**Test file:** none
**Class:** `SBOMGate`
**gate_id:** `sbom`
**mapped_control_ids:** `["SR-3", "SR-11", "SA-10", "SA-11"]`

---

## Scan Method

`scan()` performs four distinct checks for each `diff_file`:

1. **Manifest/lockfile cross-check** — if the file's basename is a key in `_MANIFEST_LOCKFILE_MAP`, the gate checks whether any of the expected lockfile basenames appear in the set of all modified file basenames in the diff. If no lockfile is present, fires one SR-3 finding at line 1.
2. **Pipeline file detection** — if the file path matches `_PIPELINE_FILES` regex, fires one SA-10 finding at line 1.
3. **Unpinned version patterns** — for each added line, runs all `_UNPINNED_PATTERNS` (5 patterns). Each match fires one SR-11 finding.
4. **Test coverage weakening** — for each added line, runs all `_TEST_COVERAGE_PATTERNS` (2 patterns). Each match fires one SA-11 finding.

Checks 3 and 4 run on all files regardless of filename.

---

## Patterns

### Unpinned Version Patterns (`_UNPINNED_PATTERNS`) — control SR-11

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `>=` | Unpinned version specifier >= | SR-11 | Pin dependencies to exact versions for reproducible builds |
| 2 | `~=` | Loose version specifier ~= | SR-11 | Pin dependencies to exact versions for reproducible builds |
| 3 | `:\s*["\']?\*["\']?` | Wildcard version specifier * | SR-11 | Pin dependencies to exact versions for reproducible builds |
| 4 | `:\s*["\']?latest["\']?` | Version set to 'latest' | SR-11 | Pin dependencies to exact versions for reproducible builds |
| 5 | `:\s*["\']?\^` | Caret version range (allows minor/patch changes) | SR-11 | Pin dependencies to exact versions for reproducible builds |

### Test Coverage Weakening Patterns (`_TEST_COVERAGE_PATTERNS`) — control SA-11

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 6 | `(?i)(?:coverage\|cov).*(?:fail.?under\|threshold\|minimum)\s*[:=]\s*\d+` | Test coverage threshold modification detected | SA-11 | Maintain or increase test coverage thresholds |
| 7 | `(?i)skip.?test\|no.?test\|test.*disabled` | Test execution may be skipped or disabled | SA-11 | Maintain or increase test coverage thresholds |

---

## Special Detection Logic

### Manifest / Lockfile Cross-Check

The gate collects the set of all file basenames in the diff at the start of `scan()`:

```python
basenames = {df.path.split("/")[-1] for df in diff_files}
```

For each `diff_file` whose basename appears as a key in `_MANIFEST_LOCKFILE_MAP`, it checks:

```python
has_lockfile_update = any(lock_name in basenames for lock_name in expected_locks)
```

The manifest-to-lockfile mapping is:

| Manifest | Accepted lockfiles |
|---|---|
| `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| `requirements.txt` | `requirements.lock`, `Pipfile.lock`, `poetry.lock` |
| `Pipfile` | `Pipfile.lock` |
| `pyproject.toml` | `poetry.lock`, `uv.lock`, `pdm.lock` |
| `go.mod` | `go.sum` |
| `Cargo.toml` | `Cargo.lock` |
| `Gemfile` | `Gemfile.lock` |
| `composer.json` | `composer.lock` |

If no matching lockfile basename is present in the diff, an SR-3 finding is emitted for the manifest file at line 1. The finding evidence message includes the list of expected lockfile names.

### Pipeline File Detection

The gate checks each file path against the `_PIPELINE_FILES` regex:

```
(?i)(?:\.github/workflows/.*\.ya?ml|Jenkinsfile|\.gitlab-ci\.ya?ml|
azure-pipelines\.ya?ml|\.circleci/config\.yml|Dockerfile|docker-compose.*\.ya?ml|
Makefile|\.travis\.ya?ml|cloudbuild\.ya?ml)
```

Any match fires one SA-10 finding at line 1, regardless of line content.

---

## Known Debt / Deferred Patterns

- No test file exists for this gate; all behaviour is untested by automated tests
- The `_UNPINNED_PATTERNS` apply to all added lines in the diff, not exclusively to dependency manifest files, producing false positives in unrelated files that mention version ranges (e.g., documentation, comments)
- There is no detection for dependency confusion attacks (private package names that could be shadowed by public registry packages)
- There is no integrity verification check (e.g., hash pinning in `requirements.txt` via `--hash=`)

---

## Test Coverage

No test file exists for `SBOMGate`. This gate has no automated test coverage.
