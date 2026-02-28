# Gate 4 — Supply Chain & SBOM Gate: Implementation Reference

**Source file:** `src/controlgate/gates/sbom_gate.py`
**Test file:** `tests/test_gates/test_sbom_gate.py`
**Class:** `SBOMGate`
**gate_id:** `sbom`
**mapped_control_ids:** `["SR-3", "SR-11", "SA-10", "SA-11"]`

---

## Scan Method

`scan()` operates in three phases that execute for every `diff_file` in the input list:

**Phase 1 — Cross-file lockfile check (SR-3)**
Before iterating files, `scan()` builds a set of all file basenames present in the diff:

```python
basenames = {df.path.split("/")[-1] for df in diff_files}
```

For each `diff_file` whose basename is a key in `_MANIFEST_LOCKFILE_MAP`, the gate checks whether any of the expected lockfile basenames appear in `basenames`. If none match, one SR-3 finding is emitted at line 1 of the manifest file. This check fires once per manifest file per diff, not per added line.

**Phase 2 — Pipeline file detection (SA-10)**
For each `diff_file`, the gate tests `diff_file.path` against the `_PIPELINE_FILES` regex. Any match fires one SA-10 finding at line 1, regardless of the file's line content. The check is path-based only.

**Phase 3 — Added-line pattern scan (SR-11 and SA-11)**
For each added line (`line_no`, `line`) in `diff_file.all_added_lines`, the gate runs two independent pattern loops:

- All five `_UNPINNED_PATTERNS` are tested against the line; each match fires one SR-11 finding.
- Both `_TEST_COVERAGE_PATTERNS` are tested against the line; each match fires one SA-11 finding.

Phases 2 and 3 run on every file in the diff regardless of filename. A single file can produce findings from both phases simultaneously (e.g., a GitHub Actions workflow that also contains a version specifier).

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

The gate collects the set of all file basenames present in the diff at the start of `scan()`:

```python
basenames = {df.path.split("/")[-1] for df in diff_files}
```

For each `diff_file` whose basename appears as a key in `_MANIFEST_LOCKFILE_MAP`, the gate evaluates:

```python
has_lockfile_update = any(lock_name in basenames for lock_name in expected_locks)
```

Matching is basename-only. If the manifest file is `services/backend/package.json`, only the string `"package.json"` is looked up in `_MANIFEST_LOCKFILE_MAP`; similarly, only the basenames of potential lockfiles are checked against `basenames`. A lockfile at `services/backend/package-lock.json` satisfies the check because its basename `"package-lock.json"` will be present in `basenames`.

The manifest-to-lockfile mapping used by `_MANIFEST_LOCKFILE_MAP` is:

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

If no matching lockfile basename is present in the diff, one SR-3 finding is emitted for the manifest file at line 1. The finding's `evidence` field lists all accepted lockfile names so the developer knows which files to update.

### Pipeline File Detection

The gate tests each file's path against the module-level `_PIPELINE_FILES` compiled regex:

```
(?i)(?:\.github/workflows/.*\.ya?ml|Jenkinsfile|\.gitlab-ci\.ya?ml|
azure-pipelines\.ya?ml|\.circleci/config\.yml|Dockerfile|docker-compose.*\.ya?ml|
Makefile|\.travis\.ya?ml|cloudbuild\.ya?ml)
```

The regex is case-insensitive (`(?i)`) and matches common CI/CD and build system filenames. Any file whose path matches fires one SA-10 finding at line 1. The finding description is fixed: `"Build/CI pipeline file modified — requires security review"`.

---

## Test Coverage

The `SBOMGate` is tested within `tests/test_coverage_gaps.py` under the `TestSBOMGate` class.

| Test | What It Verifies |
|---|---|
| `test_detects_unpinned_deps` | A `requirements.txt` diff containing `flask>=2.0` and `boto3~=1.26` produces at least one finding with `control_id == "SR-11"` |
| `test_detects_manifest_without_lockfile` | A diff that modifies `requirements.txt` without updating any accepted lockfile produces at least one finding with `control_id == "SR-3"` |
| `test_detects_pipeline_change` | A diff that modifies `.github/workflows/ci.yml` produces at least one finding with `control_id == "SA-10"` |
| `test_detects_coverage_weakening` | A diff adding `cov_fail_under = 50` to `setup.cfg` produces at least one finding with `control_id == "SA-11"` |
| `test_detects_skip_tests` | A diff adding `skip_tests = True` to `config.py` produces at least one finding with `control_id == "SA-11"` |
