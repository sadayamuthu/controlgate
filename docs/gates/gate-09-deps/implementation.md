# Gate 9 — Dependency Vulnerability Gate: Implementation Reference

**Source file:** `src/controlgate/gates/deps_gate.py`
**Test file:** `tests/test_gates/test_deps_gate.py`
**Class:** `DepsGate`
**gate_id:** `deps`
**mapped_control_ids:** `["RA-5", "SI-2", "SA-12"]`

---

## Scan Method

`scan()` iterates every `DiffFile` and, for each added line (`diff_file.all_added_lines`), runs a single loop over `_PATTERNS` — a module-level list of 5-tuples `(pattern, description, control_id, remediation)`. Every pattern is evaluated against every added line using `pattern.search(line)`; a matching line emits one finding via `self._make_finding()`. No file-type filter is applied; all file extensions are checked. A single line can produce multiple findings if it matches more than one pattern.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?:pip\|pip3\|npm\|yarn\|gem)\b.*--no-verify\|--no-verify.*(?:pip\|pip3\|npm\|yarn\|gem)\b` | Package integrity verification bypassed with --no-verify | SA-12 | Remove --no-verify to ensure package checksums are validated |
| 2 | `--ignore-scripts` | npm --ignore-scripts bypasses postinstall security hooks | SA-12 | Audit dependencies manually before using --ignore-scripts; prefer a scanned internal registry |
| 3 | `http://[^\s]*(?:pypi\|npmjs\|rubygems\|packagist\|pkg\.go\.dev\|registry\.)` | Insecure HTTP URL used for package registry — man-in-the-middle risk | SI-2 | Use HTTPS for all package registry URLs |
| 4 | `pip3?\s+install\s+(?!-r\s)[A-Za-z0-9][^\n]*(?:>=\|<=\|~=\|!=\|(?<![=!<>])>(?!=)\|(?<![=!<>])<(?!=))` | pip install with range version specifier — use == for reproducible installs | RA-5 | Pin to exact versions (pip install package==1.2.3) for reproducibility |
| 5 | `pip\s+install\s+(?!-r\s)(?:[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s+(?![^\s]*==)[A-Za-z0-9][A-Za-z0-9_.-]*)*\s*$` | pip install without pinned version — dependency may resolve to a vulnerable release | RA-5 | Pin all dependencies to exact versions (pip install package==1.2.3) or use a lockfile |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_no_verify` | `pip install --no-verify requests` produces at least one finding whose description contains "no-verify" or "integrity" (pattern 1) |
| `test_detects_ignore_scripts` | `npm install --ignore-scripts` produces at least one finding (pattern 2) |
| `test_detects_http_registry` | `registry=http://registry.npmjs.org/` produces at least one finding whose description contains "http" (pattern 3) |
| `test_detects_unpinned_pip_install` | `pip install requests flask` (no version pins) produces at least one finding (pattern 5) |
| `test_pinned_install_no_findings` | `pip install requests==2.31.0 flask==3.0.0` (exact pins) produces zero findings |
| `test_git_no_verify_not_flagged` | `git commit --no-verify -m "release"` produces zero findings, confirming the pattern is scoped to package managers only |
| `test_detects_range_specifier` | `pip install requests>=2.0.0` produces at least one finding (pattern 4) |
| `test_findings_have_gate_id` | Every finding produced by the `--no-verify` diff has `gate == "deps"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the `--no-verify` diff has a `control_id` in `{"RA-5", "SI-2", "SA-12"}` |
