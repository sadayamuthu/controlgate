# Gate 16 — License Compliance Gate: Implementation Reference

**Source file:** `src/controlgate/gates/license_gate.py`
**Test file:** `tests/test_gates/test_license_gate.py`
**Class:** `LicenseGate`
**gate_id:** `license`
**mapped_control_ids:** `["SA-4", "SR-3"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the provided list. Before entering the per-line loop it evaluates `_MANIFEST_FILES.search(diff_file.path)` once per file and stores the boolean result as `is_manifest`. It then iterates every added line via `diff_file.all_added_lines`, which yields `(line_no, line)` tuples. For each added line two independent checks are performed:

1. **Manifest copyleft keyword check (SA-4):** if `is_manifest` is true and `_COPYLEFT_PATTERN.search(line)` matches, `_make_finding()` is called with control ID `SA-4`, the file path, line number, a fixed description, the first 120 characters of the stripped line as evidence, and a remediation string.
2. **SPDX copyleft identifier check (SR-3):** regardless of file type, if `_SPDX_COPYLEFT.search(line)` matches, `_make_finding()` is called with control ID `SR-3` and its corresponding description and remediation.

Both checks run independently on every added line; a single line can produce two findings if it is in a manifest file and contains both a copyleft keyword and an SPDX copyleft identifier. All findings are collected into a flat list and returned.

---

## Patterns

Note: This gate does NOT use the standard `_PATTERNS` tuple list. Instead it uses three module-level compiled patterns used directly in `scan()`.

| Pattern | Regex | File Scope | Emits | Description |
|---|---|---|---|---|
| `_COPYLEFT_PATTERN` | `(?i)\b(?:GPL\|AGPL\|SSPL\|LGPL\|GNU\s+(?:General\|Affero\|Lesser))\b` | Manifest files only | SA-4 | Matches copyleft license keywords and GNU license family names as whole words, case-insensitively |
| `_MANIFEST_FILES` | `(?i)(?:requirements.*\.txt\|package\.json\|go\.mod\|Cargo\.toml\|Gemfile\|composer\.json\|setup\.cfg\|pyproject\.toml)$` | (path filter, not a detection pattern) | — | Identifies dependency manifest files by path suffix; used to gate the `_COPYLEFT_PATTERN` check |
| `_SPDX_COPYLEFT` | `SPDX-License-Identifier:\s*(?:GPL\|AGPL\|SSPL\|LGPL\|EUPL\|OSL\|CDDL)` | All files | SR-3 | Matches formal SPDX license identifier declarations whose value begins with a recognised copyleft license abbreviation |

---

## Special Detection Logic

### Manifest File Filter

At the start of the per-file loop, the gate evaluates whether the file is a dependency manifest:

```python
is_manifest = bool(_MANIFEST_FILES.search(diff_file.path))
```

This boolean is computed once per file and reused for every line in that file. The pattern matches the path's suffix (anchored with `$`) against a fixed set of known manifest file names: `requirements*.txt`, `package.json`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`, `setup.cfg`, and `pyproject.toml`. The match is case-insensitive.

Inside the per-line loop, the two detection checks branch on this flag:

- The **copyleft keyword check** (`_COPYLEFT_PATTERN`) is executed only when `is_manifest` is true. This scoping decision is deliberate: copyleft license keywords such as "GPL" appear legitimately in documentation, changelog entries, comment blocks, and test fixtures throughout source code. Restricting the keyword check to manifest files eliminates the majority of false positives while still catching the highest-risk scenario — a developer declaring a copyleft-licensed package as a direct dependency.
- The **SPDX identifier check** (`_SPDX_COPYLEFT`) is executed unconditionally for all added lines in all files. SPDX identifiers are formal, machine-readable declarations specifically intended to assert a file's license; their presence is always significant regardless of file type, and false positives are rare.

The result is a two-tier detection posture: broad but low-noise keyword detection anchored to manifests, and universal SPDX detection anchored to the formal licensing convention.

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_gpl_in_requirements` | A diff adding a line containing "GPL" in a `requirements.txt` file triggers at least one finding with control ID SA-4 |
| `test_detects_agpl_in_package_json` | A diff adding a line containing "AGPL" in a `package.json` file triggers at least one finding with control ID SA-4 |
| `test_detects_spdx_gpl_in_source` | A diff adding a line containing `SPDX-License-Identifier: GPL` in a non-manifest source file triggers at least one finding with control ID SR-3 |
| `test_mit_license_no_findings` | A diff adding lines that reference the MIT license (a permissive license) in both a manifest and a source file produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "license"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"SA-4", "SR-3"}` |
