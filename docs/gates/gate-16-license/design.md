# Gate 16 — License Compliance Gate

**gate_id:** `license`
**NIST Controls:** SA-4, SR-3
**Priority:** Medium

---

## Purpose

Guards against copyleft-licensed dependencies and source files entering a proprietary codebase without deliberate review. Copyleft licenses such as GPL, AGPL, SSPL, and LGPL carry reciprocal obligations: any software that links against or distributes a copyleft-licensed component may itself be required to be released under the same license. By scanning dependency manifests for copyleft license keywords at diff time, the gate intercepts the moment a developer adds a new dependency whose license could force open-sourcing of the entire codebase. A second, complementary check flags SPDX copyleft license identifiers in any file, catching cases where copyleft-licensed source code is copied or vendored directly rather than declared as a dependency.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Copyleft license keyword (GPL, AGPL, SSPL, LGPL, or GNU General/Affero/Lesser) in a dependency manifest file | Adding a copyleft-licensed package to a manifest is the primary vector through which reciprocal license obligations enter a proprietary codebase; catching it at diff time allows legal review before the dependency is merged | SA-4 |
| SPDX copyleft license identifier (`SPDX-License-Identifier:` followed by GPL, AGPL, SSPL, LGPL, EUPL, OSL, or CDDL) in any source file | An SPDX identifier in a source file is a precise, machine-readable declaration of the file's license; its presence in any added line signals that copyleft-licensed code may have been vendored or copied into the codebase | SR-3 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** copyleft keyword detection scoped to manifest files only; SPDX identifier check applies to all files
- **Manifest files scanned:** requirements*.txt, package.json, go.mod, Cargo.toml, Gemfile, composer.json, setup.cfg, pyproject.toml

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- Copyleft keyword detection is limited to manifest files — copyleft comments in source files are not flagged unless the line also contains a formal SPDX identifier
- Does not perform recursive dependency scanning; only direct additions to manifests are inspected
- The keyword pattern matches the literal strings GPL, AGPL, SSPL, LGPL, and GNU General/Affero/Lesser; licenses referred to by alternative abbreviations, full names without these strings, or SPDX expressions using `AND`/`OR` operators that include a copyleft component are not detected by the keyword check
- The SPDX check does not parse compound SPDX expressions; a combined expression such as `MIT AND GPL-2.0-only` is flagged, but only because the raw string contains "GPL"

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SA-4 | Acquisition Process | Detects copyleft license keywords in dependency manifests — the primary point at which third-party software is acquired — ensuring that legal obligations imposed by copyleft licenses are identified and reviewed before the dependency enters the codebase |
| SR-3 | Supply Chain Controls and Plans | Detects formal SPDX copyleft license identifiers in any added source file, covering the supply chain risk that arises when copyleft-licensed code is vendored, copied, or otherwise incorporated directly rather than declared through a package manager |
