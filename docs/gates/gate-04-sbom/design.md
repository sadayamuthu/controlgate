# Gate 4 — Supply Chain & SBOM Gate

**gate_id:** `sbom`
**NIST Controls:** SR-3, SR-11, SA-10, SA-11
**Priority:** Medium

---

## Purpose

Reduces supply chain risk by detecting dependency management practices that allow untrusted or unverified software components to enter the build. Unpinned dependency versions permit silent package substitution attacks; missing lockfiles mean the exact set of transitive dependencies is not reproducible; modified CI/CD pipeline files create opportunities to inject malicious build steps; and weakened test coverage thresholds erode the assurance baseline. This gate provides automated visibility into these risks at the point where the manifest or pipeline change is introduced.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Dependency manifest modified without corresponding lockfile update | Without a lockfile update, the resolved dependency set is non-deterministic and may differ between environments | SR-3 |
| Unpinned version specifier `>=` in dependency files | Allows any future version to be resolved; an attacker who compromises a package registry can silently inject malicious code | SR-11 |
| Loose version specifier `~=` | Permits minor-version upgrades that may introduce breaking or malicious changes | SR-11 |
| Wildcard version specifier `*` | Resolves to whatever the latest published version is at install time | SR-11 |
| Version set to `latest` | Equivalent to a wildcard; provides no reproducibility guarantee | SR-11 |
| Caret version range `^` | Allows minor and patch updates; non-deterministic across install runs | SR-11 |
| Build/CI pipeline file modified | Pipeline changes can introduce unauthorized build steps, exfiltrate secrets, or alter artifact signing | SA-10 |
| Test coverage threshold modification | Lowering or removing coverage thresholds weakens the assurance evidence produced by the test suite | SA-11 |
| Test execution skipped or disabled | Disabling tests removes verification of functional and security properties | SA-11 |

---

## Scope

- **Scans:** file paths (for manifest/lockfile cross-check and pipeline file detection) and added lines (for unpinned version patterns and test coverage patterns)
- **File types targeted:** all file types for line scanning; manifest check is basename-based (`package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`); pipeline check uses a filename regex
- **Special detection:** cross-file lockfile check — when a manifest file appears in the diff, the gate checks whether any of its expected lockfiles also appear in the same diff

---

## Known Limitations

- Does not scan deleted or unmodified lines
- Lockfile cross-check is per-commit: if the manifest and lockfile are updated in separate commits, this gate will fire on the manifest commit
- Unpinned version patterns apply to all added lines in all files, not just dependency manifest files, which may produce false positives in documentation or configuration files that mention version ranges in a non-dependency context
- Does not validate that the lockfile content is consistent with the manifest (only that a lockfile was also modified)
- Pipeline file detection is filename-based; custom CI systems with non-standard filenames will not be detected

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SR-3 | Supply Chain Controls and Processes | Detects manifest changes without corresponding lockfile updates, ensuring the dependency supply chain remains auditable and reproducible |
| SR-11 | Component Authenticity | Detects unpinned version specifiers that allow arbitrary component versions to be resolved, undermining component integrity |
| SA-10 | Developer Configuration Management | Detects modifications to build/CI pipeline files that require security review to prevent unauthorized changes to the build process |
| SA-11 | Developer Testing and Evaluation | Detects modifications that lower test coverage thresholds or disable test execution, weakening development-time security assurance |
