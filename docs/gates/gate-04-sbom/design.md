# Gate 4 — Supply Chain & SBOM Gate

**gate_id:** `sbom`
**NIST Controls:** SR-3, SR-11, SA-10, SA-11
**Priority:** 🟡 Medium

---

## Purpose

Prevents unreviewed supply chain changes from entering the build by detecting three categories of risk: unpinned dependency versions that allow silent package substitution across install runs, CI/CD pipeline file modifications that create opportunities for unauthorized build-step injection, and dependency manifest changes that are not accompanied by a corresponding lockfile update (manifest-without-lockfile). Together these controls ensure that the resolved software component set remains deterministic, auditable, and reviewed before it reaches downstream environments.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Dependency manifest modified without corresponding lockfile update | Without a lockfile update the resolved dependency set is non-deterministic; transitive dependencies may silently change between environments and install runs | SR-3 |
| Build/CI pipeline file modified | Pipeline changes can inject malicious build steps, exfiltrate secrets, alter artifact signing, or disable security checks without obvious code review signals | SA-10 |
| Unpinned version specifier in added lines (`>=`, `~=`, `*`, `latest`, `^`) | Unpinned specifiers allow any future version to be resolved at install time; a compromised package registry can silently deliver a malicious version that satisfies the constraint | SR-11 |
| Test coverage threshold lowered or test execution disabled | Weakening coverage thresholds or skipping tests removes verification of functional and security properties, eroding the assurance evidence produced by the test suite | SA-11 |

---

## Scope

- **Lockfile cross-check:** cross-file analysis — when a manifest file appears in the diff, the gate inspects the full set of modified file basenames across the entire diff to determine whether at least one accepted lockfile was also updated
- **Pipeline file detection:** per-file path check against a filename regex; fires once per matching file regardless of line content
- **Unpinned version patterns:** all added lines in every file in the diff are scanned; checks are not restricted to dependency manifest file types
- **Test coverage weakening patterns:** all added lines in every file in the diff are scanned; checks are not restricted to configuration file types

---

## Known Limitations

- The lockfile cross-check uses basename matching (`path.split("/")[-1]`), so renaming or moving a lockfile to a non-standard path fools the check — only the filename portion is compared, not the full path
- Does not scan binary lockfiles (e.g., compiled or encrypted lock formats); only text-based lockfile names are recognised
- Cannot detect transitive dependency vulnerabilities — the gate confirms a lockfile was updated alongside the manifest but does not inspect or validate the lockfile content for known-vulnerable versions
- Unpinned version patterns fire on any added line in any file, not exclusively in dependency manifest files, which may produce false positives in documentation, comments, or configuration files that mention version ranges in a non-dependency context
- Pipeline file detection is filename-based; custom CI systems that use non-standard filenames will not be flagged

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SR-3 | Supply Chain Controls and Processes | Detects dependency manifest changes that are not accompanied by a lockfile update, ensuring the resolved dependency supply chain remains auditable and reproducible across environments |
| SR-11 | Component Authenticity | Detects unpinned version specifiers (`>=`, `~=`, `*`, `latest`, `^`) that allow arbitrary component versions to be resolved at install time, undermining the integrity and verifiability of software components |
| SA-10 | Developer Configuration Management | Detects modifications to build and CI/CD pipeline files, flagging changes that require security review to prevent unauthorized alterations to the build process or artifact pipeline |
| SA-11 | Developer Testing and Evaluation | Detects changes that lower test coverage thresholds or disable test execution, preserving the development-time assurance evidence required to validate functional and security properties |
