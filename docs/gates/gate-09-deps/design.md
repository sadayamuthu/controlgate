# Gate 9 — Dependency Vulnerability Gate

**gate_id:** `deps`
**NIST Controls:** RA-5, SI-2, SA-12
**Priority:** 🟡 Medium

---

## Purpose

Gate 9 addresses the dependency supply chain as an attack surface by detecting hygiene violations that allow vulnerable or tampered packages to enter the build. Unpinned dependencies can resolve to a newer, malicious, or vulnerable release at install time; integrity verification flags like `--no-verify` and `--ignore-scripts` disable the checksum and hook mechanisms that package managers use to validate downloaded content; and insecure HTTP registry URLs expose package download traffic to man-in-the-middle substitution. Together these weaknesses undermine the assumption that the code built is the code reviewed, creating a gap between the declared dependency graph and the software that actually executes in production.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Package manager invoked with `--no-verify` (`pip`, `pip3`, `npm`, `yarn`, `gem`) | Disabling checksum verification allows a tampered or malicious package to be installed silently | SA-12 |
| `npm install --ignore-scripts` | Bypassing postinstall hooks removes a class of integrity checks; auditing is required as a substitute | SA-12 |
| Insecure HTTP URL for a package registry (`pypi`, `npmjs`, `rubygems`, `packagist`, `pkg.go.dev`, `registry.*`) | HTTP exposes package downloads to man-in-the-middle substitution; an attacker on the network can silently replace a package | SI-2 |
| `pip install` with a range version specifier (`>=`, `<=`, `~=`, `!=`, `>`, `<`) | Range specifiers allow the resolver to select a newer release that may introduce a vulnerability not present in the tested version | RA-5 |
| `pip install` of a package without any pinned version (`==`) | Without an exact version pin the resolver may silently upgrade to a vulnerable release | RA-5 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files
- **Special detection:** none

---

## Known Limitations

- Does not scan deleted/removed lines
- Does not perform cross-file analysis
- Does not inspect `requirements.txt`, `package.json`, `Gemfile`, or other manifest files for unpinned versions — only inline `pip install` command invocations in diff lines are checked
- Range-specifier and unpinned-version detection is limited to `pip`/`pip3`; equivalent patterns for `npm`, `yarn`, `gem`, or `go get` are not covered
- The `--no-verify` pattern requires the flag and the package manager name to appear on the same line; multi-line shell commands may evade detection
- `git commit --no-verify` and other non-package-manager uses of `--no-verify` are intentionally excluded by the pattern, but the exclusion is name-based and may not cover every non-package-manager tool that uses the flag

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| RA-5 | Vulnerability Monitoring and Scanning | Detects `pip install` commands that use range or unpinned version specifiers, which prevent reproducible builds and allow vulnerable package versions to be silently introduced |
| SI-2 | Flaw Remediation | Detects insecure HTTP URLs used to reach package registries, where a known vulnerability in the transport layer could allow a patched package to be substituted with a vulnerable one |
| SA-12 | Supply Chain Protection | Detects use of `--no-verify` and `--ignore-scripts` flags that bypass the integrity and hook mechanisms package managers provide to validate the provenance and safety of downloaded packages |
