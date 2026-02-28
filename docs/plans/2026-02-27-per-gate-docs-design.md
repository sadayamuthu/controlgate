# Per-Gate Documentation Design

**Date:** 2026-02-27
**Status:** Approved
**Scope:** Reverse-engineer all 18 gates into individual design + implementation docs

---

## Goal

Create a self-contained documentation folder for each of the 18 security gates. Each folder contains two files targeting different audiences:

- `design.md` — compliance/security reviewers: what the gate detects, why it matters, NIST control mapping, known limitations
- `implementation.md` — developers: source file, class, patterns table, special logic, known debt, test coverage

This is a pure documentation effort — no code changes. Existing files in `docs/plans/` are left as-is (historical record).

---

## Folder Structure

```
docs/gates/
├── gate-01-secrets/
│   ├── design.md
│   └── implementation.md
├── gate-02-crypto/
│   ├── design.md
│   └── implementation.md
├── gate-03-iam/
├── gate-04-sbom/
├── gate-05-iac/
├── gate-06-input-validation/
├── gate-07-audit/
├── gate-08-change-control/
├── gate-09-deps/
├── gate-10-api/
├── gate-11-privacy/
├── gate-12-resilience/
├── gate-13-incident/
├── gate-14-observability/
├── gate-15-memsafe/
├── gate-16-license/
├── gate-17-aiml/
└── gate-18-container/
    ├── design.md
    └── implementation.md
```

Folder names use zero-padded gate number + `gate_id` for consistent sort order.

---

## Gate Index

| Folder | Gate Name | Source File | gate_id | NIST Controls |
|---|---|---|---|---|
| `gate-01-secrets` | Secrets & Credential Gate | `secrets_gate.py` | `secrets` | IA-5, IA-6, SC-12, SC-28 |
| `gate-02-crypto` | Cryptography Gate | `crypto_gate.py` | `crypto` | SC-8, SC-13, SC-17, SC-23 |
| `gate-03-iam` | IAM Gate | `iam_gate.py` | `iam` | AC-3, AC-4, AC-5, AC-6 |
| `gate-04-sbom` | Supply Chain / SBOM Gate | `sbom_gate.py` | `sbom` | SR-3, SR-11, SA-10, SA-11 |
| `gate-05-iac` | Infrastructure-as-Code Gate | `iac_gate.py` | `iac` | CM-2, CM-6, CM-7, SC-7 |
| `gate-06-input-validation` | Input Validation Gate | `input_gate.py` | `input_validation` | SI-7, SI-10, SI-11, SI-16 |
| `gate-07-audit` | Audit Logging Gate | `audit_gate.py` | `audit` | AU-2, AU-3, AU-12 |
| `gate-08-change-control` | Change Control Gate | `change_gate.py` | `change_control` | CM-3, CM-4, CM-5 |
| `gate-09-deps` | Dependency Vulnerability Gate | `deps_gate.py` | `deps` | RA-5, SI-2, SA-12 |
| `gate-10-api` | API Security Gate | `api_gate.py` | `api` | SC-8, AC-3, SC-5, SI-10 |
| `gate-11-privacy` | Data Privacy Gate | `privacy_gate.py` | `privacy` | PT-2, PT-3, SC-28 |
| `gate-12-resilience` | Resilience & Backup Gate | `resilience_gate.py` | `resilience` | CP-9, CP-10, SI-13 |
| `gate-13-incident` | Incident Response Gate | `incident_gate.py` | `incident` | IR-4, IR-6, AU-6 |
| `gate-14-observability` | Observability Gate | `observability_gate.py` | `observability` | SI-4, AU-12 |
| `gate-15-memsafe` | Memory Safety Gate | `memsafe_gate.py` | `memsafe` | SI-16, CM-7 |
| `gate-16-license` | License Compliance Gate | `license_gate.py` | `license` | SA-4, SR-3 |
| `gate-17-aiml` | AI/ML Security Gate | `aiml_gate.py` | `aiml` | SI-10, SC-28, SR-3 |
| `gate-18-container` | Container Security Gate | `container_gate.py` | `container` | CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3 |

---

## `design.md` Template

```markdown
# Gate N — <Gate Name>

**gate_id:** `<gate_id>`
**NIST Controls:** <list>
**Priority:** 🔴 High / 🟡 Medium / 🟢 Later

---

## Purpose

One paragraph: what threat or compliance gap this gate addresses, and why it matters.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| <plain English description> | <business risk> | <control ID> |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all / specific
- **Special detection:** entropy analysis / file-type flags / other (if applicable)

---

## Known Limitations

- Does not scan deleted/removed lines
- Does not perform cross-file analysis
- <gate-specific deferred patterns>

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| <ID> | <Title> | <one sentence> |
```

---

## `implementation.md` Template

```markdown
# Gate N — <Gate Name>: Implementation Reference

**Source file:** `src/controlgate/gates/<gate_id>_gate.py`
**Test file:** `tests/test_gates/test_<gate_id>_gate.py`
**Class:** `<ClassName>`
**gate_id:** `<gate_id>`
**mapped_control_ids:** `["X-1", "X-2"]`

---

## Scan Method

Description of how `scan()` works — standard pattern loop vs. custom logic.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `<regex>` | <description> | <ID> | <remediation> |

---

## Special Detection Logic

(Omit section if gate uses only the standard pattern loop.)

---

## Known Debt / Deferred Patterns

(Omit section if no deferred patterns.)

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_<name>` | <description> |
```

---

## Authoring Notes

- Write `design.md` from the code, not from prior plan docs — the code is the source of truth
- `implementation.md` patterns table is extracted verbatim from `_PATTERNS` in the source file
- For gates with multiple pattern groups (ContainerGate), use sub-sections per group in the patterns table
- SecretsGate has entropy-based detection in addition to patterns — document this in Special Detection Logic
- ObservabilityGate has a K8s liveness probe absence check — document this in Special Detection Logic
- Known debt entries come from `docs/plans/2026-02-27-gates-gap-analysis.md`
- Total deliverable: 36 files (18 × design.md + 18 × implementation.md)
