# Gate 12 — Resilience & Backup Gate

**gate_id:** `resilience`
**NIST Controls:** CP-9, CP-10, SI-13
**Priority:** 🟡 Medium

---

## Purpose

Detects infrastructure and application configuration changes that undermine recoverability. When critical settings such as deletion protection, automated backups, final snapshots, and retry logic are disabled or zeroed out, the system loses its ability to recover from accidental deletion, data loss, or transient failure. This gate flags these misconfigurations at commit time — before they can reach a production environment — providing an automated guardrail aligned with NIST contingency planning and fault-tolerance controls.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `deletion_protection = false` on a database resource | Allows a database to be accidentally or maliciously deleted with no recovery path | CP-9 |
| `backup = false` on a database resource | Disables automated backups, leaving no restore point if data is corrupted or lost | CP-9 |
| `skip_final_snapshot = true` on a database resource | Prevents a final snapshot from being taken before deletion, making recovery impossible | CP-9 |
| `max_retries = 0` on an external service call or client | Eliminates retry behaviour so any transient failure becomes an unrecoverable error | SI-13 |
| `backup_retention_period = 0` on a database resource | Explicitly zeroes the backup window, functionally disabling all automated backups | CP-9 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files (typically IaC and config files)

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- Does not verify that `backup_retention_period` is set to a meaningful non-zero value beyond confirming it is not explicitly 0
- Does not detect missing backup configuration (only detects explicit disabling)
- Does not verify recovery objectives (RTO/RPO) or that restore procedures have been tested

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| CP-9 | Information System Backup | Detects explicit disabling of deletion protection, automated backups, final snapshots, and backup retention periods on database resources |
| CP-10 | Information System Recovery and Reconstitution | Declared in scope; no patterns currently implemented — see implementation.md for known debt |
| SI-13 | Predictable Failure Prevention | Detects `max_retries = 0`, which removes retry logic and makes external service calls fail immediately on transient errors |
