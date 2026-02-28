# Gate 12 — Resilience & Backup Gate: Implementation Reference

**Source file:** `src/controlgate/gates/resilience_gate.py`
**Test file:** `tests/test_gates/test_resilience_gate.py`
**Class:** `ResilienceGate`
**gate_id:** `resilience`
**mapped_control_ids:** `["CP-9", "CP-10", "SI-13"]`

---

## Scan Method

`scan()` iterates over every `DiffFile` in the provided list and, for each added line (via `diff_file.all_added_lines`), runs the line through all entries in `_PATTERNS`. When a compiled regex matches, `_make_finding()` is called with the associated `control_id`, `description`, and `remediation` strings. Evidence is taken from the matched line stripped of leading/trailing whitespace and truncated to 120 characters. All findings are collected into a flat list and returned.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)deletion.?protection\s*[:=]\s*false` | deletion_protection disabled — database can be accidentally or maliciously deleted | CP-9 | Set deletion_protection = true on all production databases |
| 2 | `(?i)backup\s*[:=]\s*false` | Automated backups disabled for database resource | CP-9 | Enable automated backups; set backup_retention_period to at least 7 days |
| 3 | `(?i)skip.?final.?snapshot\s*[:=]\s*true` | skip_final_snapshot = true — no snapshot taken before database deletion | CP-9 | Set skip_final_snapshot = false and specify a final_snapshot_identifier |
| 4 | `(?i)max.?retries\s*[:=]\s*0` | max_retries set to 0 — no retry on transient failures | SI-13 | Set max_retries to at least 3 with exponential backoff for external service calls |
| 5 | `(?i)backup.?retention.?period\s*[:=]\s*0` | backup_retention_period = 0 disables automated database backups | CP-9 | Set backup_retention_period to at least 7 days for production databases |

---

## Known Debt / Deferred Patterns

- **CP-10 (System Recovery and Reconstitution):** declared in `mapped_control_ids` but no patterns currently emit CP-10 findings. Detection for recovery testing verification, RTO/RPO assertion checks, and restore rehearsal indicators has been deferred. Until patterns are added, CP-10 coverage is nominal only.

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_deletion_protection_false` | A diff adding `deletion_protection = false` produces at least one finding with "deletion_protection" or "backup" in the description |
| `test_detects_skip_final_snapshot` | A diff adding `skip_final_snapshot = true` produces at least one finding |
| `test_detects_max_retries_zero` | A diff adding `MAX_RETRIES = 0` produces at least one finding |
| `test_clean_config_no_findings` | A diff with `deletion_protection = true` and `skip_final_snapshot = false` produces zero findings |
| `test_findings_have_gate_id` | Every finding from the deletion-protection diff carries `gate == "resilience"` |
| `test_findings_have_valid_control_ids` | Every finding from the deletion-protection diff uses a control ID within `{"CP-9", "CP-10", "SI-13"}` |
