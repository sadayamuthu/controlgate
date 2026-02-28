# Gate 11 — Data Privacy Gate: Implementation Reference

**Source file:** `src/controlgate/gates/privacy_gate.py`
**Test file:** `tests/test_gates/test_privacy_gate.py`
**Class:** `PrivacyGate`
**gate_id:** `privacy`
**mapped_control_ids:** `["PT-2", "PT-3", "SC-28"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the provided list and, for each file, iterates every `(line_no, line)` pair from `diff_file.all_added_lines`. Each added line is tested against all four entries in `_PATTERNS`; every match produces one finding via `_make_finding()`. There are no sub-methods, no removed-line checks, and no file-extension filters.

Patterns 1 and 4 share the `_PII_FIELDS` helper constant, which is a non-capturing alternation of PII keyword fragments. This constant is concatenated into the base regex string at module load time before `re.compile()` is called, so the runtime pattern contains the fully expanded alternation.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)(?:logging\.\|logger\.\|print\().*(?:ssn\|social.?security\|date.?of.?birth\|dob\|credit.?card\|card.?number\|cvv\|passport\|drivers.?license)` | PII field name detected in logging/print statement | PT-3 | Remove PII from logs; use opaque identifiers (user_id) instead of PII field values |
| 2 | `(?i)serialize_all_fields\s*=\s*True` | `serialize_all_fields=True` exposes all model fields — may leak PII or sensitive data | PT-2 | Use an explicit fields allowlist in serializers; never serialize all fields by default |
| 3 | `(?i)expires_at\s*=\s*None\|ttl\s*[:=]\s*0\|ttl\s*[:=]\s*null` | Data retention field set to null/0 — no expiry policy enforced | SC-28 | Set an explicit `expires_at` or TTL for all data with retention requirements |
| 4 | `(?i)(?:CharField\|TextField\|StringField\|Column\(String)\s*\(.*?(?:ssn\|social.?security\|date.?of.?birth\|dob\|credit.?card\|card.?number\|cvv\|passport\|drivers.?license)` | PII field stored in plaintext database column without encryption marker | SC-28 | Encrypt PII at rest using field-level encryption or a dedicated vault |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_pii_in_log` | A diff adding `logging.debug("User SSN: %s, DOB: %s", user.ssn, user.date_of_birth)` produces at least one finding whose description contains "pii" or "log" |
| `test_detects_serialize_all_fields` | A diff adding `serialize_all_fields = True` to a serializer class produces at least one finding |
| `test_detects_no_expiry` | A diff adding `expires_at = None` to a model class produces at least one finding |
| `test_clean_code_no_findings` | A diff adding a log statement that uses only `user_id` (no PII keywords) produces zero findings |
| `test_findings_have_gate_id` | Every finding produced from the PII-in-log diff carries `gate == "privacy"` |
| `test_findings_have_valid_control_ids` | Every finding produced from the PII-in-log diff uses a control ID within `{"PT-2", "PT-3", "SC-28"}` |
