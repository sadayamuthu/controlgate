# Gate 7 — Audit & Logging Gate: Implementation Reference

**Source file:** `src/controlgate/gates/audit_gate.py`
**Test file:** none
**Class:** `AuditGate`
**gate_id:** `audit`
**mapped_control_ids:** `["AU-2", "AU-3", "AU-12"]`

---

## Scan Method

`scan()` performs three distinct sub-checks per `diff_file`, calling dedicated methods for each:

1. `_check_removed_logging(diff_file)` — scans `hunk.removed_lines` for deleted log statements; fires AU-12 findings.
2. `_check_auth_logging(diff_file)` — heuristic that detects auth/security functions added without any logging in the same hunk; fires AU-2 findings.
3. `_check_pii_in_logs(diff_file.path, line_no, line)` — called per added line; runs `_PII_LOG_PATTERNS` loop; fires AU-3 findings.

This is one of only two gates in ControlGate that reads `hunk.removed_lines`.

---

## Patterns

### PII in Log Patterns (`_PII_LOG_PATTERNS`) — control AU-3

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:ssn\|social.?security\|sin\b)` | Possible SSN/SIN logged — PII in logs | AU-3 | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 2 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:password\|passwd\|pwd\|secret\|token\|api.?key)` | Sensitive credential may be logged — secrets in logs | AU-3 | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 3 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:credit.?card\|card.?number\|cvv\|ccn)` | Possible credit card data logged — PII in logs | AU-3 | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 4 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:date.?of.?birth\|dob\|birth.?date)` | Possible date of birth logged — PII in logs | AU-3 | Redact or mask sensitive data before logging. Log only non-PII identifiers |

### Removed Logging Statement Pattern (`_LOGGING_STATEMENT`) — control AU-12

Applied to removed lines (`hunk.removed_lines`):

| Regex | Description | Control |
|---|---|---|
| `(?i)(?:log(?:ger)?\.(?:info\|warn\|error\|debug\|critical\|warning)\|logging\.(?:info\|warn\|error\|debug\|critical\|warning)\|console\.(?:log\|warn\|error)\|print\s*\()` | Logging statement removed — may reduce audit trail | AU-12 |

### Auth Function Pattern (`_AUTH_FUNCTION_PATTERNS`) — control AU-2

Applied to added lines aggregated per hunk:

| Regex | Description | Control |
|---|---|---|
| `(?i)(?:def\s+(?:login\|logout\|authenticate\|authorize\|verify\|check_permission\|validate_token\|reset_password\|change_password\|create_user\|delete_user\|grant_role\|revoke_role\|signup\|signin))` | Security-critical function without logging | AU-2 |

---

## Special Detection Logic

### Removed Logging Detection (`_check_removed_logging`)

Iterates `diff_file.hunks` and for each hunk iterates `hunk.removed_lines` (a list of `(line_no, line)` tuples representing deleted lines). For each removed line that matches `_LOGGING_STATEMENT`, one AU-12 finding is emitted at the line number of the removed line.

This operates on the original line numbers from the diff context, not the post-patch line numbers.

### Auth-Function-Without-Logging Heuristic (`_check_auth_logging`)

For each hunk in `diff_file.hunks`:
1. Joins all added lines in the hunk into a single string: `added_text = " ".join(line for _, line in hunk.added_lines)`
2. Checks whether `_AUTH_FUNCTION_PATTERNS` matches anywhere in `added_text`
3. If a match is found, checks whether `_LOGGING_STATEMENT` also appears in `added_text`
4. If the hunk contains an auth function but no log statement, iterates `hunk.added_lines` to find the specific line matching `_AUTH_FUNCTION_PATTERNS` and emits one AU-2 finding at that line number, then breaks (one finding per hunk)

The heuristic is intentionally per-hunk: if the auth function and its log statement appear in different hunks, the heuristic will fire a false positive.

---

## Known Debt / Deferred Patterns

- No test file exists for this gate; all behaviour is untested by automated tests
- The auth-function heuristic does not detect logging provided by decorators or middleware outside the function definition
- PII pattern matching requires the logging call and PII keyword to appear on the same line; structured log calls that build a dict argument spread across multiple lines are not detected

---

## Test Coverage

No test file exists for `AuditGate`. This gate has no automated test coverage.
