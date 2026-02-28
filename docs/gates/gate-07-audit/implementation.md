# Gate 7 — Audit & Logging Gate: Implementation Reference

**Source file:** `src/controlgate/gates/audit_gate.py`
**Test file:** `tests/test_gates/test_audit_gate.py`
**Class:** `AuditGate`
**gate_id:** `audit`
**mapped_control_ids:** `["AU-2", "AU-3", "AU-12"]`

---

## Scan Method

`scan()` performs three distinct sub-checks per `diff_file`, calling dedicated methods for each:

1. **`_check_removed_logging(diff_file)`** — scans `hunk.removed_lines` for deleted log statements. For each hunk in `diff_file.hunks`, iterates `hunk.removed_lines` (a list of `(line_no, line)` tuples representing deleted lines). Any removed line matching `_LOGGING_STATEMENT` emits one **AU-12** finding at the original line number.

2. **`_check_auth_logging(diff_file)`** — heuristic that detects auth/security functions added without any logging in the same hunk. For each hunk, joins all added lines into a single string and checks for `_AUTH_FUNCTION_PATTERNS`; if found, checks that `_LOGGING_STATEMENT` also appears in the same joined text. If logging is absent, emits one **AU-2** finding at the line of the auth function and stops after the first match per hunk.

3. **`_check_pii_in_logs(diff_file.path, line_no, line)`** — called once per added line via `diff_file.all_added_lines`. Runs the added line against all four `_PII_LOG_PATTERNS`; each matching pattern emits one **AU-3** finding.

This is one of only two gates in ControlGate that reads `hunk.removed_lines`.

---

## Patterns

### PII in Log Patterns (`_PII_LOG_PATTERNS`) — control AU-3

| # | Regex | Description | Remediation |
|---|---|---|---|
| 1 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:ssn\|social.?security\|sin\b)` | Possible SSN/SIN logged — PII in logs | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 2 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:password\|passwd\|pwd\|secret\|token\|api.?key)` | Sensitive credential may be logged — secrets in logs | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 3 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:credit.?card\|card.?number\|cvv\|ccn)` | Possible credit card data logged — PII in logs | Redact or mask sensitive data before logging. Log only non-PII identifiers |
| 4 | `(?i)(?:log(?:ger)?\|print\|console)\s*[\.(].*(?:date.?of.?birth\|dob\|birth.?date)` | Possible date of birth logged — PII in logs | Redact or mask sensitive data before logging. Log only non-PII identifiers |

---

## Special Detection Logic

### (a) Removed-Line Logging Detection (`_check_removed_logging`)

Iterates `diff_file.hunks` and for each hunk iterates `hunk.removed_lines`. For each removed line that matches `_LOGGING_STATEMENT`, one AU-12 finding is emitted at the original (pre-patch) line number from the diff context.

The `_LOGGING_STATEMENT` pattern matches:

- `log.info(`, `log.warn(`, `log.error(`, `log.debug(`, `log.critical(`, `log.warning(` (and `logger.*` variants)
- `logging.info(`, `logging.warn(`, `logging.error(`, `logging.debug(`, `logging.critical(`, `logging.warning(`
- `console.log(`, `console.warn(`, `console.error(`
- `print(`

### (b) Auth-Function-Without-Logging Heuristic (`_check_auth_logging`)

For each hunk in `diff_file.hunks`:

1. Joins all added lines into a single string: `added_text = " ".join(line for _, line in hunk.added_lines)`
2. Checks whether `_AUTH_FUNCTION_PATTERNS` matches anywhere in `added_text`
3. If a match is found, checks whether `_LOGGING_STATEMENT` also appears in `added_text`
4. If the hunk contains an auth function but no log statement, iterates `hunk.added_lines` to find the specific line matching `_AUTH_FUNCTION_PATTERNS`, emits one AU-2 finding at that line number, then breaks (one finding per hunk maximum)

The auth function name keywords matched by `_AUTH_FUNCTION_PATTERNS` are: `login`, `logout`, `authenticate`, `authorize`, `verify`, `check_permission`, `validate_token`, `reset_password`, `change_password`, `create_user`, `delete_user`, `grant_role`, `revoke_role`, `signup`, `signin`.

The heuristic is intentionally per-hunk. If the auth function definition and its log statement appear in different hunks of the same diff, the heuristic will fire a false positive.

### (c) `_LOGGING_STATEMENT` Dual Usage

The `_LOGGING_STATEMENT` compiled pattern is used in **two** distinct checks:

- In `_check_removed_logging`: applied to each **removed** line to detect deleted audit calls.
- In `_check_auth_logging`: applied to the joined **added** text of each hunk to determine whether the auth function has accompanying logging.

---

## Test Coverage

No test file currently exists for `AuditGate`. The file `tests/test_gates/test_audit_gate.py` has not been created; this gate has no automated test coverage.
