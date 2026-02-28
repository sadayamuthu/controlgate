# Gate 7 — Audit & Logging Gate

**gate_id:** `audit`
**NIST Controls:** AU-2, AU-3, AU-12
**Priority:** 🔴 High

---

## Purpose

Ensures that security-relevant events are logged and that the audit trail is not inadvertently degraded by code changes. Inadequate logging is consistently cited in incident post-mortems as the primary reason attackers can operate undetected for extended periods. This gate detects three categories of logging risk: removal of existing log statements (which may reduce audit coverage), authentication and authorization functions that lack accompanying log output (leaving security decisions unrecorded), and log statements that include personally identifiable information or sensitive credentials (which creates a secondary data exposure).

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Removed logging statement | Deleting a log call may eliminate the only record of an event from the audit trail | AU-12 |
| Security-critical function added without logging (`login`, `logout`, `authenticate`, `authorize`, `verify`, `check_permission`, `validate_token`, `reset_password`, `change_password`, `create_user`, `delete_user`, `grant_role`, `revoke_role`, `signup`, `signin`) | Authentication and access-control events that are not logged cannot be used for incident detection or forensic reconstruction | AU-2 |
| SSN or SIN logged | Social security numbers in log output create a PII data exposure incident | AU-3 |
| Password, secret, token, or API key logged | Credential material in log files enables secondary credential compromise | AU-3 |
| Credit card number or CVV logged | Payment card data in logs creates a PCI-DSS compliance violation | AU-3 |
| Date of birth logged | Date of birth is PII; its presence in logs may violate GDPR, HIPAA, or other privacy regulations | AU-3 |

---

## Scope

This gate scans **both added lines and removed lines**, making it one of only two gates in ControlGate that reads `hunk.removed_lines`. Three distinct scanning mechanisms are applied per diff file:

- **Removed-line scan** (`_check_removed_logging`): iterates `hunk.removed_lines` across all hunks to detect deleted log statements; uses the `_LOGGING_STATEMENT` pattern.
- **Auth-function heuristic** (`_check_auth_logging`): iterates added lines grouped per hunk; joins all added lines in a hunk into a single string and checks for an auth/security function name without an accompanying log call in the same hunk; uses both `_AUTH_FUNCTION_PATTERNS` and `_LOGGING_STATEMENT`.
- **PII-in-log scan** (`_check_pii_in_logs`): iterates `diff_file.all_added_lines` and runs each added line against the four `_PII_LOG_PATTERNS`.

No file-extension filter is applied; all files in the diff are scanned.

---

## Known Limitations

- The auth-function-without-logging check is a **heuristic operating per hunk**: if a function definition and its log statement appear in different hunks of the same diff, the heuristic will produce a false positive.
- The gate **cannot detect logging done in a called function**, decorator, or middleware outside the function body; it only checks whether the same hunk that introduces the function also contains a log call.
- **PII detection is keyword-based and line-scoped**: the regex requires the logging call and the PII keyword to appear on the same line. Structured logging calls that build a dict argument spread across multiple lines will not be detected.
- Removed-logging detection cannot distinguish intentional removal (superseded by a better framework) from accidental removal; all removed log statements are flagged.
- `print()` is treated as a logging statement for both removed-line detection and the auth-function heuristic, which may produce false positives on diagnostic print statements.

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| AU-2 | Event Logging | Detects authentication and authorization functions added without accompanying log statements, ensuring security-relevant events are captured |
| AU-3 | Content of Audit Records | Detects PII and credential data being written to logs, which pollutes audit records with data that should not be present and creates secondary exposure |
| AU-12 | Audit Record Generation | Detects removal of logging statements that may reduce the completeness of the audit record trail |
