# Gate 3 — IAM & Access Control Gate: Implementation Reference

**Source file:** `src/controlgate/gates/iam_gate.py`
**Test file:** `tests/test_gates/test_iam_gate.py`
**Class:** `IAMGate`
**gate_id:** `iam`
**mapped_control_ids:** `["AC-3", "AC-4", "AC-5", "AC-6"]`

## Scan Method

`scan()` iterates every `diff_file` and calls `_check_line()` for each added line. `_check_line()` runs a single loop over `_IAM_PATTERNS` (10 patterns), each a 4-tuple `(pattern, description, control_id, remediation)`. All patterns are evaluated for every added line; a line can produce multiple findings. There is no file-type filter — all file types are scanned.

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `"Action"\s*:\s*"\*"|'Action'\s*:\s*'\*'` | Wildcard IAM action detected — grants all permissions | AC-6 | Apply least privilege: specify only the exact actions needed |
| 2 | `"Resource"\s*:\s*"\*"|'Resource'\s*:\s*'\*'` | Wildcard resource in IAM policy — applies to all resources | AC-6 | Scope resources to specific ARNs instead of using wildcards |
| 3 | `"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"` | IAM policy allows all actions | AC-6 | Follow least privilege principle — enumerate specific actions needed |
| 4 | `(?i)(?:AdministratorAccess|PowerUserAccess|FullAccess)` | Overly permissive managed policy referenced | AC-6 | Use custom policies with minimum required permissions instead of broad managed policies |
| 5 | `(?i)arn:aws:iam::.*:policy/AdministratorAccess` | AdministratorAccess policy attached | AC-5 | Implement separation of duties — avoid admin access in application code |
| 6 | `(?i)(?:access.control.allow.origin|cors.*origin)\s*[:=]\s*["\']?\*["\']?` | Wildcard CORS origin allows any domain | AC-4 | Restrict CORS origins to specific trusted domains |
| 7 | `(?i)allow_origins\s*=\s*\[?\s*["\']?\*["\']?` | CORS configured to allow all origins | AC-4 | Specify allowed origins explicitly instead of using wildcards |
| 8 | `(?i)@app\.route\(.*\)\s*$` | Route handler without explicit authentication decorator | AC-3 | Add authentication/authorization middleware or decorator to this endpoint |
| 9 | `(?i)(?:public|anonymous|no.?auth|skip.?auth|allow.?all)` | Explicit authentication bypass detected | AC-3 | Verify this endpoint should be publicly accessible; document the security decision |
| 10 | `(?i)sts[:\.]assume.?role` | STS AssumeRole without visible condition constraints | AC-3 | Add condition constraints (IP, MFA, time) to assume-role policies |

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_wildcard_action` | A policy document with `"Action": "*"` and `"Resource": "*"` triggers at least one finding with "wildcard" or "Action" in the description |
| `test_detects_cors_wildcard` | `access-control-allow-origin: *` header triggers at least one finding with "CORS" in the description |
