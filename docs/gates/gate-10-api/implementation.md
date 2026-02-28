# Gate 10 — API Security Gate: Implementation Reference

**Source file:** `src/controlgate/gates/api_gate.py`
**Test file:** `tests/test_gates/test_api_gate.py`
**Class:** `APIGate`
**gate_id:** `api`
**mapped_control_ids:** `["SC-8", "AC-3", "SC-5", "SI-10"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the provided list and then iterates every added line via `diff_file.all_added_lines`, which yields `(line_no, line)` tuples. For each added line the method runs all six entries in the module-level `_PATTERNS` list in order. Each entry is a four-tuple of `(compiled_regex, description, control_id, remediation)`. When a pattern's `.search()` call matches the line, `_make_finding()` is called with the corresponding control ID, file path, line number, description, the first 120 characters of the stripped line as evidence, and the remediation string. All findings are collected into a flat list and returned. There is no early-exit per line; a single added line can produce multiple findings if it matches more than one pattern.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `verify\s*=\s*False` | TLS certificate verification disabled — subject to MITM attacks | SC-8 | Remove verify=False and use a proper CA bundle; never disable TLS verification in production |
| 2 | `(?i)(?:CORS_ORIGIN_ALLOW_ALL\|allow_all_origins)\s*=\s*True` | CORS wildcard origin configured — allows any domain to make credentialed requests | AC-3 | Restrict CORS to an explicit allowlist of trusted origins |
| 3 | `Access-Control-Allow-Origin.*?[=:]\s*["']?\s*\*` | Access-Control-Allow-Origin: * permits requests from any origin | AC-3 | Restrict Access-Control-Allow-Origin to specific trusted origins |
| 4 | `Access-Control-Allow-Credentials.*?[=:]\s*["']?\s*true` (case-insensitive) | Access-Control-Allow-Credentials: true with wildcard origin creates CSRF/CORS bypass risk | AC-3 | Never combine Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: * |
| 5 | `[?&](?:api[_-]?key\|token\|access[_-]?token\|secret)[=]` | API key or token passed in URL query parameter — logged in server access logs | SC-8 | Pass API credentials in Authorization header, not in URL query parameters |
| 6 | `(?i)GRAPHQL_INTROSPECTION\s*=\s*True\|graphiql\s*=\s*True` | GraphQL introspection or GraphiQL enabled — exposes full schema to attackers | AC-3 | Disable introspection and GraphiQL in non-development environments |

---

## Known Debt / Deferred Patterns

- SC-5 (Denial of Service Protection): declared in `mapped_control_ids` but no patterns currently emit SC-5; rate-limiting and DoS detection deferred
- SI-10 (Information Input Validation): declared in `mapped_control_ids` but no patterns currently emit SI-10; API input schema validation deferred

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_verify_false` | A line containing `verify=False` triggers a finding with "TLS" or "MITM" in the description and control ID SC-8 |
| `test_detects_cors_allow_all` | A line containing `CORS_ORIGIN_ALLOW_ALL = True` or `allow_all_origins = True` triggers a finding with "CORS" or "wildcard" in the description and control ID AC-3 |
| `test_detects_api_key_in_query` | A URL containing a query parameter named `api_key`, `token`, `access_token`, or `secret` triggers a finding with "query parameter" in the description and control ID SC-8 |
| `test_detects_credentialed_cors` | A line containing `Access-Control-Allow-Credentials: true` triggers a finding referencing the CSRF/CORS bypass risk and control ID AC-3 |
| `test_clean_code_no_findings` | Code that uses proper TLS settings, header-based auth, and restricted CORS origins produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "api"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"SC-8", "AC-3"}` |
| `test_detects_graphql_introspection` | A line containing `GRAPHQL_INTROSPECTION = True` or `graphiql = True` triggers a finding with "introspection" or "GraphiQL" in the description and control ID AC-3 |
