# Gate 13 — Incident Response Gate: Implementation Reference

**Source file:** `src/controlgate/gates/incident_gate.py`
**Test file:** `tests/test_gates/test_incident_gate.py`
**Class:** `IncidentGate`
**gate_id:** `incident`
**mapped_control_ids:** `["IR-4", "IR-6", "AU-6"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the provided list and then iterates every added line via `diff_file.all_added_lines`, which yields `(line_no, line)` tuples. For each added line the method runs all four entries in the module-level `_PATTERNS` list in order. Each entry is a four-tuple of `(compiled_regex, description, control_id, remediation)`. When a pattern's `.search()` call matches the line, `_make_finding()` is called with the corresponding control ID, file path, line number, description, the first 120 characters of the stripped line as evidence, and the remediation string. All findings are collected into a flat list and returned. There is no early-exit per line; a single added line can produce multiple findings if it matches more than one pattern.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `^\s*except\s*:\s*$` | Bare except clause — silently swallows all exceptions, preventing incident detection | IR-4 | Catch specific exceptions and log them; never use bare except: pass |
| 2 | `catch\s*\([^)]*\)\s*\{\s*\}` | Empty catch block — exception swallowed silently in JS/TS/Java | IR-4 | Log or rethrow exceptions; never leave catch blocks empty |
| 3 | `traceback\.print_exc\(\)\|traceback\.format_exc\(\)` | Stack trace exposed in response — leaks implementation details to attackers | IR-4 | Log the traceback server-side only; return a generic error message to clients |
| 4 | `(?i)notify\s*:\s*false\|notifications.?enabled\s*[:=]\s*false` | Alerting/notification disabled in monitoring configuration | IR-6 | Enable notifications for all critical alerts; silence specific alerts rather than disabling all |

---

## Known Debt / Deferred Patterns

- AU-6 (Audit Review, Analysis, and Reporting): declared in `mapped_control_ids` but no patterns emit AU-6; audit log gap detection and missing review automation deferred

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_bare_except_pass` | A diff adding a bare `except:` clause triggers at least one finding whose description contains "exception" or "silent" |
| `test_detects_empty_catch_js` | A diff adding an empty `catch(e) {}` block in a JavaScript file triggers at least one finding |
| `test_detects_traceback_exposure` | A diff adding a `traceback.print_exc()` call triggers at least one finding |
| `test_detects_notify_false` | A diff adding `notify: false` in a YAML alerting configuration triggers at least one finding |
| `test_logged_exception_no_findings` | A diff adding a properly handled exception using a named exception type, a logger call, and a re-raise produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "incident"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"IR-4", "IR-6", "AU-6"}` |
