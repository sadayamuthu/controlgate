# Gate 6 — Input Validation & Error Handling Gate: Implementation Reference

**Source file:** `src/controlgate/gates/input_gate.py`
**Test file:** `tests/test_gates/test_input_gate.py`
**Class:** `InputGate`
**gate_id:** `input_validation`
**mapped_control_ids:** `["SI-7", "SI-10", "SI-11", "SI-16"]`

---

## Scan Method

`scan()` iterates every `diff_file` and calls `_check_line()` for each added line. `_check_line()` runs a single loop over `_INPUT_PATTERNS` (15 patterns), each a 4-tuple `(pattern, description, control_id, remediation)`. All patterns are evaluated for every added line; a single line can produce multiple findings.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)(?:execute\|cursor\.execute\|query)\s*\(\s*f["']` | SQL query built with f-string — SQL injection risk | SI-10 | Use parameterized queries (cursor.execute('SELECT ... WHERE id = %s', (id,))) |
| 2 | `(?i)(?:execute\|cursor\.execute\|query)\s*\(.*\.format\(` | SQL query built with .format() — SQL injection risk | SI-10 | Use parameterized queries instead of string formatting for SQL |
| 3 | `(?i)(?:execute\|cursor\.execute\|query)\s*\(.*%\s` | SQL query built with % string interpolation — SQL injection risk | SI-10 | Use parameterized queries instead of % formatting for SQL |
| 4 | `(?i)(?:execute\|cursor\.execute\|query)\s*\(.*\+\s*(?:request\|req\|params\|user\|input)` | SQL query built with concatenation of user input | SI-10 | Use parameterized queries. Never concatenate user input into SQL |
| 5 | `(?i)\beval\s*\(` | Use of eval() — code injection risk | SI-10 | Avoid eval(). Use ast.literal_eval() for data parsing or json.loads() for JSON |
| 6 | `(?i)\bexec\s*\(` | Use of exec() — code injection risk | SI-10 | Avoid exec(). Refactor to use safe alternatives |
| 7 | `(?i)subprocess\.(?:call\|run\|Popen)\s*\(.*shell\s*=\s*True` | Shell command execution with shell=True — command injection risk | SI-10 | Use shell=False and pass command as a list: subprocess.run(['cmd', 'arg']) |
| 8 | `(?i)os\.system\s*\(` | Use of os.system() — command injection risk | SI-10 | Use subprocess.run() with shell=False instead of os.system() |
| 9 | `(?i)os\.popen\s*\(` | Use of os.popen() — command injection risk | SI-10 | Use subprocess.run() with shell=False instead of os.popen() |
| 10 | `(?i)\bpickle\.loads?\b` | Unsafe deserialization with pickle — arbitrary code execution risk | SI-10 | Use JSON or other safe serialization formats. Never unpickle untrusted data |
| 11 | `(?i)\byaml\.(?:load\|unsafe_load)\s*\(` | Unsafe YAML loading — code execution risk | SI-10 | Use yaml.safe_load() instead of yaml.load() or yaml.unsafe_load() |
| 12 | `(?i)except\s*:\s*(?:pass\|\.\.\.|\s*$)` | Bare except clause silently swallows all errors | SI-11 | Catch specific exceptions and log them. Avoid bare except: pass |
| 13 | `(?i)(?:traceback\.print\|print.*traceback\|traceback\.format)` | Stack trace may be exposed to users | SI-11 | Log stack traces server-side only. Never expose traceback details to end users |
| 14 | `(?i)(?:DEBUG\|debug)\s*[:=]\s*(?:True\|true\|1\|on)` | Debug mode enabled — may expose internal details | SI-11 | Disable debug mode in production configurations |
| 15 | `(?i)(?:urllib\|requests\|wget\|curl).*(?:download\|get)\b(?!.*(?:verify\|checksum\|hash\|sha\|md5sum))` | File download without integrity verification | SI-7 | Verify downloaded files with checksums (SHA-256) before use |
| 16 | `(?i)\b(?:strcpy\|strcat\|sprintf\|gets)\s*\(` | Unsafe C string function — buffer overflow risk | SI-16 | Use safe alternatives: strncpy, strncat, snprintf, fgets |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_sql_injection` | `cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")` triggers at least one finding with "SQL" in the description |
| `test_detects_eval` | `result = eval(data)` triggers at least one finding with "eval" in the description |
| `test_detects_bare_except` | `except: pass` triggers at least one finding with "except" in the description |
