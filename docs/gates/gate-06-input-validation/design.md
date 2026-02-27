# Gate 6 — Input Validation & Error Handling Gate

**gate_id:** `input_validation`
**NIST Controls:** SI-7, SI-10, SI-11, SI-16
**Priority:** High

---

## Purpose

Detects the introduction of code patterns that expose applications to injection attacks, unsafe code execution, insecure deserialization, and information disclosure through improper error handling. SQL injection, command injection, and unsafe deserialization remain the most reliably exploitable vulnerability classes across the OWASP Top 10 and CISA Known Exploited Vulnerabilities catalog. This gate catches the construction of dynamic queries from user input, use of dangerous execution primitives (`eval`, `exec`, `os.system`), insecure deserialization via `pickle` and `yaml.load`, and the disclosure of internal error state through tracebacks or debug mode — all at the point of code introduction.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| SQL query built with f-string | f-strings embed user input directly into the query string, enabling SQL injection | SI-10 |
| SQL query built with `.format()` | Same risk as f-strings; `.format()` interpolates user data into the query | SI-10 |
| SQL query built with `%` interpolation | Classic Python `%`-style string formatting in SQL produces injection-vulnerable queries | SI-10 |
| SQL query built by concatenating user input | Direct string concatenation of request/user/params variables into SQL | SI-10 |
| Use of `eval()` | Executes arbitrary Python code from a string; code injection if the argument is user-controlled | SI-10 |
| Use of `exec()` | Executes arbitrary code; same risk as `eval()` | SI-10 |
| `subprocess` with `shell=True` | Passes the command through the shell interpreter, enabling command injection via metacharacters | SI-10 |
| Use of `os.system()` | Invokes a shell command; subject to command injection if any part is user-controlled | SI-10 |
| Use of `os.popen()` | Same as `os.system()` with the addition of capturing output | SI-10 |
| `pickle.loads()` / `pickle.load()` | Deserializes arbitrary Python objects; crafted payloads execute arbitrary code during deserialization | SI-10 |
| `yaml.load()` / `yaml.unsafe_load()` | Unsafe YAML deserialization can execute arbitrary Python constructors | SI-10 |
| Bare `except: pass` | Silently swallows all exceptions including security-relevant failures; makes breaches invisible | SI-11 |
| Stack trace exposure (`traceback.print`, `print.*traceback`) | Exposes internal file paths, function names, and logic to users; aids attacker reconnaissance | SI-11 |
| Debug mode enabled (`DEBUG=True`) | Debug mode typically enables detailed error pages, REPL access, and disables security hardening | SI-11 |
| File download without integrity verification | Downloads without hash verification can be replaced with malicious content | SI-7 |
| Unsafe C string functions (`strcpy`, `strcat`, `sprintf`, `gets`) | Classic buffer overflow vulnerabilities in C/C++ code | SI-16 |

---

## Scope

- **Scans:** all added lines in every file in the diff
- **File types targeted:** all file types; no extension filter is applied
- **Special detection:** none; standard pattern loop only

---

## Known Limitations

- Does not scan deleted or unmodified lines
- SQL injection patterns require the function call (`execute`, `cursor.execute`, `query`) to appear on the same line as the string construction; multi-line query builds are not detected
- The `os.system()` and `os.popen()` patterns fire on any use of these functions, not only those with user-controlled arguments; this produces false positives on calls with static strings
- `exec()` detection is case-insensitive and may match unrelated symbols containing "exec" in non-Python files
- Bare except detection matches `except: pass` and `except: ...` but not multi-line bare except blocks where `pass` is on the next line
- The download-without-integrity-verification pattern is a heuristic; it excludes lines that also contain the words `verify`, `checksum`, `hash`, `sha`, or `md5sum` but cannot perform semantic analysis of the surrounding code

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SI-7 | Software, Firmware, and Information Integrity | Detects file downloads that lack integrity verification (checksum/hash validation) |
| SI-10 | Information Input Validation | Detects SQL injection via string construction, unsafe code execution primitives (eval/exec/os.system), command injection via shell=True, and unsafe deserialization (pickle/yaml.load) |
| SI-11 | Error Handling | Detects bare except clauses that suppress errors, exposed stack traces, and enabled debug mode — all of which represent improper error handling that can aid attackers or hide failures |
| SI-16 | Memory Protection | Detects unsafe C string functions (strcpy, strcat, sprintf, gets) that are well-known sources of buffer overflow vulnerabilities |
