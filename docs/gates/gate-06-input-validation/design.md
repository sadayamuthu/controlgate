# Gate 6 — Input Validation & Error Handling Gate

**gate_id:** `input_validation`
**NIST Controls:** SI-7, SI-10, SI-11, SI-16
**Priority:** 🔴 High

---

## Purpose

Gate 6 detects the introduction of code patterns that expose applications to injection attacks, unsafe code execution, insecure deserialization, and information disclosure through improper error handling. It covers SQL injection risks arising from dynamic query construction, use of dangerous execution primitives such as `eval`, `exec`, `os.system`, `os.popen`, and `subprocess` with `shell=True`, shell injection via unsafe C string functions, unsafe deserialization through `pickle` and `yaml.load`, improper error handling via bare `except` clauses or exposed stack traces, enabled debug mode that leaks internal state, and file download calls that omit checksum or hash integrity verification. All checks are applied at the point of code introduction by scanning every added line in the diff.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| **SQL Injection** | | |
| SQL query built with f-string | f-strings embed user input directly into the query string, enabling SQL injection | SI-10 |
| SQL query built with `.format()` | `.format()` interpolates user data into the query, same risk as f-strings | SI-10 |
| SQL query built with `%` interpolation | Classic Python `%`-style string formatting in SQL produces injection-vulnerable queries | SI-10 |
| SQL query built by concatenating user input | Direct string concatenation of `request`/`user`/`params` variables into SQL | SI-10 |
| **Dangerous Functions** | | |
| Use of `eval()` | Executes arbitrary Python from a string; code injection if the argument is user-controlled | SI-10 |
| Use of `exec()` | Executes arbitrary code; same risk as `eval()` | SI-10 |
| `subprocess` with `shell=True` | Passes the command through the shell interpreter, enabling command injection via metacharacters | SI-10 |
| Use of `os.system()` | Invokes a shell command; subject to command injection if any part is user-controlled | SI-10 |
| Use of `os.popen()` | Same shell-execution risk as `os.system()` with the addition of captured output | SI-10 |
| **Deserialization** | | |
| `pickle.loads()` / `pickle.load()` | Deserializes arbitrary Python objects; crafted payloads execute arbitrary code during deserialization | SI-10 |
| `yaml.load()` / `yaml.unsafe_load()` | Unsafe YAML deserialization can trigger arbitrary Python constructors | SI-10 |
| **Error Handling** | | |
| Bare `except: pass` | Silently swallows all exceptions including security-relevant failures; makes breaches invisible | SI-11 |
| Stack trace exposure (`traceback.print`, `print.*traceback`, `traceback.format`) | Exposes internal file paths, function names, and logic to users; aids attacker reconnaissance | SI-11 |
| Debug mode enabled (`DEBUG=True`) | Debug mode enables detailed error pages and disables security hardening in many frameworks | SI-11 |
| **Integrity** | | |
| File download without integrity verification | Downloads without hash verification can be silently replaced with malicious content | SI-7 |
| **Buffer Safety** | | |
| Unsafe C string functions (`strcpy`, `strcat`, `sprintf`, `gets`) | Classic buffer overflow vulnerabilities exploitable for arbitrary code execution in C/C++ code | SI-16 |

---

## Scope

- Scans all added lines in every file present in the diff
- No file-type filter is applied — all file extensions are included

---

## Known Limitations

- Detection is pattern-based only; no data flow analysis is performed, so whether a flagged call actually processes untrusted input cannot be determined
- The gate cannot determine whether the argument passed to `eval()` or `exec()` is user-controlled; any call to these functions is flagged regardless of its actual argument
- The bare `except` check is syntactic only and matches `except: pass` or `except: ...` on the same line; a bare `except` block where `pass` appears on the following line is not detected

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SI-7 | Software, Firmware, and Information Integrity | Detects file downloads that omit integrity verification (checksum/hash validation), flagging the risk of tampered content being consumed by the application |
| SI-10 | Information Input Validation | Detects SQL injection via dynamic query construction, unsafe code execution primitives (`eval`/`exec`/`os.system`/`os.popen`), command injection via `shell=True`, and unsafe deserialization (`pickle`/`yaml.load`) |
| SI-11 | Error Handling | Detects bare `except` clauses that suppress errors, exposed stack traces, and enabled debug mode — all of which constitute improper error handling that can aid attackers or hide security failures |
| SI-16 | Memory Protection | Detects unsafe C string functions (`strcpy`, `strcat`, `sprintf`, `gets`) that are well-known sources of buffer overflow vulnerabilities |
