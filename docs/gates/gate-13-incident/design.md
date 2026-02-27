# Gate 13 — Incident Response Gate

**gate_id:** `incident`
**NIST Controls:** IR-4, IR-6, AU-6
**Priority:** High

---

## Purpose

Guards against code changes that silently degrade or remove an organisation's ability to detect, respond to, and report security incidents. Silent exception swallowing prevents errors from ever reaching monitoring systems; exposed stack traces hand attackers detailed implementation intelligence; and disabled alerting configurations mean that when something does go wrong, nobody is notified. By flagging these patterns at diff time, the gate ensures that incident detection capability is not quietly eroded during routine development.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Bare `except:` clause in Python | A bare except catches every possible exception, including keyboard interrupts and system exits, and when paired with `pass` it discards the error entirely — no log, no alert, no visibility into what went wrong | IR-4 |
| Empty catch block in JS/TS/Java (`catch(...) {}`) | An empty catch block silently swallows exceptions in JavaScript, TypeScript, and Java, leaving the application in an unknown state with no record of the failure | IR-4 |
| `traceback.print_exc()` or `traceback.format_exc()` in a response path | Returning a Python stack trace to the client leaks internal module paths, dependency versions, and logic structure — intelligence an attacker can use to craft targeted exploits | IR-4 |
| `notify: false` or `notifications_enabled: false/= false` in configuration | Disabling notifications in a monitoring or alerting configuration silences the entire alert pipeline, ensuring that incidents are not reported to on-call responders | IR-6 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- The bare-except pattern is Python-specific and relies on the line being exactly `except:` (with optional surrounding whitespace); multi-statement bare-except clauses on a single line are not matched
- The empty-catch pattern requires the opening brace and closing brace to appear on the same line (`catch(e) {}`); multi-line empty catch blocks are not detected
- The traceback pattern matches any added line calling `traceback.print_exc()` or `traceback.format_exc()` regardless of whether the result is returned to a client or logged server-side; legitimate server-side logging calls will produce false positives
- The notification-disabled pattern is case-insensitive but regex-based; equivalent settings expressed through environment variables, feature flags, or programmatic calls are not detected

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| IR-4 | Incident Handling | Detects bare except clauses and empty catch blocks that prevent exceptions from being observed or logged, and detects stack trace exposure that leaks implementation detail to attackers during an incident |
| IR-6 | Incident Reporting | Detects monitoring or alerting configuration that explicitly disables notifications, ensuring that incidents are not silently dropped before reaching on-call responders |
| AU-6 | Audit Review, Analysis, and Reporting | Declared in `mapped_control_ids`; no patterns currently emitted — audit log gap detection and missing review automation deferred (see Known Debt in the implementation reference) |
