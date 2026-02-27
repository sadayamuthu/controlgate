# ControlGate — New Gates Design (Gates 9–18)

**Date:** 2026-02-27
**Status:** Approved
**Approach:** Flat — one file per gate, consistent with existing 8 gates

---

## Summary

Add 10 new security gates to ControlGate, expanding coverage from 8 to 18 gates and closing major NIST SP 800-53 Rev. 5 gaps in the RA, CP, IR, PT, SI-16, SA-4, SC-39, and ML-specific control families.

---

## Coverage Map — Before and After

### Existing 8 Gates
| Gate | gate_id | NIST Families |
|---|---|---|
| Secrets | `secrets` | IA, SC |
| Crypto | `crypto` | SC |
| IAM | `iam` | AC |
| Supply Chain | `sbom` | SR, SA |
| IaC | `iac` | CM, SC |
| Input Validation | `input_validation` | SI |
| Audit | `audit` | AU |
| Change Control | `change_control` | CM |

### New 10 Gates
| Gate | gate_id | NIST Families | Priority |
|---|---|---|---|
| Dependency Vulnerability | `deps` | RA, SI, SA | 🔴 High |
| API Security | `api` | SC, AC, SI | 🔴 High |
| Data Privacy | `privacy` | PT, SC | 🔴 High |
| Resilience & Backup | `resilience` | CP, SI | 🟡 Medium |
| Incident Response | `incident` | IR, AU | 🟡 Medium |
| Observability | `observability` | SI, AU | 🟡 Medium |
| Memory Safety | `memsafe` | SI, CM | 🟢 Later |
| License Compliance | `license` | SA, SR | 🟢 Later |
| AI/ML Security | `aiml` | SI, SC, SR | 🟢 Later |
| Container Security | `container` | CM, SC, AC, SI, AU, SR | 🔴 High |

---

## Architecture

No changes to `engine.py`, `base.py`, `models.py`, or any reporter. Each gate is a standalone file following the identical contract:

```
src/controlgate/gates/
├── deps_gate.py           # Gate 9  — RA-5, SI-2, SA-12
├── api_gate.py            # Gate 10 — SC-8, AC-3, SC-5, SI-10
├── privacy_gate.py        # Gate 11 — PT-2, PT-3, SC-28
├── resilience_gate.py     # Gate 12 — CP-9, CP-10, SI-13
├── incident_gate.py       # Gate 13 — IR-4, IR-6, AU-6
├── observability_gate.py  # Gate 14 — SI-4, AU-12
├── memsafe_gate.py        # Gate 15 — SI-16, CM-7
├── license_gate.py        # Gate 16 — SA-4, SR-3
├── aiml_gate.py           # Gate 17 — SI-10, SC-28, SR-3
└── container_gate.py      # Gate 18 — CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3
```

Two supporting changes:
1. `catalog.py` — add 10 new entries to `GATE_CONTROL_MAP`
2. `gates/__init__.py` — add 10 new classes to `ALL_GATES` and `__all__`

---

## Multi-Control-ID Decision

The ContainerGate spec groups patterns by category with multiple control IDs per pattern. Since `_make_finding()` takes a single `control_id`, each pattern uses its **primary** (most directly relevant) control ID:

| Pattern group | Primary control ID |
|---|---|
| Image integrity | `SI-7` |
| Least privilege | `AC-6` |
| Network isolation | `SC-7` |
| Runtime hardening | `SC-39` |
| Audit/logging | `AU-12` |
| Resource limits | `CM-6` |

---

## Gate Designs

### Gate 9 — Dependency Vulnerability (`deps`)
**NIST:** RA-5, SI-2, SA-12
**Scope:** Static pattern detection only. Live CVE lookup requires a network call outside the gate model and is out of scope.

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `--no-verify` flag in pip/npm | Bypasses integrity checks | `SA-12` | HIGH |
| `--ignore-scripts` in npm | Skips postinstall security scripts | `SA-12` | MEDIUM |
| `pip install` without pinned version (no `==`) | Unpinned install at runtime | `RA-5` | HIGH |
| `http://` in package registry URLs | Unencrypted package fetch | `SI-2` | HIGH |
| File: `requirements.txt`/`package.json` changed without lockfile | Dependency change without audit trail | `SR-3` borrow | MEDIUM |

### Gate 10 — API Security (`api`)
**NIST:** SC-8, AC-3, SC-5, SI-10

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `verify=False` in requests/urllib | TLS verification disabled | `SC-8` | CRITICAL |
| `CORS_ORIGIN_ALLOW_ALL = True` / `allow_all_origins = True` | Wildcard CORS origin | `AC-3` | HIGH |
| `Access-Control-Allow-Origin: *` + `Credentials: true` | Credentialed wildcard CORS | `AC-3` | CRITICAL |
| `?api_key=` / `?token=` in URL construction | API key in query param | `SC-8` | HIGH |
| `GraphQL introspection` enabled outside dev | Schema exposure | `AC-3` | MEDIUM |

### Gate 11 — Data Privacy (`privacy`)
**NIST:** PT-2, PT-3, SC-28
**Note:** MP-6 (media sanitization) has no applicable code patterns and is excluded.

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `logging.*` / `print()` containing PII field names (ssn, social_security, date_of_birth, credit_card) | PII in logs | `PT-3` | HIGH |
| `serialize_all_fields = True` | Data over-exposure in API | `PT-2` | HIGH |
| `ttl: 0` / `expires_at: null` in data models | Missing retention policy | `SC-28` | MEDIUM |
| PII field names (`ssn`, `dob`, `credit_card`) in unencrypted model fields | PII stored without encryption marker | `SC-28` | CRITICAL |

### Gate 12 — Resilience & Backup (`resilience`)
**NIST:** CP-9, CP-10, SI-13

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `deletion_protection: false` / `backup: false` | Backup protection disabled | `CP-9` | CRITICAL |
| `skip_final_snapshot = true` | No final snapshot on delete | `CP-9` | HIGH |
| `max_retries = 0` / `max_retries: 0` | Retry disabled | `SI-13` | HIGH |
| DB connection with no timeout (`connect_timeout` absent) | No connection timeout | `CP-10` | MEDIUM |

### Gate 13 — Incident Response (`incident`)
**NIST:** IR-4, IR-6, AU-6

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `except:` with no body or just `pass` | Silent exception swallowing | `IR-4` | HIGH |
| `catch (e) {}` / `catch(e) {}` in JS/TS | Silent exception swallowing | `IR-4` | HIGH |
| `traceback.print_exc()` in non-test files | Stack trace exposed | `IR-4` | HIGH |
| `notify: false` / `notifications_enabled: false` | Alerting disabled | `IR-6` | MEDIUM |

### Gate 14 — Observability (`observability`)
**NIST:** SI-4, AU-12

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `livenessProbe` absent from K8s pod spec additions | No liveness probe | `SI-4` | HIGH |
| `monitoring: false` / `enable_monitoring = false` | Monitoring disabled | `SI-4` | HIGH |
| `logging_driver: none` / `--log-driver=none` | Container logging disabled | `AU-12` | HIGH |
| DLQ resource deleted from diff | Dead letter queue removed | `AU-12` | HIGH |

### Gate 15 — Memory Safety (`memsafe`)
**NIST:** SI-16, CM-7

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `eval(` / `exec(` with non-literal argument | Dynamic code execution | `SI-16` | CRITICAL |
| `unsafe {` in Rust (no safety comment on same/prev line) | Unsafe Rust block | `CM-7` | HIGH |
| `ctypes.` / `cffi.` direct memory function calls | Raw memory access | `SI-16` | MEDIUM |
| `strcpy(` / `memcpy(` in C diffs | Unbounded copy functions | `SI-16` | HIGH |

### Gate 16 — License Compliance (`license`)
**NIST:** SA-4, SR-3

| Pattern | Description | Control | Severity |
|---|---|---|---|
| GPL/AGPL/SSPL/LGPL in package manifests | Copyleft license in dep | `SA-4` | HIGH |
| SPDX copyleft identifiers in added source files | Copyleft in source | `SA-4` | HIGH |
| License header removed from diff (detected line removal) | License stripped | `SR-3` | MEDIUM |

### Gate 17 — AI/ML Security (`aiml`)
**NIST:** SI-10, SC-28, SR-3

| Pattern | Description | Control | Severity |
|---|---|---|---|
| `trust_remote_code=True` | Executes arbitrary remote code | `SR-3` | CRITICAL |
| `pickle.load(` / `pickle.loads(` | Arbitrary code exec on load | `SI-10` | CRITICAL |
| Model URL via `http://` (not `https://`) | Unencrypted model fetch | `SR-3` | HIGH |
| LLM prompt built with f-string from user input | Prompt injection vector | `SI-10` | CRITICAL |
| Model weights in plaintext config fields | Model stored unencrypted | `SC-28` | HIGH |

### Gate 18 — Container Security (`container`)
**NIST:** CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3

Patterns organized by group (primary control ID per pattern):

**Image Integrity (→ `SI-7`)**
- `FROM <image>:latest` — unpinned latest tag (HIGH)
- `FROM <image>` with no tag — untagged base image (HIGH)
- `ADD https?://` — remote ADD without verification (HIGH)

**Least Privilege (→ `AC-6`)**
- `USER root` — container runs as root (CRITICAL)
- `--privileged` flag — full host access (CRITICAL)
- `--cap-add ALL` / `--cap-add SYS_ADMIN` — dangerous capabilities (CRITICAL/HIGH)
- `allowPrivilegeEscalation: true` — escalation permitted (HIGH)
- `runAsNonRoot: false` — root explicitly allowed (HIGH)

**Network Isolation (→ `SC-7`)**
- `hostNetwork: true` — host network namespace (HIGH)
- `hostPort: <n>` — host port binding (MEDIUM)

**Runtime Hardening (→ `SC-39`)**
- `readOnlyRootFilesystem: false` — writable root FS (HIGH)
- `hostPID: true` — host process namespace (CRITICAL)
- `hostIPC: true` — host IPC namespace (CRITICAL)
- `seccompProfile.*Unconfined` — no seccomp (HIGH)

**Audit (→ `AU-12`)**
- `log_driver.*none` / `--log-driver=none` — logging disabled (HIGH)

**Resource Limits (→ `CM-6`)**
- `resources: {}` — no resource limits (MEDIUM)
- `--memory.*-1` — unlimited memory (MEDIUM)

---

## Supporting Changes

### `catalog.py` — `GATE_CONTROL_MAP` additions
```python
"deps":          ["RA-5", "SI-2", "SA-12"],
"api":           ["SC-8", "AC-3", "SC-5", "SI-10"],
"privacy":       ["PT-2", "PT-3", "SC-28"],
"resilience":    ["CP-9", "CP-10", "SI-13"],
"incident":      ["IR-4", "IR-6", "AU-6"],
"observability": ["SI-4", "AU-12"],
"memsafe":       ["SI-16", "CM-7"],
"license":       ["SA-4", "SR-3"],
"aiml":          ["SI-10", "SC-28", "SR-3"],
"container":     ["CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"],
```

### `gates/__init__.py` — `ALL_GATES` additions
```python
from controlgate.gates.deps_gate import DepsGate
from controlgate.gates.api_gate import APIGate
from controlgate.gates.privacy_gate import PrivacyGate
from controlgate.gates.resilience_gate import ResilienceGate
from controlgate.gates.incident_gate import IncidentGate
from controlgate.gates.observability_gate import ObservabilityGate
from controlgate.gates.memsafe_gate import MemSafeGate
from controlgate.gates.license_gate import LicenseGate
from controlgate.gates.aiml_gate import AIMLGate
from controlgate.gates.container_gate import ContainerGate
```

---

## Testing Strategy

Each gate gets a `tests/test_gates/test_<gate_id>_gate.py` file following the existing pattern:
- One positive test per major pattern group (detects the violation)
- One negative test (clean code returns no findings)
- One test asserting `gate_id` on all findings
- One test asserting `control_id` is from the gate's `mapped_control_ids`

---

## Out of Scope

- Live CVE lookup for `deps` gate (requires network call)
- Enhancement control IDs like `AC-6(1)`, `CM-7(2)` as primary — these are noted in remediation text only, since catalog lookup falls back gracefully if the enhancement ID isn't present
- Changes to engine, reporters, models, or config system
