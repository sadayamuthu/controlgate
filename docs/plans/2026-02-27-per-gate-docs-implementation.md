# Per-Gate Documentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reverse-engineer all 18 security gates into individual `design.md` + `implementation.md` files under `docs/gates/gate-NN-<id>/`.

**Architecture:** Pure documentation — no code changes, no tests. Each task creates one gate folder with two files, then commits. Content is reverse-engineered from the gate source file. Source of truth is the gate `.py` file, not prior plan docs.

**Tech Stack:** Markdown, Python source reading only. Run no tests. Commit with `git add docs/gates/... && git commit`.

---

## Reference

Design spec: `docs/plans/2026-02-27-per-gate-docs-design.md`

Templates are defined there. Quick summary:

**`design.md`** — for compliance/security reviewers:
- Purpose (1 paragraph)
- What This Gate Detects (table: detection | why it matters | NIST control)
- Scope (what lines/files scanned, special detection)
- Known Limitations
- NIST Control Mapping (table: control ID | title | how addressed)

**`implementation.md`** — for developers:
- Header (source file, test file, class, gate_id, mapped_control_ids)
- Scan Method (how scan() works)
- Patterns (table: # | regex | description | control | remediation)
- Special Detection Logic (only if gate has logic beyond standard pattern loop)
- Known Debt / Deferred Patterns (only if applicable)
- Test Coverage (table: test name | what it verifies)

---

## Task 1: Directory scaffold + Gate 1 — Secrets

**Files to create:**
- `docs/gates/gate-01-secrets/design.md`
- `docs/gates/gate-01-secrets/implementation.md`

**Source:** `src/controlgate/gates/secrets_gate.py`
**Test file:** `tests/test_gates/test_secrets_gate.py`

### Step 1: Create `docs/gates/gate-01-secrets/design.md`

```markdown
# Gate 1 — Secrets & Credential Gate

**gate_id:** `secrets`
**NIST Controls:** IA-5, IA-6, SC-12, SC-28
**Priority:** 🔴 High

---

## Purpose

Prevents hardcoded secrets, API keys, tokens, and private keys from being committed to source control. Credentials committed to git are permanently exposed in history, even after removal, and are a leading cause of cloud account compromise. This gate provides an automated pre-commit tripwire for the most common credential formats used across AWS, GCP, GitHub, OpenAI, Stripe, and database connection strings.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| AWS Access Key ID (AKIA/ASIA format) | Direct cloud account takeover | IA-5 |
| AWS Secret Access Key (40-char base64) | Paired with key ID enables full AWS API access | IA-5 |
| Google API Key (AIza prefix) | Unauthorized GCP service usage and billing fraud | IA-5 |
| Hardcoded credential assignment (`password =`, `token =`, etc.) | Generic pattern catches language-agnostic credential leaks | SC-28 |
| Private key files (RSA, EC, DSA, OpenSSH) | Key compromise enables impersonation and decryption of historical traffic | SC-12 |
| X.509 certificate files | Certificates in repos risk unauthorized service impersonation | SC-12 |
| GitHub Personal Access Tokens (ghp_ prefix) | Repo access, Actions secrets, and org data at risk | IA-5 |
| API secret keys (sk- prefix) | OpenAI/Stripe-style keys enabling fraudulent API usage | IA-5 |
| Bearer tokens in source code | Runtime tokens should not appear in code | IA-6 |
| Database connection strings with embedded credentials | Leaks DB host, port, username, and password | SC-28 |
| High-entropy quoted strings ≥20 chars | Catches randomized secrets not matching known formats | IA-5 |
| Sensitive file types committed (.env, .pem, .key, .p12, .pfx, .jks) | Entire file classes should never appear in source control | SC-28 |

---

## Scope

- **Scans:** all added lines in every file in the diff
- **File types targeted:** all files; additionally performs file-path checks for sensitive file extensions
- **Special detection:** Shannon entropy analysis — any quoted string ≥20 characters with entropy ≥4.5 bits/char is flagged even if it doesn't match a known pattern. Evidence is truncated to 120 characters.

---

## Known Limitations

- Does not scan deleted or unmodified lines
- Entropy detection produces false positives on long base64-encoded non-secret values (e.g., public keys, checksums)
- Known secret formats are a subset of real-world credential types; novel formats require new patterns
- Will not detect secrets stored in binary files

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| IA-5 | Authenticator Management | Detects hardcoded passwords, tokens, and API keys that should be managed through a secrets manager |
| IA-6 | Authentication Feedback | Detects bearer tokens embedded in source code where they may be logged or exposed |
| SC-12 | Cryptographic Key Establishment and Management | Detects private keys and certificates committed to repositories |
| SC-28 | Protection of Information at Rest | Detects credentials and sensitive file types that expose data-at-rest protection keys |
```

### Step 2: Create `docs/gates/gate-01-secrets/implementation.md`

```markdown
# Gate 1 — Secrets & Credential Gate: Implementation Reference

**Source file:** `src/controlgate/gates/secrets_gate.py`
**Test file:** `tests/test_gates/test_secrets_gate.py`
**Class:** `SecretsGate`
**gate_id:** `secrets`
**mapped_control_ids:** `["IA-5", "IA-6", "SC-12", "SC-28"]`

---

## Scan Method

`scan()` iterates every `diff_file` and calls two sub-methods:
1. `_check_sensitive_file()` — matches the file path against `_SENSITIVE_FILE_PATTERNS`; fires one SC-28 finding per file if the path matches
2. `_check_line()` — for each added line, runs all `_PATTERNS` regex matches, then runs Shannon entropy analysis on any quoted string ≥20 chars

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?:AKIA\|ASIA)[0-9A-Z]{16}` | AWS Access Key ID detected | IA-5 | Use IAM roles or AWS Secrets Manager |
| 2 | `(?:"\|')(?:[A-Za-z0-9/+=]{40})(?:"\|')` | Possible AWS Secret Access Key detected | IA-5 | Use IAM roles or AWS Secrets Manager |
| 3 | `AIza[0-9A-Za-z\-_]{35}` | Google API Key detected | IA-5 | Use GCP Secret Manager or env vars |
| 4 | `(?i)(?:password\|passwd\|pwd\|secret\|token\|api[_-]?key\|auth[_-]?token\|access[_-]?token)\s*[:=]\s*["'][^"']{4,}["']` | Hardcoded credential detected | SC-28 | Use env var or secrets manager |
| 5 | `(?i)(?:password\|passwd\|pwd\|secret\|token\|api[_-]?key)\s*=\s*(?!None\|null\|""\|''\|os\.environ\|env\(\|getenv)[^\s#]{4,}` | Hardcoded credential in assignment | SC-28 | Use env var or secrets manager |
| 6 | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` | Private key committed to repository | SC-12 | Use secrets manager; never commit keys |
| 7 | `-----BEGIN CERTIFICATE-----` | Certificate file committed | SC-12 | Manage via PKI or secrets manager |
| 8 | `ghp_[0-9a-zA-Z]{36}` | GitHub Personal Access Token | IA-5 | Use GitHub Apps or GITHUB_TOKEN |
| 9 | `sk-[0-9a-zA-Z]{20,}` | API secret key (OpenAI/Stripe pattern) | IA-5 | Use env vars or secrets manager |
| 10 | `(?i)bearer\s+[a-z0-9\-._~+/]+=*` | Bearer token in source code | IA-6 | Load from environment or config |
| 11 | `(?i)(?:mongodb\|postgres(?:ql)?\|mysql\|redis\|amqp)://[^\s:]+:[^\s@]+@` | DB connection string with embedded credentials | SC-28 | Use env vars for connection strings |

**Sensitive file path patterns (checked against `diff_file.path`):**
- `\.env(?:\..+)?$`
- `(?i)credentials`
- `(?i)\.pem$`
- `(?i)\.key$`
- `(?i)\.p12$`
- `(?i)\.pfx$`
- `(?i)\.jks$`

---

## Special Detection Logic

**Shannon entropy analysis** (`_check_line`, after pattern loop):
- Scans every added line for quoted strings matching `["']([A-Za-z0-9+/=\-_]{20,})["']`
- For each candidate string of length ≥20: computes Shannon entropy
- Fires an IA-5 finding if entropy ≥4.5 bits/char AND no finding already exists for that line
- Avoids duplicate findings: checks if a pattern-based finding already fired on the same line number

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_aws_key` | AKIA/ASIA format AWS key |
| `test_detects_hardcoded_password` | `password = "..."` assignment |
| `test_detects_private_key` | `-----BEGIN RSA PRIVATE KEY-----` |
| `test_clean_code_no_findings` | Safe code produces zero findings |
| `test_detects_sensitive_file` | `.env` file path triggers finding |
| `test_detects_high_entropy_string` | Long random string triggers entropy detection |
| `test_findings_have_gate_id` | All findings carry `gate == "secrets"` |
| `test_findings_have_valid_control_ids` | All findings use IA-5, IA-6, SC-12, or SC-28 |
```

### Step 3: Commit

```bash
git add docs/gates/gate-01-secrets/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 1 — Secrets design and implementation reference"
```

---

## Task 2: Gate 2 — Crypto

**Files to create:**
- `docs/gates/gate-02-crypto/design.md`
- `docs/gates/gate-02-crypto/implementation.md`

**Source:** `src/controlgate/gates/crypto_gate.py`
**Test file:** `tests/test_gates/test_crypto_gate.py`

**Key facts:**
- Class: `CryptoGate` | gate_id: `crypto` | Controls: SC-8, SC-13, SC-17, SC-23
- Three pattern groups: `_WEAK_ALGO_PATTERNS` (SC-13), `_TLS_PATTERNS` (SC-8/SC-17), `_SESSION_PATTERNS` (SC-23)
- Weak algorithms: MD5, SHA-1, DES, RC4, 3DES, Blowfish, ECB mode
- TLS patterns: bare http:// URLs (non-localhost), ssl_verify=False, verify=False, CERT_NONE/CERT_OPTIONAL, check_hostname=False, self-signed references, TLSv1.0/SSLv2/SSLv3
- Session patterns: secure=False on cookies, SameSite=None
- Scan method: standard pattern loop across 3 groups; no special logic

### Step 1: Write `design.md` covering:
- Purpose: detect weak crypto algorithms, disabled TLS verification, deprecated protocol versions, and insecure session cookie configuration
- Detections table covering all three groups
- Scope: all added lines, all file types
- Limitations: does not detect correct key length (only algorithm name), no cross-call analysis
- NIST mapping: SC-8 (transmission confidentiality), SC-13 (approved cryptography), SC-17 (PKI certificates), SC-23 (session authenticity)

### Step 2: Write `implementation.md` covering:
- All patterns from the three groups with their control IDs
- Note that `_WEAK_ALGO_PATTERNS` tuples have only 3 fields (pattern, description, remediation) — control ID is hardcoded as SC-13 in `_check_line`

### Step 3: Commit
```bash
git add docs/gates/gate-02-crypto/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 2 — Crypto design and implementation reference"
```

---

## Task 3: Gate 3 — IAM

**Files to create:**
- `docs/gates/gate-03-iam/design.md`
- `docs/gates/gate-03-iam/implementation.md`

**Source:** `src/controlgate/gates/iam_gate.py`
**Test file:** `tests/test_gates/test_iam_gate.py`

**Key facts:**
- Class: `IAMGate` | gate_id: `iam` | Controls: AC-3, AC-4, AC-5, AC-6
- Single `_IAM_PATTERNS` list: 10 patterns
- Detections: wildcard IAM Action (`"*"`), wildcard Resource (`"*"`), Allow+Action=*, AdministratorAccess/PowerUserAccess managed policies, AdministratorAccess ARN (AC-5 separation of duties), wildcard CORS origin (AC-4), allow_origins=[`*`] (AC-4), Flask route without auth decorator (AC-3), explicit auth bypass keywords (AC-3), STS AssumeRole (AC-3)
- Scan method: standard pattern loop; no file-type filtering

### Step 1: Write `design.md` covering:
- Purpose: detect overly permissive IAM policies, missing authorization, and wildcard access grants in IaC, application code, and API config
- Detections table for all 10 patterns
- Scope: all added lines, all file types
- Limitations: route-decorator check is heuristic (only detects `@app.route` without decorators on the same line); cannot verify whether a named auth decorator is actually enforced
- NIST mapping: AC-3 (access enforcement), AC-4 (info flow), AC-5 (separation of duties), AC-6 (least privilege)

### Step 2: Write `implementation.md`
- Full patterns table (10 rows)

### Step 3: Commit
```bash
git add docs/gates/gate-03-iam/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 3 — IAM design and implementation reference"
```

---

## Task 4: Gate 4 — SBOM

**Files to create:**
- `docs/gates/gate-04-sbom/design.md`
- `docs/gates/gate-04-sbom/implementation.md`

**Source:** `src/controlgate/gates/sbom_gate.py`
**Test file:** `tests/test_gates/test_sbom_gate.py`

**Key facts:**
- Class: `SBOMGate` | gate_id: `sbom` | Controls: SR-3, SR-11, SA-10, SA-11
- Three detection mechanisms:
  1. **Cross-file check (SR-3):** if a manifest file (package.json, requirements.txt, go.mod, etc.) is modified but no corresponding lockfile appears in the same diff, fires a finding
  2. **Pipeline file flag (SA-10):** if a CI/CD or build file (Dockerfile, .github/workflows/*.yml, Jenkinsfile, etc.) appears in the diff, fires a review-required finding
  3. **Unpinned version patterns (SR-11):** `>=`, `~=`, `:*`, `:latest`, `:\^` on added lines
  4. **Test coverage weakening (SA-11):** coverage threshold modification, skip-test patterns
- Manifest-to-lockfile map: package.json→{package-lock.json,yarn.lock,pnpm-lock.yaml}, requirements.txt→{requirements.lock,Pipfile.lock,poetry.lock}, pyproject.toml→{poetry.lock,uv.lock,pdm.lock}, go.mod→go.sum, Cargo.toml→Cargo.lock, Gemfile→Gemfile.lock, composer.json→composer.lock

### Step 1: Write `design.md` covering:
- Purpose: prevent unreviewed supply chain changes — unpinned dependencies, pipeline modifications, and manifest-without-lockfile changes
- Detections table covering all four mechanisms
- Scope: cross-file analysis for lockfile check; all added lines for version/test patterns; file-path check for pipeline files
- Limitations: lockfile cross-check uses basename matching, so renaming a lockfile fools it; does not scan binary lockfiles
- NIST mapping: SR-3 (supply chain controls), SR-11 (component authenticity), SA-10 (developer config management), SA-11 (developer testing)

### Step 2: Write `implementation.md` with special note on the cross-file lockfile logic

### Step 3: Commit
```bash
git add docs/gates/gate-04-sbom/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 4 — SBOM design and implementation reference"
```

---

## Task 5: Gate 5 — IaC

**Files to create:**
- `docs/gates/gate-05-iac/design.md`
- `docs/gates/gate-05-iac/implementation.md`

**Source:** `src/controlgate/gates/iac_gate.py`
**Test file:** `tests/test_gates/test_iac_gate.py`

**Key facts:**
- Class: `IaCGate` | gate_id: `iac` | Controls: CM-2, CM-6, CM-7, SC-7
- **File-type filter**: only scans IaC files — `.tf`, `.tfvars`, `.hcl`, `.yaml`, `.yml`, `.json`, `Dockerfile`, and paths containing `terraform/`, `infra/`, `infrastructure/`, `deploy/`, `k8s/`, `kubernetes/`, `helm/`, `.github/`, `cloudformation/`, `cdk/`
- 14 patterns: 0.0.0.0/0 ingress (SC-7), ::/0 ingress (SC-7), public ACL on storage (SC-7), S3 block_public_acls=false (SC-7), root/privileged container (CM-6), empty securityContext (CM-6), allowPrivilegeEscalation=true (CM-6), hostNetwork=true (CM-7), hostPID/hostIPC=true (CM-7), empty resources block (CM-6), sensitive ports exposed (CM-7), encryption disabled (CM-6), logging disabled (CM-6), versioning disabled (CM-2)

### Step 1: Write `design.md` — note the file-type filtering in Scope section

### Step 2: Write `implementation.md` — document `_is_iac_file()` logic in Special Detection Logic section

### Step 3: Commit
```bash
git add docs/gates/gate-05-iac/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 5 — IaC design and implementation reference"
```

---

## Task 6: Gate 6 — Input Validation

**Files to create:**
- `docs/gates/gate-06-input-validation/design.md`
- `docs/gates/gate-06-input-validation/implementation.md`

**Source:** `src/controlgate/gates/input_gate.py`
**Test file:** `tests/test_gates/test_input_gate.py`

**Key facts:**
- Class: `InputGate` | gate_id: `input_validation` | Controls: SI-7, SI-10, SI-11, SI-16
- 15 patterns in a single `_INPUT_PATTERNS` list
- Detection groups: SQL injection via f-string/format()/%/concatenation (SI-10), eval()/exec()/subprocess+shell=True/os.system()/os.popen() (SI-10), pickle.loads/yaml.load unsafe (SI-10), bare except:pass/traceback exposure/debug=True (SI-11), download without integrity verification (SI-7), strcpy/strcat/sprintf/gets C functions (SI-16)
- Standard pattern loop; no file-type filtering

### Step 1: Write `design.md`

### Step 2: Write `implementation.md` with 15-row patterns table

### Step 3: Commit
```bash
git add docs/gates/gate-06-input-validation/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 6 — Input Validation design and implementation reference"
```

---

## Task 7: Gate 7 — Audit

**Files to create:**
- `docs/gates/gate-07-audit/design.md`
- `docs/gates/gate-07-audit/implementation.md`

**Source:** `src/controlgate/gates/audit_gate.py`
**Test file:** `tests/test_gates/test_audit_gate.py`

**Key facts:**
- Class: `AuditGate` | gate_id: `audit` | Controls: AU-2, AU-3, AU-12
- **Three detection methods:**
  1. `_check_removed_logging()` — scans `hunk.removed_lines` for logging statements (AU-12); this is one of only two gates that reads REMOVED lines
  2. `_check_auth_logging()` — for each hunk, checks if an auth function name (login, logout, authenticate, etc.) appears in added lines WITHOUT an accompanying log statement in the same hunk (AU-2)
  3. `_check_pii_in_logs()` — pattern scan of added lines for PII keywords inside log/print calls (AU-3)
- PII patterns: SSN/SIN, passwords/tokens, credit cards, date of birth — all in log context

### Step 1: Write `design.md` — highlight removed-line detection as a special capability (unlike most gates)

### Step 2: Write `implementation.md` — document all three methods in Special Detection Logic

### Step 3: Commit
```bash
git add docs/gates/gate-07-audit/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 7 — Audit design and implementation reference"
```

---

## Task 8: Gate 8 — Change Control

**Files to create:**
- `docs/gates/gate-08-change-control/design.md`
- `docs/gates/gate-08-change-control/implementation.md`

**Source:** `src/controlgate/gates/change_gate.py`
**Test file:** `tests/test_gates/test_change_gate.py`

**Key facts:**
- Class: `ChangeGate` | gate_id: `change_control` | Controls: CM-3, CM-4, CM-5
- **File-path based detection (not line content):**
  - `_SECURITY_CRITICAL_FILES` regex flags .github/workflows, CODEOWNERS, Dockerfile, docker-compose, .env, terraform/*.tf, deploy/, k8s/, CI pipeline files (CM-3)
  - `_DEPLOY_CONFIG_FILES` regex flags helm/values*.yml, terraform/*.tfvars, ansible/, pulumi/ (CM-4)
  - Hard-coded CODEOWNERS path check (CM-5)
- One line-content pattern: `branch.?protection` keyword in added lines (CM-5)

### Step 1: Write `design.md` — emphasize that most detections are file-path based, not content-based

### Step 2: Write `implementation.md` — document the two file-path regexes and the CODEOWNERS path check in Special Detection Logic

### Step 3: Commit
```bash
git add docs/gates/gate-08-change-control/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 8 — Change Control design and implementation reference"
```

---

## Task 9: Gate 9 — Deps

**Files to create:**
- `docs/gates/gate-09-deps/design.md`
- `docs/gates/gate-09-deps/implementation.md`

**Source:** `src/controlgate/gates/deps_gate.py`
**Test file:** `tests/test_gates/test_deps_gate.py`

**Key facts:**
- Class: `DepsGate` | gate_id: `deps` | Controls: RA-5, SI-2, SA-12
- 5 patterns: --no-verify bypass (SA-12), --ignore-scripts (SA-12), http:// package registry URL (SI-2), pip install with range specifier (RA-5), pip install without pinned version (RA-5)
- Standard pattern loop; no file-type filtering

### Step 1: Write `design.md`

### Step 2: Write `implementation.md`

### Step 3: Commit
```bash
git add docs/gates/gate-09-deps/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 9 — Deps design and implementation reference"
```

---

## Task 10: Gate 10 — API Security

**Files to create:**
- `docs/gates/gate-10-api/design.md`
- `docs/gates/gate-10-api/implementation.md`

**Source:** `src/controlgate/gates/api_gate.py`
**Test file:** `tests/test_gates/test_api_gate.py`

**Key facts:**
- Class: `APIGate` | gate_id: `api` | Controls: SC-8, AC-3, SC-5, SI-10
- 6 patterns: verify=False (SC-8), CORS_ORIGIN_ALLOW_ALL/allow_all_origins=True (AC-3), Access-Control-Allow-Origin:* header (AC-3), Access-Control-Allow-Credentials:true (AC-3), API key in URL query param (SC-8), GraphQL introspection/GraphiQL enabled (AC-3)
- Standard pattern loop
- Note: SC-5 (DoS protection) and SI-10 (input validation) are in `mapped_control_ids` per design spec but no patterns currently fire those specific control IDs — the existing 6 patterns all fire SC-8 or AC-3

### Step 1: Write `design.md` — note SC-5/SI-10 are mapped but not directly triggered by current patterns

### Step 2: Write `implementation.md`

### Step 3: Commit
```bash
git add docs/gates/gate-10-api/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 10 — API Security design and implementation reference"
```

---

## Task 11: Gate 11 — Privacy

**Files to create:**
- `docs/gates/gate-11-privacy/design.md`
- `docs/gates/gate-11-privacy/implementation.md`

**Source:** `src/controlgate/gates/privacy_gate.py`
**Test file:** `tests/test_gates/test_privacy_gate.py`

**Key facts:**
- Class: `PrivacyGate` | gate_id: `privacy` | Controls: PT-2, PT-3, SC-28
- 4 patterns: PII field name in logging/print (PT-3), serialize_all_fields=True (PT-2), expires_at=None/ttl=0 (SC-28), PII field in plaintext DB column definition (SC-28)
- PII field keywords shared via `_PII_FIELDS` string: ssn, social security, date of birth, dob, credit card, cvv, passport, driver's license
- Standard pattern loop

### Step 1: Write `design.md`

### Step 2: Write `implementation.md`

### Step 3: Commit
```bash
git add docs/gates/gate-11-privacy/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 11 — Privacy design and implementation reference"
```

---

## Task 12: Gate 12 — Resilience

**Files to create:**
- `docs/gates/gate-12-resilience/design.md`
- `docs/gates/gate-12-resilience/implementation.md`

**Source:** `src/controlgate/gates/resilience_gate.py`
**Test file:** `tests/test_gates/test_resilience_gate.py`

**Key facts:**
- Class: `ResilienceGate` | gate_id: `resilience` | Controls: CP-9, CP-10, SI-13
- 5 patterns: deletion_protection=false (CP-9), backup=false (CP-9), skip_final_snapshot=true (CP-9), max_retries=0 (SI-13), backup_retention_period=0 (CP-9)
- Standard pattern loop
- Known debt: CP-10 (system recovery) — design spec included `connect_timeout` absence detection but this requires negative/absence detection not supported by the added-lines model

### Step 1: Write `design.md`

### Step 2: Write `implementation.md` — include Known Debt section for CP-10 connect_timeout

### Step 3: Commit
```bash
git add docs/gates/gate-12-resilience/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 12 — Resilience design and implementation reference"
```

---

## Task 13: Gate 13 — Incident Response

**Files to create:**
- `docs/gates/gate-13-incident/design.md`
- `docs/gates/gate-13-incident/implementation.md`

**Source:** `src/controlgate/gates/incident_gate.py`
**Test file:** `tests/test_gates/test_incident_gate.py`

**Key facts:**
- Class: `IncidentGate` | gate_id: `incident` | Controls: IR-4, IR-6, AU-6
- 4 patterns: bare `except:` clause (IR-4), empty JS/TS/Java catch block (IR-4), traceback.print_exc()/traceback.format_exc() exposure (IR-4), notify:false/notifications_enabled=false (IR-6)
- AU-6 (audit review/analysis) is in `mapped_control_ids` but no pattern directly fires it; AU-6 coverage is implicit via the incident detection patterns
- Standard pattern loop

### Step 1: Write `design.md`

### Step 2: Write `implementation.md` — note AU-6 in Known Limitations (mapped but implicit)

### Step 3: Commit
```bash
git add docs/gates/gate-13-incident/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 13 — Incident Response design and implementation reference"
```

---

## Task 14: Gate 14 — Observability

**Files to create:**
- `docs/gates/gate-14-observability/design.md`
- `docs/gates/gate-14-observability/implementation.md`

**Source:** `src/controlgate/gates/observability_gate.py`
**Test file:** `tests/test_gates/test_observability_gate.py`

**Key facts:**
- Class: `ObservabilityGate` | gate_id: `observability` | Controls: SI-4, AU-12
- 4 line-level patterns: enable_monitoring=false (SI-4), monitoring_interval=0 (SI-4), log driver=none (AU-12), --log-driver=none (AU-12)
- **Special logic:** For files matching `(?i)(?:deployment|statefulset|daemonset).*\.ya?ml$`, scans `diff_file.full_content` (not just added lines) for `livenessProbe`; if `containers:` is present but no `livenessProbe`, fires SI-4 finding
- Known debt: design spec included DLQ resource deletion detection but that requires scanning removed lines

### Step 1: Write `design.md` — describe the K8s liveness probe check in Scope

### Step 2: Write `implementation.md` — document the `full_content` probe check in Special Detection Logic; include Known Debt for DLQ deletion pattern

### Step 3: Commit
```bash
git add docs/gates/gate-14-observability/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 14 — Observability design and implementation reference"
```

---

## Task 15: Gate 15 — Memory Safety

**Files to create:**
- `docs/gates/gate-15-memsafe/design.md`
- `docs/gates/gate-15-memsafe/implementation.md`

**Source:** `src/controlgate/gates/memsafe_gate.py`
**Test file:** `tests/test_gates/test_memsafe_gate.py`

**Key facts:**
- Class: `MemSafeGate` | gate_id: `memsafe` | Controls: SI-16, CM-7
- 7 patterns: eval() with dynamic arg (SI-16), exec() (SI-16), unsafe Rust block (CM-7), ctypes raw memory ops (SI-16), cffi ffi.cast/buffer/from_buffer/memmove (SI-16), strcpy/strcat (SI-16), memcpy with user input (SI-16)
- Note on cffi pattern: uses `(?<!\w)` negative lookbehind to avoid false positives on variables like `audio_ffi.cast()`
- Standard pattern loop

### Step 1: Write `design.md`

### Step 2: Write `implementation.md` — note the word-boundary guard on the cffi pattern

### Step 3: Commit
```bash
git add docs/gates/gate-15-memsafe/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 15 — Memory Safety design and implementation reference"
```

---

## Task 16: Gate 16 — License

**Files to create:**
- `docs/gates/gate-16-license/design.md`
- `docs/gates/gate-16-license/implementation.md`

**Source:** `src/controlgate/gates/license_gate.py`
**Test file:** `tests/test_gates/test_license_gate.py`

**Key facts:**
- Class: `LicenseGate` | gate_id: `license` | Controls: SA-4, SR-3
- Two pattern objects (not a `_PATTERNS` list — unique structure):
  - `_COPYLEFT_PATTERN`: `(?i)\b(?:GPL|AGPL|SSPL|LGPL|GNU\s+(?:General|Affero|Lesser))\b` — only fires for manifest files (SA-4)
  - `_SPDX_COPYLEFT`: `SPDX-License-Identifier:\s*(?:GPL|AGPL|SSPL|LGPL|EUPL|OSL|CDDL)` — fires for any source file (SR-3)
- Manifest file detection: `_MANIFEST_FILES` regex matches requirements*.txt, package.json, go.mod, Cargo.toml, Gemfile, composer.json, setup.cfg, pyproject.toml
- Copyleft keyword in non-manifest files is intentionally NOT flagged (to avoid false positives in comments)
- Known debt: design spec included license header removal detection, but requires scanning removed lines

### Step 1: Write `design.md` — explain the manifest-only restriction for copyleft keywords

### Step 2: Write `implementation.md` — describe the dual-pattern + manifest-file-check logic in Special Detection Logic; include Known Debt for license header removal

### Step 3: Commit
```bash
git add docs/gates/gate-16-license/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 16 — License Compliance design and implementation reference"
```

---

## Task 17: Gate 17 — AI/ML Security

**Files to create:**
- `docs/gates/gate-17-aiml/design.md`
- `docs/gates/gate-17-aiml/implementation.md`

**Source:** `src/controlgate/gates/aiml_gate.py`
**Test file:** `tests/test_gates/test_aiml_gate.py`

**Key facts:**
- Class: `AIMLGate` | gate_id: `aiml` | Controls: SI-10, SC-28, SR-3
- 6 patterns: trust_remote_code=True (SR-3), pickle.load/pickle.loads (SI-10), joblib.load (SI-10), http:// model/weights URL (SR-3), f-string with user/input/request/query/prompt variables (SI-10), model_path/weights_path/checkpoint_path/model_weights assigned to string literal (SC-28)
- Standard pattern loop
- Known limitation: commented-out config lines fire the SC-28 pattern (accepted trade-off, documented in test file)

### Step 1: Write `design.md` — include the comment-line limitation in Known Limitations

### Step 2: Write `implementation.md`

### Step 3: Commit
```bash
git add docs/gates/gate-17-aiml/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 17 — AI/ML Security design and implementation reference"
```

---

## Task 18: Gate 18 — Container Security

**Files to create:**
- `docs/gates/gate-18-container/design.md`
- `docs/gates/gate-18-container/implementation.md`

**Source:** `src/controlgate/gates/container_gate.py`
**Test file:** `tests/test_gates/test_container_gate.py`

**Key facts:**
- Class: `ContainerGate` | gate_id: `container` | Controls: CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3
- **Six pattern groups** (each is a separate module-level list):
  - `_IMAGE_PATTERNS` (SI-7): FROM :latest, FROM with no tag, ADD https://
  - `_PRIVILEGE_PATTERNS` (AC-6): USER root, privileged:true, --cap-add ALL, --cap-add SYS_ADMIN/SYS_PTRACE/NET_ADMIN, allowPrivilegeEscalation:true, runAsNonRoot:false
  - `_NETWORK_PATTERNS` (SC-7): hostNetwork:true, hostPort:N
  - `_RUNTIME_PATTERNS` (SC-39): readOnlyRootFilesystem:false, hostPID:true, hostIPC:true, seccomp Unconfined
  - `_AUDIT_PATTERNS` (AU-12): log driver none (docker-compose), --log-driver=none
  - `_RESOURCE_PATTERNS` (CM-6): resources:{}, --memory=-1
- scan() iterates all pattern groups in `_ALL_PATTERN_GROUPS`; no file-type filtering

### Step 1: Write `design.md` — organize detections table by domain (image integrity, privilege, network, runtime, audit, resources)

### Step 2: Write `implementation.md` — use sub-sections per group in the Patterns table

### Step 3: Commit
```bash
git add docs/gates/gate-18-container/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: add Gate 18 — Container Security design and implementation reference"
```

---

## Task 19: Final verification

### Step 1: Verify all 36 files exist

```bash
find docs/gates -name "*.md" | sort
```

Expected: 36 files — `design.md` and `implementation.md` in each of 18 gate folders.

### Step 2: Verify all required sections are present in each file

```bash
for f in docs/gates/*/design.md; do
  echo "=== $f ==="
  grep "^## " "$f"
done
```

Each `design.md` should show: Purpose, What This Gate Detects, Scope, Known Limitations, NIST Control Mapping.

```bash
for f in docs/gates/*/implementation.md; do
  echo "=== $f ==="
  grep "^## " "$f"
done
```

Each `implementation.md` should show at minimum: Scan Method, Patterns, Test Coverage.

### Step 3: Commit (only if any final corrections were needed)

```bash
git add docs/gates/ && PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: final corrections to per-gate documentation"
```

---

## Checklist

- [ ] Task 1: Gate 1 — Secrets (design.md + implementation.md)
- [ ] Task 2: Gate 2 — Crypto
- [ ] Task 3: Gate 3 — IAM
- [ ] Task 4: Gate 4 — SBOM
- [ ] Task 5: Gate 5 — IaC
- [ ] Task 6: Gate 6 — Input Validation
- [ ] Task 7: Gate 7 — Audit
- [ ] Task 8: Gate 8 — Change Control
- [ ] Task 9: Gate 9 — Deps
- [ ] Task 10: Gate 10 — API Security
- [ ] Task 11: Gate 11 — Privacy
- [ ] Task 12: Gate 12 — Resilience
- [ ] Task 13: Gate 13 — Incident Response
- [ ] Task 14: Gate 14 — Observability
- [ ] Task 15: Gate 15 — Memory Safety
- [ ] Task 16: Gate 16 — License Compliance
- [ ] Task 17: Gate 17 — AI/ML Security
- [ ] Task 18: Gate 18 — Container Security
- [ ] Task 19: Final verification — 36 files, all required sections present
