# Gate 1 — Secrets & Credential Gate: Implementation Reference

**Source file:** `src/controlgate/gates/secrets_gate.py`
**Test file:** `tests/test_gates/test_secrets_gate.py`
**Class:** `SecretsGate`
**gate_id:** `secrets`
**mapped_control_ids:** `["IA-5", "IA-6", "SC-12", "SC-28"]`

---

## Scan Method

`scan()` iterates every `diff_file` and calls two sub-methods:
1. `_check_sensitive_file()` — matches the file path against `_SENSITIVE_FILE_PATTERNS`; fires one SC-28 finding per file if the path matches (breaks after first match per file)
2. `_check_line()` — for each added line, runs all `_PATTERNS` regex matches, then runs Shannon entropy analysis on any quoted string ≥20 chars

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?:AKIA\|ASIA)[0-9A-Z]{16}` | AWS Access Key ID detected | IA-5 | Use IAM roles or AWS Secrets Manager instead of hardcoded keys |
| 2 | `(?:"\|')(?:[A-Za-z0-9/+=]{40})(?:"\|')` | Possible AWS Secret Access Key detected | IA-5 | Use IAM roles or AWS Secrets Manager instead of hardcoded keys |
| 3 | `AIza[0-9A-Za-z\-_]{35}` | Google API Key detected | IA-5 | Use GCP Secret Manager or environment variables |
| 4 | `(?i)(?:password\|passwd\|pwd\|secret\|token\|api[_-]?key\|auth[_-]?token\|access[_-]?token)\s*[:=]\s*["'][^"']{4,}["']` | Hardcoded credential detected | SC-28 | Move to environment variable or secrets manager (AWS SSM, GCP Secret Manager, Azure Key Vault) |
| 5 | `(?i)(?:password\|passwd\|pwd\|secret\|token\|api[_-]?key)\s*=\s*(?!None\|null\|""\|''\|os\.environ\|env\(\|getenv)[^\s#]{4,}` | Hardcoded credential in assignment | SC-28 | Move to environment variable or secrets manager |
| 6 | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` | Private key committed to repository | SC-12 | Never commit private keys. Use a secrets manager or secure key storage |
| 7 | `-----BEGIN CERTIFICATE-----` | Certificate file committed to repository | SC-12 | Manage certificates through a PKI or secrets manager, not source control |
| 8 | `ghp_[0-9a-zA-Z]{36}` | GitHub Personal Access Token detected | IA-5 | Use GitHub Apps or GITHUB_TOKEN instead of personal access tokens |
| 9 | `sk-[0-9a-zA-Z]{20,}` | API secret key detected (OpenAI/Stripe pattern) | IA-5 | Use environment variables or a secrets manager for API keys |
| 10 | `(?i)bearer\s+[a-z0-9\-._~+/]+=*` | Bearer token detected in source code | IA-6 | Tokens should be loaded from environment or config, not hardcoded |
| 11 | `(?i)(?:mongodb\|postgres(?:ql)?\|mysql\|redis\|amqp)://[^\s:]+:[^\s@]+@` | Database connection string with embedded credentials | SC-28 | Use environment variables for connection strings with credentials |

**Sensitive file path patterns** (checked against `diff_file.path`, fires SC-28):

| Pattern | Matches |
|---|---|
| `\.env(?:\..+)?$` | `.env`, `.env.prod`, `.env.local`, etc. |
| `(?i)credentials` | Any file with "credentials" in name |
| `(?i)\.pem$` | PEM certificate/key files |
| `(?i)\.key$` | Key files |
| `(?i)\.p12$` | PKCS#12 key stores |
| `(?i)\.pfx$` | Personal Information Exchange files |
| `(?i)\.jks$` | Java KeyStore files |

---

## Special Detection Logic

**Shannon entropy analysis** — runs after the pattern loop in `_check_line()`:

1. Scans the line for quoted strings matching `["']([A-Za-z0-9+/=\-_]{20,})["']`
2. For each candidate token of length ≥20: computes Shannon entropy (bits per character)
3. If entropy ≥ 4.5 AND no finding from this gate already exists for that line number, fires an IA-5 finding
4. The duplicate-check prevents double-firing when a pattern already matched the same line

Constants: `_ENTROPY_THRESHOLD = 4.5`, `_MIN_LENGTH_FOR_ENTROPY = 20`

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_aws_key` | AKIA/ASIA format AWS access key triggers an IA-5 finding with "AWS" in the description |
| `test_detects_hardcoded_password` | `DB_PASSWORD = "super_secret_123"` assignment triggers a finding with "credential" or "password" in the description |
| `test_detects_private_key` | `-----BEGIN RSA PRIVATE KEY-----` header triggers a finding with "key" in the description |
| `test_clean_code_no_findings` | Code that reads credentials from `os.environ` produces zero findings |
| `test_detects_database_uri` | `postgres://user:pass@host/db` connection string triggers a finding with "connection string" or "credential" in the description |
| `test_detects_github_token` | `ghp_…` GitHub Personal Access Token pattern triggers at least one finding |
| `test_findings_have_gate_id` | Every finding from the AWS-key diff carries `gate == "secrets"` |
| `test_findings_have_control_ids` | Every finding from the AWS-key diff uses a control ID within `{IA-5, IA-6, SC-12, SC-28}` |
