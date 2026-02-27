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
3. If entropy ≥ 4.5 AND no finding already exists for that line number, fires an IA-5 finding
4. The duplicate-check prevents double-firing when a pattern already matched the same line

Constants: `_ENTROPY_THRESHOLD = 4.5`, `_MIN_LENGTH_FOR_ENTROPY = 20`

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_aws_key` | AKIA/ASIA format AWS access key triggers IA-5 finding |
| `test_detects_hardcoded_password` | `password = "secret123"` assignment triggers SC-28 |
| `test_detects_private_key` | `-----BEGIN RSA PRIVATE KEY-----` triggers SC-12 |
| `test_clean_code_no_findings` | Safe env-var-based code produces zero findings |
| `test_detects_sensitive_file` | `.env` file path triggers SC-28 finding |
| `test_detects_high_entropy_string` | Long random string triggers entropy-based IA-5 |
| `test_findings_have_gate_id` | All findings carry `gate == "secrets"` |
| `test_findings_have_valid_control_ids` | All findings use only IA-5, IA-6, SC-12, or SC-28 |
