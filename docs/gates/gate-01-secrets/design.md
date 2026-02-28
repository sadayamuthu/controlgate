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
