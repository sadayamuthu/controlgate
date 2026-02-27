# Gate 2 — Cryptography & TLS Gate: Implementation Reference

**Source file:** `src/controlgate/gates/crypto_gate.py`
**Test file:** `tests/test_gates/test_crypto_gate.py`
**Class:** `CryptoGate`
**gate_id:** `crypto`
**mapped_control_ids:** `["SC-8", "SC-13", "SC-17", "SC-23"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the input list and calls `_check_line()` for each added line (via `diff_file.all_added_lines`). No file-type filter is applied — all files are scanned regardless of extension.

`_check_line()` runs three separate pattern loops in sequence across the three pattern groups:

1. `_WEAK_ALGO_PATTERNS` — 3-tuple `(pattern, description, remediation)`; the control ID is hardcoded as `"SC-13"` inside `_check_line()`.
2. `_TLS_PATTERNS` — 4-tuple `(pattern, description, control_id, remediation)`; control ID varies per pattern (SC-8 or SC-17).
3. `_SESSION_PATTERNS` — 4-tuple `(pattern, description, control_id, remediation)`; all patterns map to SC-23.

A single added line can produce multiple findings if it matches patterns from more than one group.

---

## Patterns

### Weak Algorithm Patterns (`_WEAK_ALGO_PATTERNS`) — all SC-13

Note: these tuples have only 3 fields; `SC-13` is hardcoded in `_check_line()` rather than stored in the tuple.

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)\b(?:hashlib\.)?md5\b` | Weak hash algorithm MD5 detected | SC-13 | Use SHA-256 or SHA-3 instead of MD5 (FIPS 180-4 compliant) |
| 2 | `(?i)\b(?:hashlib\.)?sha1\b` | Weak hash algorithm SHA-1 detected | SC-13 | Use SHA-256 or SHA-3 instead of SHA-1 (FIPS 180-4 compliant) |
| 3 | `(?i)\bDES\b(?!C|K|IGN)` | Weak cipher DES detected | SC-13 | Use AES-256 instead of DES |
| 4 | `(?i)\bRC4\b` | Weak cipher RC4 detected | SC-13 | Use AES-256 or ChaCha20 instead of RC4 |
| 5 | `(?i)\b3DES\b|triple.?des` | Weak cipher 3DES/TripleDES detected | SC-13 | Use AES-256 instead of 3DES |
| 6 | `(?i)\bBlowfish\b` | Weak cipher Blowfish detected | SC-13 | Use AES-256 or ChaCha20 instead of Blowfish |
| 7 | `(?i)ECB\b` | Insecure cipher mode ECB detected | SC-13 | Use CBC, GCM, or CTR mode instead of ECB |

### TLS / SSL Patterns (`_TLS_PATTERNS`)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 8 | `http://(?!localhost\|127\.0\.0\.1\|0\.0\.0\.0\|example\.com)` | Unencrypted HTTP URL in production code | SC-8 | Use HTTPS for all production endpoints to ensure transmission confidentiality |
| 9 | `(?i)ssl[_.]?verify\s*[:=]\s*(?:False\|false\|0\|no\|off)` | SSL/TLS verification disabled | SC-8 | Never disable SSL verification in production. Fix certificate issues instead |
| 10 | `(?i)verify\s*[:=]\s*(?:False\|false\|0)` | TLS certificate verification disabled | SC-8 | Never disable certificate verification in production code |
| 11 | `(?i)CERT_NONE|CERT_OPTIONAL` | Weak or disabled certificate validation | SC-17 | Use CERT_REQUIRED for all TLS connections |
| 12 | `(?i)check_hostname\s*[:=]\s*(?:False\|false\|0)` | TLS hostname checking disabled | SC-8 | Enable hostname checking for TLS connections |
| 13 | `(?i)self[_-]?signed\|selfsigned` | Self-signed certificate reference in production config | SC-17 | Use certificates from a trusted CA in production environments |
| 14 | `(?i)(?:TLSv1(?:\.0)?\|SSLv[23])\b` | Deprecated TLS/SSL version detected | SC-8 | Use TLS 1.2 or higher. TLS 1.0, 1.1, and all SSL versions are deprecated |

### Session / Cookie Patterns (`_SESSION_PATTERNS`)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 15 | `(?i)(?:session\|cookie).*(?:secure\s*[:=]\s*(?:False\|false\|0)\|httponly\s*[:=]\s*(?:False\|false\|0))` | Insecure session/cookie configuration | SC-23 | Set Secure=True, HttpOnly=True, and SameSite=Strict on session cookies |
| 16 | `(?i)samesite\s*[:=]\s*(?:["\']?none["\']?)` | SameSite=None on cookies reduces CSRF protection | SC-23 | Use SameSite=Strict or SameSite=Lax unless cross-site access is required |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_md5` | `hashlib.md5(...)` in an added line triggers a finding with "MD5" in the description |
| `test_detects_ssl_verify_false` | `requests.get(url, verify=False)` triggers at least one finding with "verification" or "ssl" in the description |
| `test_detects_http_url` | A non-local `http://` URL triggers at least one finding with "HTTP" in the description |
| `test_findings_have_crypto_gate_id` | Every finding produced by the MD5 diff carries `gate == "crypto"` |
