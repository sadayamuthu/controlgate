# Gate 2 — Cryptography & TLS Gate

**gate_id:** `crypto`
**NIST Controls:** SC-8, SC-13, SC-17, SC-23
**Priority:** 🔴 High

---

## Purpose

Gate 2 detects weak cryptographic algorithms, disabled TLS verification, deprecated protocol versions, and insecure session cookie configuration — preventing cryptographic failures that expose data in transit. By scanning all added lines at commit time, it catches dangerous patterns such as MD5/SHA-1 hash functions, DES/RC4/3DES/Blowfish/ECB ciphers, bare `http://` URLs, disabled certificate or hostname verification, deprecated TLS 1.0 and SSL versions, and misconfigured session cookies before they reach production systems.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| MD5 hash algorithm usage | MD5 is cryptographically broken; collisions are trivially producible, making it unsuitable for integrity or authentication | SC-13 |
| SHA-1 hash algorithm usage | SHA-1 is deprecated by NIST (FIPS 180-4); collision attacks have been demonstrated | SC-13 |
| DES cipher usage | DES has a 56-bit key space, broken in under 24 hours with commodity hardware | SC-13 |
| RC4 cipher usage | RC4 has known statistical biases and practical attacks; prohibited in TLS since RFC 7465 | SC-13 |
| 3DES/TripleDES cipher usage | 3DES is deprecated; susceptible to Sweet32 birthday attacks with long sessions | SC-13 |
| Blowfish cipher usage | Blowfish has a 64-bit block size making it vulnerable to Sweet32 attacks; no longer recommended | SC-13 |
| ECB cipher mode usage | ECB mode leaks data patterns through identical ciphertext blocks; deterministic encryption without semantic security | SC-13 |
| Unencrypted HTTP URLs (non-local) | Transmits data in cleartext over the network; susceptible to interception and man-in-the-middle attacks | SC-8 |
| SSL/TLS verification disabled (`ssl_verify=False`) | Disabling certificate verification eliminates protection against MITM attacks | SC-8 |
| TLS certificate verification disabled (`verify=False`) | Same as above; commonly set during development and inadvertently left in production | SC-8 |
| `CERT_NONE` or `CERT_OPTIONAL` in SSL context | Weak or absent certificate validation in Python ssl module | SC-17 |
| TLS hostname checking disabled (`check_hostname=False`) | Allows connections to any host with a valid certificate, defeating SNI-based security | SC-8 |
| Self-signed certificate references | Self-signed certificates in production bypass trusted CA validation | SC-17 |
| Deprecated TLS/SSL versions (TLSv1.0, SSLv2, SSLv3) | Deprecated versions have known vulnerabilities (POODLE, BEAST, DROWN); prohibited by PCI-DSS 3.2+ | SC-8 |
| Insecure session/cookie flags (`Secure=False`, `HttpOnly=False`) | Cookies without Secure can be transmitted over HTTP; cookies without HttpOnly are accessible to JavaScript | SC-23 |
| `SameSite=None` on cookies | Permits cross-site requests without CSRF token validation | SC-23 |

---

## Scope

- Scans all added lines in every file included in the diff
- Applies to all file types; no extension filter is applied
- Uses three internal pattern groups: `_WEAK_ALGO_PATTERNS` (7 patterns, SC-13), `_TLS_PATTERNS` (7 patterns, SC-8/SC-17), and `_SESSION_PATTERNS` (2 patterns, SC-23)
- All three groups are evaluated for every added line; a single line may produce multiple findings

---

## Known Limitations

- Does not evaluate key length or key strength — only the algorithm name is matched, so a correctly-sized AES key is not confirmed
- No cross-call analysis to confirm that HTTPS is actually used for all connections; only the literal string `http://` in added lines is flagged
- The bare `http://` URL pattern excludes `localhost`, `127.0.0.1`, `0.0.0.0`, and `example.com` but does not exclude other common development or test hostnames
- Will not detect weak algorithms used through third-party library abstractions that do not mention the algorithm by name

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SC-8 | Transmission Confidentiality and Integrity | Detects HTTP URLs, disabled TLS verification, hostname check bypasses, and deprecated TLS/SSL versions that undermine transmission security |
| SC-13 | Cryptographic Protection | Detects use of non-FIPS-approved algorithms (MD5, SHA-1, DES, RC4, 3DES, Blowfish) and insecure cipher modes (ECB) |
| SC-17 | Public Key Infrastructure Certificates | Detects `CERT_NONE`/`CERT_OPTIONAL` settings and self-signed certificate references that bypass PKI validation |
| SC-23 | Session Authenticity | Detects insecure cookie/session flags and `SameSite=None` configurations that expose sessions to interception or CSRF |
