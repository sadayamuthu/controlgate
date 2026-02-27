# Gate 11 — Data Privacy Gate

**gate_id:** `privacy`
**NIST Controls:** PT-2, PT-3, SC-28
**Priority:** 🔴 High

---

## Purpose

Guards against PII handling violations introduced in code changes. Logging PII fields exposes personal data in log aggregation systems and violates the principle of data minimization; serializing all model fields by default risks leaking sensitive attributes through API responses; data fields with no expiry or TTL create unbounded retention that violates retention policies; and PII stored in plaintext database columns is unprotected at rest if the storage layer is compromised. By flagging these patterns at diff time, the gate ensures that privacy-degrading code is caught before it reaches a deployed environment.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| PII field name (SSN, date of birth, credit card, CVV, passport, driver's license) appearing in a logging or print statement | Writing PII to logs exposes personal data in log storage, log aggregators, and observability tools where access controls are often weaker than production datastores | PT-3 |
| `serialize_all_fields = True` in a serializer class | Opt-in-to-everything serialization exposes every model field — including PII and internal fields — through API responses without an explicit allowlist review | PT-2 |
| `expires_at = None`, `ttl: 0`, or `ttl: null` in a model or data class | A null or zero retention marker means data is stored indefinitely with no automated expiry, violating explicit retention policy requirements | SC-28 |
| PII field name in a plaintext `CharField`, `TextField`, `StringField`, or `Column(String)` database column definition | Defining PII columns without encryption annotations means the data is stored in plaintext at rest, leaving it exposed if the database is accessed directly | SC-28 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- PII detection is keyword-based and line-scoped; structured logging calls or field definitions that span multiple lines will not be detected
- The plaintext-column pattern matches on field name keywords in the column definition; it does not detect PII stored under innocuous column names, nor does it inspect ORM `Meta` classes or migration files for encryption markers
- The `serialize_all_fields` pattern fires on any added line containing the literal, including documentation and test fixtures

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| PT-2 | Authority to Process Personally Identifiable Information | Detects `serialize_all_fields = True` which bypasses field-level access control in serializers and may cause unauthorized disclosure of PII through API responses |
| PT-3 | Personally Identifiable Information Processing Purposes | Detects PII field names in logging and print statements, preventing personal data from being written to log systems outside the purpose for which it was collected |
| SC-28 | Protection of Information at Rest | Detects both missing data retention markers (null `expires_at` / zero TTL) and PII stored in plaintext database columns without encryption, ensuring data at rest is protected and bounded in lifetime |
