# Gate 3 — IAM & Access Control Gate

**gate_id:** `iam`
**NIST Controls:** AC-3, AC-4, AC-5, AC-6
**Priority:** High

---

## Purpose

Prevents overly permissive identity and access management configurations from reaching production. Wildcard IAM actions and resources, over-broad managed policies (AdministratorAccess, PowerUserAccess), wildcard CORS origins, unauthenticated route handlers, and unconstrained STS AssumeRole calls are among the most exploited misconfigurations in cloud environments. This gate enforces least-privilege principles at commit time by scanning for these patterns across policy documents, application code, and infrastructure configuration.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Wildcard IAM action (`"Action": "*"`) | Grants the principal permission to perform every AWS action; any compromise becomes a full account takeover | AC-6 |
| Wildcard IAM resource (`"Resource": "*"`) | Applies the policy to every resource in the account rather than scoping to specific ARNs | AC-6 |
| IAM policy allowing all actions (`"Effect": "Allow"` with `"Action": "*"`) | Explicit allow-all in a policy document; combined with wildcard resource grants unrestricted access | AC-6 |
| Overly permissive managed policy reference (AdministratorAccess, PowerUserAccess, FullAccess) | Broad managed policies violate least privilege and are frequently involved in privilege escalation | AC-6 |
| AdministratorAccess policy ARN attached | Direct attachment of the AWS AdministratorAccess managed policy in code or IaC | AC-5 |
| Wildcard CORS origin (`Access-Control-Allow-Origin: *`) | Allows any external domain to make credentialed cross-origin requests | AC-4 |
| `allow_origins = ["*"]` style CORS configuration | Framework-level CORS wildcard permitting all origins | AC-4 |
| Unauthenticated Flask route handler (`@app.route(...)` without auth decorator) | Route exposed without explicit authentication or authorization middleware | AC-3 |
| Authentication bypass keywords (public, anonymous, no-auth, skip-auth, allow-all) | Explicit markers indicating intentional or accidental auth bypass | AC-3 |
| STS AssumeRole without condition constraints | Assume-role calls without MFA, IP, or time conditions can be abused if credentials are compromised | AC-3 |

---

## Scope

- **Scans:** all added lines in every file in the diff
- **File types targeted:** all file types; useful across `.json` policy documents, `.tf`/`.yml` IaC files, and Python/JavaScript application code
- **Special detection:** none; standard pattern loop only

---

## Known Limitations

- Does not scan deleted or unmodified lines
- The unauthenticated route pattern matches any `@app.route(...)` on its own line regardless of whether an auth decorator exists on the preceding line; expect false positives on well-authenticated route definitions
- Does not parse IAM JSON structure; nested or multi-statement policies with partial wildcards may be missed
- STS AssumeRole detection fires on any reference to the API; it cannot determine whether conditions are set in a separate Policy block
- CORS detection covers common patterns but not all framework-specific CORS libraries

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| AC-3 | Access Enforcement | Detects unauthenticated route handlers, authentication bypass markers, and unconstrained AssumeRole calls that weaken access enforcement |
| AC-4 | Information Flow Enforcement | Detects wildcard CORS configurations that permit unrestricted cross-origin information flows |
| AC-5 | Separation of Duties | Detects direct attachment of AdministratorAccess, which eliminates role separation by granting a single principal all permissions |
| AC-6 | Least Privilege | Detects wildcard actions, wildcard resources, and overly permissive managed policies that violate the principle of least privilege |
