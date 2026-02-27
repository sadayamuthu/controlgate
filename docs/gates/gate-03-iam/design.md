# Gate 3 — IAM & Access Control Gate

**gate_id:** `iam`
**NIST Controls:** AC-3, AC-4, AC-5, AC-6
**Priority:** 🔴 High

---

## Purpose

Gate 3 detects overly permissive IAM policies, missing authorization checks, wildcard permissions, and broad CORS configurations in IaC, application code, and API config. By scanning every added line at commit time, it enforces least-privilege and access-control principles before misconfigured policies can reach production environments.

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Wildcard IAM action (`"Action": "*"`) | Grants the principal permission to perform every AWS action; any compromise becomes a full account takeover | AC-6 |
| Wildcard IAM resource (`"Resource": "*"`) | Applies the policy to every resource in the account rather than scoping to specific ARNs | AC-6 |
| IAM policy allowing all actions (`"Effect": "Allow"` with `"Action": "*"`) | Explicit allow-all in a policy document; combined with a wildcard resource grants unrestricted access | AC-6 |
| Overly permissive managed policy reference (AdministratorAccess, PowerUserAccess, FullAccess) | Broad managed policies violate least privilege and are frequently involved in privilege escalation | AC-6 |
| AdministratorAccess policy ARN attached | Direct attachment of the AWS AdministratorAccess managed policy in code or IaC | AC-5 |
| Wildcard CORS origin (`Access-Control-Allow-Origin: *`) | Allows any external domain to make credentialed cross-origin requests | AC-4 |
| `allow_origins = ["*"]` style CORS configuration | Framework-level CORS wildcard permitting all origins | AC-4 |
| Unauthenticated Flask route handler (`@app.route(...)` without auth decorator) | Route exposed without explicit authentication or authorization middleware | AC-3 |
| Authentication bypass keywords (public, anonymous, no-auth, skip-auth, allow-all) | Explicit markers indicating intentional or accidental auth bypass | AC-3 |
| STS AssumeRole without condition constraints | Assume-role calls without MFA, IP, or time conditions can be abused if credentials are compromised | AC-3 |

## Scope

- Scans all added lines in every file included in the diff
- No file-type filter — patterns are evaluated against all file types (`.json`, `.tf`, `.yml`, `.py`, `.js`, etc.)
- Deleted and unmodified lines are not scanned

## Known Limitations

- The Flask route-decorator check is heuristic — it only fires when `@app.route()` appears with no other decorators on the same line
- Cannot verify whether a named auth decorator is actually enforced at runtime
- Does not analyze IAM policy documents beyond added lines; nested or multi-statement policies with partial wildcards in unchanged lines may be missed

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| AC-3 | Access Enforcement | Detects unauthenticated route handlers, authentication bypass markers, and unconstrained AssumeRole calls that weaken access enforcement |
| AC-4 | Information Flow Enforcement | Detects wildcard CORS configurations that permit unrestricted cross-origin information flows |
| AC-5 | Separation of Duties | Detects direct attachment of AdministratorAccess, which eliminates role separation by granting a single principal all permissions |
| AC-6 | Least Privilege | Detects wildcard actions, wildcard resources, and overly permissive managed policies that violate the principle of least privilege |
