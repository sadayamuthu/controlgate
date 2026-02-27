# Gate 8 — Change Control Gate

**gate_id:** `change_control`
**NIST Controls:** CM-3, CM-4, CM-5
**Priority:** Medium

---

## Purpose

Enforces change management discipline by detecting modifications to security-critical files and deployment configurations that require additional review, impact analysis, or administrator approval before being merged. Changes to CI/CD pipelines, Dockerfiles, Terraform configurations, IAM/RBAC policies, CODEOWNERS files, and branch protection settings carry disproportionate security risk relative to application code changes. This gate creates mandatory visibility for these changes by emitting findings that require a reviewer to acknowledge the security implications before the commit is accepted.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| Security-critical file modified (workflows, CODEOWNERS, Dockerfile, docker-compose, .env, Terraform, deploy/, k8s/, CI configs, nginx/apache/htaccess, supervisord, security/auth source files, IAM/RBAC/ACL policy files) | These files directly control the security posture of the system; unreviewed changes can introduce persistent backdoors or privilege escalation paths | CM-3 |
| Deployment configuration modified (Helm values, Terraform tfvars, Ansible playbooks, Pulumi configs) | Deployment config changes affect the runtime environment; incorrect changes can expose services or disable security controls | CM-4 |
| CODEOWNERS file modified | CODEOWNERS controls who must approve PRs for specific code paths; removal of a security-team entry can allow unapproved changes to sensitive files | CM-5 |
| Branch protection configuration change (`branch_protection`, `protected_branch` in added lines) | Branch protection settings prevent force pushes and require PR reviews; weakening them removes a key access control | CM-5 |

---

## Scope

- **Scans:** file paths (for security-critical file and deployment config detection, and CODEOWNERS check) and added lines (for branch protection content pattern)
- **File types targeted:** all file types; detections are primarily path-based using large regular expressions against `diff_file.path`
- **Special detection:** most findings are generated from the file path rather than line content; only the branch protection pattern inspects added line text

---

## Known Limitations

- Does not scan deleted or unmodified lines
- Security-critical file detection is purely filename/path-based; a file containing critical security logic but named with a generic name will not be flagged
- The gate emits a finding for every matching file modification without assessing whether the change is benign; all security-critical file changes produce findings regardless of the nature of the modification
- The branch protection line-content pattern is a heuristic; it fires on any added line containing the words "branch protection" or "protected branch" regardless of context (e.g., comments, documentation)
- The CODEOWNERS check fires on any path containing the string `CODEOWNERS` (case-insensitive); changes that add restrictions are treated identically to changes that remove them

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| CM-3 | Configuration Change Control | Detects modifications to security-critical files that should follow a formal change control process including security review and documentation |
| CM-4 | Impact Analysis | Detects deployment and infrastructure configuration changes that require analysis of their security impact before being applied to production |
| CM-5 | Access Restrictions for Change | Detects CODEOWNERS modifications and branch protection changes that could weaken the access restrictions controlling who can approve and merge code changes |
