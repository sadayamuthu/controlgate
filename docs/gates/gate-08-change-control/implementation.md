# Gate 8 — Change Control Gate: Implementation Reference

**Source file:** `src/controlgate/gates/change_gate.py`
**Test file:** none
**Class:** `ChangeGate`
**gate_id:** `change_control`
**mapped_control_ids:** `["CM-3", "CM-4", "CM-5"]`

---

## Scan Method

`scan()` iterates every `diff_file` and performs four checks, most of which are path-based rather than line-content-based:

1. **Security-critical file check** — if `diff_file.path` matches `_SECURITY_CRITICAL_FILES`, fires one CM-3 finding at line 1.
2. **Deployment config check** — if `diff_file.path` matches `_DEPLOY_CONFIG_FILES`, fires one CM-4 finding at line 1.
3. **CODEOWNERS check** — if `"CODEOWNERS"` appears in `diff_file.path.upper()`, fires one CM-5 finding at line 1.
4. **Line-content check** — for each added line, calls `_check_line()` which checks for the `branch.?protection` pattern; fires CM-5 findings.

Checks 1–3 are path-based and emit at most one finding each per file. Check 4 is the only content-based check and can emit multiple findings.

---

## Patterns

### Security-Critical File Regex (`_SECURITY_CRITICAL_FILES`) — control CM-3

Matched against `diff_file.path` (case-insensitive):

| Path Pattern | Example Matches |
|---|---|
| `\.github/(?:workflows\|CODEOWNERS)` | `.github/workflows/deploy.yml`, `.github/CODEOWNERS` |
| `CODEOWNERS` | `CODEOWNERS` |
| `Dockerfile` | `Dockerfile`, `services/api/Dockerfile` |
| `docker-compose.*\.ya?ml` | `docker-compose.yml`, `docker-compose.prod.yaml` |
| `\.(?:env\|env\..+)` | `.env`, `.env.production`, `.env.local` |
| `(?:terraform\|infra)/.*\.tf` | `terraform/main.tf`, `infra/vpc.tf` |
| `(?:deploy\|deployment)/` | `deploy/k8s.yaml`, `deployment/config.json` |
| `k8s/` | `k8s/deployment.yaml` |
| `kubernetes/` | `kubernetes/rbac.yaml` |
| `\.(?:gitlab-ci\|travis\|circleci)` | `.gitlab-ci.yml`, `.travis.yml`, `.circleci/config.yml` |
| `Jenkinsfile` | `Jenkinsfile` |
| `azure-pipelines` | `azure-pipelines.yml` |
| `cloudbuild` | `cloudbuild.yaml` |
| `Makefile` | `Makefile` |
| `nginx\.conf` | `nginx.conf`, `config/nginx.conf` |
| `apache.*\.conf` | `apache2.conf`, `httpd.conf` |
| `\.htaccess` | `.htaccess` |
| `supervisord\.conf` | `supervisord.conf` |
| `(?:security\|auth).*\.(?:py\|js\|ts\|rb\|go\|java)` | `security_middleware.py`, `auth.ts` |
| `(?:iam\|rbac\|acl\|policy).*\.(?:json\|ya?ml\|py)` | `iam_policy.json`, `rbac.yaml` |

### Deployment Config File Regex (`_DEPLOY_CONFIG_FILES`) — control CM-4

Matched against `diff_file.path` (case-insensitive):

| Path Pattern | Example Matches |
|---|---|
| `helm/.*values.*\.ya?ml` | `helm/values.yaml`, `helm/values.prod.yaml` |
| `charts/` | `charts/app/templates/deployment.yaml` |
| `terraform/.*\.tfvars` | `terraform/prod.tfvars` |
| `ansible/` | `ansible/playbook.yml` |
| `pulumi/` | `pulumi/index.ts` |

### CODEOWNERS Check — control CM-5

Hard-coded string check (not a regex): `"CODEOWNERS" in diff_file.path.upper()`

Matches any file path containing the word CODEOWNERS in any case. Fires one CM-5 finding at line 1 independently of the `_SECURITY_CRITICAL_FILES` check (a CODEOWNERS file can produce both a CM-3 and a CM-5 finding).

### Branch Protection Line Pattern — control CM-5

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)(?:branch.?protection\|protected.?branch)` | Branch protection configuration change detected | CM-5 | Branch protection changes require administrator approval |

---

## Known Debt / Deferred Patterns

- No test file exists for this gate; all behaviour is untested by automated tests
- A CODEOWNERS file match can produce both a CM-3 finding (from `_SECURITY_CRITICAL_FILES`) and a CM-5 finding (from the hard-coded CODEOWNERS check) for the same file; this duplication is by design but produces two findings for one file
- The gate does not distinguish between changes that tighten security controls and changes that weaken them; all modifications to critical files are treated as requiring review

---

## Test Coverage

No test file exists for `ChangeGate`. This gate has no automated test coverage.
