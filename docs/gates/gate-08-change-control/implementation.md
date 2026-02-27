# Gate 8 — Change Control Gate: Implementation Reference

**Source file:** `src/controlgate/gates/change_gate.py`
**Test file:** `tests/test_gates/test_change_gate.py`
**Class:** `ChangeGate`
**gate_id:** `change_control`
**mapped_control_ids:** `["CM-3", "CM-4", "CM-5"]`

---

## Scan Method

`scan()` iterates every `diff_file` and performs four checks, most of which are path-based rather than line-content-based:

1. **Security-critical file check** — if `diff_file.path` matches `_SECURITY_CRITICAL_FILES` (case-insensitive), fires one CM-3 finding at line 1 with description "Security-critical file modified — requires additional review".
2. **Deployment config check** — if `diff_file.path` matches `_DEPLOY_CONFIG_FILES` (case-insensitive), fires one CM-4 finding at line 1 with description "Deployment configuration modified — impact analysis required".
3. **CODEOWNERS check** — if `"CODEOWNERS"` appears in `diff_file.path.upper()`, fires one CM-5 finding at line 1 with description "CODEOWNERS file modified — may change access restrictions for code review".
4. **Line-content check** — for each added line (via `diff_file.all_added_lines`), calls `_check_line()` which applies the inline branch protection regex; fires CM-5 findings.

Checks 1–3 are path-based and emit at most one finding each per file. Check 4 is the only content-based check and can emit multiple findings per file.

---

## Patterns

There is no `_PATTERNS` list in this gate. Instead, two module-level compiled regexes handle path-based detection:

| Pattern Name | What It Matches | Control |
|---|---|---|
| `_SECURITY_CRITICAL_FILES` | File paths matching CI/CD workflow dirs (`.github/workflows`, `.gitlab-ci`, `.travis`, `.circleci`, `Jenkinsfile`, `azure-pipelines`, `cloudbuild`), container files (`Dockerfile`, `docker-compose*.yml`), environment files (`.env`, `.env.*`), infrastructure-as-code (`terraform/*.tf`, `infra/*.tf`), deployment dirs (`deploy/`, `deployment/`, `k8s/`, `kubernetes/`), web server configs (`nginx.conf`, `apache*.conf`, `.htaccess`, `supervisord.conf`), `Makefile`, security/auth source files (`security*.py\|js\|ts\|rb\|go\|java`, `auth*.py\|js\|ts\|rb\|go\|java`), and IAM/RBAC/ACL/policy files (`iam*.json\|yaml\|py`, `rbac*.json\|yaml\|py`, `acl*.json\|yaml\|py`, `policy*.json\|yaml\|py`) | CM-3 |
| `_DEPLOY_CONFIG_FILES` | File paths matching Helm values files (`helm/.*values.*\.ya?ml`), Helm charts dirs (`charts/`), Terraform variable files (`terraform/.*\.tfvars`), Ansible dirs (`ansible/`), and Pulumi dirs (`pulumi/`) | CM-4 |

---

## Special Detection Logic

### (a) `_SECURITY_CRITICAL_FILES` matches

The regex is a single large alternation compiled with `re.VERBOSE` and the `(?i)` flag for case-insensitivity. It is applied via `.search()` against the full file path string, so it fires on partial path matches (e.g., `services/api/Dockerfile` matches `Dockerfile`). Key file types covered include:

- GitHub Actions workflows and CODEOWNERS (`.github/workflows/`, `.github/CODEOWNERS`)
- Container build files (`Dockerfile`, `docker-compose*.yml`)
- Environment variable files (`.env`, `.env.production`, `.env.local`, etc.)
- Terraform and infra IaC files (`terraform/*.tf`, `infra/*.tf`)
- Deployment directories (`deploy/`, `deployment/`, `k8s/`, `kubernetes/`)
- CI/CD pipeline configs (`.gitlab-ci`, `.travis`, `.circleci`, `Jenkinsfile`, `azure-pipelines`, `cloudbuild`)
- Web server and process manager configs (`nginx.conf`, `apache*.conf`, `.htaccess`, `supervisord.conf`, `Makefile`)
- Security/auth source files (any `security*.{py,js,ts,rb,go,java}` or `auth*.{py,js,ts,rb,go,java}`)
- IAM/RBAC/ACL/policy definition files (`iam*.{json,yaml,py}`, `rbac*.{json,yaml,py}`, `acl*.{json,yaml,py}`, `policy*.{json,yaml,py}`)

### (b) `_DEPLOY_CONFIG_FILES` matches

A second compiled regex applied via `.search()` against `diff_file.path` (case-insensitive). Covers Helm values files, Helm chart directories, Terraform `.tfvars` variable files, Ansible playbook directories, and Pulumi project directories. This check is independent of `_SECURITY_CRITICAL_FILES`; a file can match both regexes and produce both a CM-3 and a CM-4 finding.

### (c) CODEOWNERS path check

A hard-coded string check — `"CODEOWNERS" in diff_file.path.upper()` — is evaluated after the regex checks. This is not a regex; it is a substring match. It fires on any file whose path contains `CODEOWNERS` in any case (e.g., `CODEOWNERS`, `.github/CODEOWNERS`, `docs/codeowners`). Because `_SECURITY_CRITICAL_FILES` also matches `CODEOWNERS` paths, a CODEOWNERS file will produce both a CM-3 finding (from the regex) and a CM-5 finding (from this check) — this duplication is by design.

### (d) Branch protection inline regex

Inside `_check_line()`, a one-off `re.search()` is applied to each added line:

```
(?i)(?:branch.?protection|protected.?branch)
```

This pattern matches any added line containing "branch protection", "branch-protection", "branchprotection", "protected branch", "protected-branch", or "protectedbranch" (the `.?` allows an optional separator character). It fires a CM-5 finding at the exact line number of the matching added line. This is the only content-based check in the gate.

---

## Test Coverage

No test file exists for `ChangeGate` at `tests/test_gates/test_change_gate.py`. This gate has no automated test coverage.
