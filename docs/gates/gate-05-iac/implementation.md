# Gate 5 — Infrastructure-as-Code Gate: Implementation Reference

**Source file:** `src/controlgate/gates/iac_gate.py`
**Test file:** `tests/test_gates/test_iac_gate.py`
**Class:** `IaCGate`
**gate_id:** `iac`
**mapped_control_ids:** `["CM-2", "CM-6", "CM-7", "SC-7"]`

---

## Scan Method

`scan()` iterates every `diff_file`. Before pattern evaluation, it calls `_is_iac_file(diff_file.path)`. If the file does not qualify as an IaC file, it is skipped entirely and the loop advances to the next file. For qualifying files, `_check_line()` is called for each added line via `diff_file.all_added_lines`. `_check_line()` runs a single loop over `_IAC_PATTERNS` (14 patterns), each a 4-tuple `(pattern, description, control_id, remediation)`. A `Finding` is appended for every pattern that matches.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `0\.0\.0\.0/0` | Unrestricted ingress rule (0.0.0.0/0) — publicly accessible | SC-7 | Restrict ingress to specific IP ranges or CIDR blocks |
| 2 | `::/0` | Unrestricted IPv6 ingress rule (::/0) — publicly accessible | SC-7 | Restrict IPv6 ingress to specific CIDR blocks |
| 3 | `(?i)(?:acl\|access)\s*[:=]\s*["\']?(?:public-read\|public-read-write\|authenticated-read)["\']?` | Public access configured on storage resource | SC-7 | Set storage ACL to private and use pre-signed URLs for controlled access |
| 4 | `(?i)block_public_acls\s*[:=]\s*(?:false\|0)` | S3 public access block disabled | SC-7 | Enable all S3 public access blocks: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets |
| 5 | `(?i)(?:USER\s+root\|user:\s*["\']?root["\']?\|runAsUser:\s*0\|privileged:\s*true)` | Container configured to run as root or privileged | CM-6 | Run containers as non-root user. Add 'USER nonroot' in Dockerfile or set runAsNonRoot: true |
| 6 | `(?i)securityContext:\s*\{\s*\}\|securityContext:\s*null` | Empty or null security context in Kubernetes | CM-6 | Define securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities |
| 7 | `(?i)allowPrivilegeEscalation:\s*true` | Privilege escalation allowed in container | CM-6 | Set allowPrivilegeEscalation: false |
| 8 | `(?i)hostNetwork:\s*true` | Container using host network | CM-7 | Avoid hostNetwork unless absolutely necessary; use network policies instead |
| 9 | `(?i)hostPID:\s*true\|hostIPC:\s*true` | Container sharing host PID or IPC namespace | CM-7 | Disable hostPID and hostIPC unless required for specific system containers |
| 10 | `(?i)resources:\s*\{\s*\}\|resources:\s*null` | No resource limits defined for container | CM-6 | Define CPU and memory resource limits to prevent resource exhaustion attacks |
| 11 | `(?i)(?:containerPort\|hostPort\|port):\s*(?:22\|3389\|5432\|3306\|6379\|27017\|9200)\b` | Sensitive service port directly exposed | CM-7 | Avoid exposing sensitive service ports directly; use network policies and internal load balancers |
| 12 | `(?i)(?:encryption\|encrypted\|encrypt)\s*[:=]\s*(?:false\|0\|off\|none\|disabled)` | Encryption explicitly disabled in infrastructure configuration | CM-6 | Enable encryption at rest and in transit for all data stores and communication channels |
| 13 | `(?i)logging\s*[:=]\s*(?:false\|disabled\|off\|0)` | Logging disabled in infrastructure configuration | CM-6 | Enable logging for all infrastructure components for audit and incident response |
| 14 | `(?i)versioning\s*[:=]\s*(?:false\|disabled\|off\|0)` | Versioning disabled on storage resource | CM-2 | Enable versioning for data protection and recovery capability |

---

## Special Detection Logic

### `_is_iac_file()` File-Type Guard

Before any pattern evaluation, `scan()` calls `_is_iac_file(path)` which returns `True` if any of the following conditions are met:

**By file extension** (checked via `path.lower().endswith(ext)`):

| Extension | Covers |
|---|---|
| `.tf` | Terraform resource files |
| `.tfvars` | Terraform variable files |
| `.hcl` | HCL configuration (Packer, Consul, Vault, etc.) |
| `.yaml` | Kubernetes manifests, CloudFormation, Docker Compose, CI configs |
| `.yml` | Same as `.yaml` |
| `.json` | CloudFormation, ARM templates, CDK output |
| `Dockerfile` | Docker image build files (suffix match) |

**By path segment** (checked via substring match in `path.lower()`):

`terraform/`, `infra/`, `infrastructure/`, `deploy/`, `k8s/`, `kubernetes/`, `helm/`, `.github/`, `cloudformation/`, `cdk/`

**By filename pattern** (checked separately):

`"Dockerfile" in path` or `"docker-compose" in path.lower()`

Files that match none of these criteria are skipped; no findings are produced for them regardless of line content.

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_public_ingress` | `cidr_blocks = ["0.0.0.0/0"]` in a `.tf` file triggers at least one finding with `"0.0.0.0/0"` in the description |
| `test_detects_root_container` | `USER root` in a `Dockerfile` triggers at least one finding with `"root"` in the description |
| `test_skips_non_iac_files` | `cidr = "0.0.0.0/0"` in `app.py` (not an IaC file) produces zero findings |
