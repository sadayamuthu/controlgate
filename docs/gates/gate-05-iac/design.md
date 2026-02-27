# Gate 5 — Infrastructure-as-Code Gate

**gate_id:** `iac`
**NIST Controls:** CM-2, CM-6, CM-7, SC-7
**Priority:** High

---

## Purpose

Prevents insecure infrastructure configurations from being deployed by detecting common misconfigurations in Terraform, CloudFormation, Kubernetes YAML, and Dockerfiles at commit time. Publicly accessible network rules, containers running as root, disabled encryption, and missing resource limits are among the most frequent causes of cloud security incidents. Catching these patterns before they reach the deployment pipeline is substantially cheaper and safer than remediating them post-deployment.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| **Network exposure:** Unrestricted IPv4 ingress rule (`0.0.0.0/0`) | Opens the resource to the entire internet, enabling reconnaissance and direct attack | SC-7 |
| **Network exposure:** Unrestricted IPv6 ingress rule (`::/0`) | Same as above for IPv6 traffic; often forgotten when IPv4 is correctly restricted | SC-7 |
| **Public storage:** Public storage ACL (`public-read`, `public-read-write`, `authenticated-read`) | Exposes object storage buckets to anonymous or broadly authenticated reads/writes | SC-7 |
| **Public storage:** S3 public access block disabled (`block_public_acls = false`) | Overrides the account-level public access guardrail, allowing bucket-level policies to grant public access | SC-7 |
| **Container security:** Container running as root or privileged (`USER root`, `runAsUser: 0`, `privileged: true`) | Root or privileged containers can break out of container isolation and access the host kernel | CM-6 |
| **Container security:** Empty or null Kubernetes security context (`securityContext: {}`) | No securityContext means all defaults apply — typically root user, no capability drops, writable root filesystem | CM-6 |
| **Container security:** Privilege escalation allowed (`allowPrivilegeEscalation: true`) | Allows processes inside the container to gain additional privileges via setuid or kernel exploits | CM-6 |
| **Container security:** Container using host network (`hostNetwork: true`) | Bypasses pod-level network isolation; container sees all host network interfaces | CM-7 |
| **Container security:** Container sharing host PID or IPC namespace (`hostPID`/`hostIPC: true`) | Allows process inspection and signal delivery across container boundaries | CM-7 |
| **Resource limits:** No resource limits defined (`resources: {}`) | Absence of CPU/memory limits enables denial-of-service through resource exhaustion | CM-6 |
| **Exposed ports:** Sensitive service port directly exposed (SSH 22, RDP 3389, databases 5432/3306/6379/27017/9200) | Direct exposure of administrative and data-tier ports to network traffic | CM-7 |
| **Insecure defaults:** Encryption explicitly disabled | Disabling at-rest or in-transit encryption leaves data unprotected | CM-6 |
| **Insecure defaults:** Logging disabled | Absence of infrastructure logging prevents detection of and response to incidents | CM-6 |
| **Insecure defaults:** Versioning disabled on storage resource | Without versioning, accidental deletion or ransomware encryption is unrecoverable | CM-2 |

---

## Scope

**IMPORTANT:** This gate only scans IaC files. All other files are skipped entirely before any pattern evaluation is performed.

**File extensions included** (matched via `path.lower().endswith(ext)`):

| Extension | Covers |
|---|---|
| `.tf` | Terraform resource files |
| `.tfvars` | Terraform variable files |
| `.hcl` | HCL configuration (Packer, Consul, Vault, etc.) |
| `.yaml` | Kubernetes manifests, CloudFormation, Docker Compose, CI configs |
| `.yml` | Same as `.yaml` |
| `.json` | CloudFormation, ARM templates, CDK output |
| `Dockerfile` | Docker image build files (suffix match) |

**Path segments included** (matched via substring in `path.lower()`):

`terraform/`, `infra/`, `infrastructure/`, `deploy/`, `k8s/`, `kubernetes/`, `helm/`, `.github/`, `cloudformation/`, `cdk/`

**Filename patterns included** (checked separately):

Any path containing `Dockerfile` or `docker-compose`.

---

## Known Limitations

- Only IaC files are scanned; non-IaC files (e.g., `.py`, `.js`, `.go`) are skipped entirely and will produce no findings even if they contain matching text.
- Only added lines are scanned; deleted or context lines are ignored.
- No cross-file analysis is performed; each file is evaluated independently with no knowledge of other files in the diff or the broader infrastructure state.
- The `resources: {}` and `securityContext: {}` patterns require the YAML to appear on a single line; multi-line null or empty definitions are not detected.
- Does not perform semantic analysis of Terraform plan output; only pattern-matches source text.

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| CM-2 | Baseline Configuration | Detects disabled versioning on storage resources, which is a required baseline configuration for data protection and recovery |
| CM-6 | Configuration Settings | Detects insecure container configurations (root user, privilege escalation, empty security contexts, no resource limits, disabled encryption and logging) that violate secure configuration baselines |
| CM-7 | Least Functionality | Detects unnecessary host namespace sharing, exposed sensitive service ports, and host network usage that violate the principle of least functionality |
| SC-7 | Boundary Protection | Detects unrestricted network ingress rules and public storage ACLs that eliminate boundary protection controls |
