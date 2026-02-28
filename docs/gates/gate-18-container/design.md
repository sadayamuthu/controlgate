# Gate 18 — Container Security Gate

**gate_id:** `container`
**NIST Controls:** CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3
**Priority:** High

---

## Purpose

Guards against container and Kubernetes misconfigurations that are commonly introduced during routine development and infrastructure changes. Unpinned base images break build reproducibility and can silently introduce compromised or updated layers; overly privileged containers and relaxed security contexts enable container-escape attacks and lateral movement within a cluster; host namespace sharing erodes the isolation boundary between workloads and the underlying node; disabled logging drivers make container activity unauditable; and missing resource limits expose the cluster to denial-of-service through resource exhaustion. By scanning added lines in git diffs across Dockerfiles, Compose files, Kubernetes manifests, and shell scripts, the gate surfaces these misconfigurations before they reach a running environment.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `FROM ... :latest` tag | The `:latest` tag is mutable — the image it resolves to can change between builds, making deployments non-reproducible and potentially introducing a backdoored layer | SI-7 |
| Base image with no tag | An untagged `FROM` directive resolves to `latest` implicitly, carrying the same reproducibility and integrity risks | SI-7 |
| `ADD` with a remote URL | `ADD https://...` fetches remote content at build time with no checksum verification, allowing a compromised upstream server to inject malicious content | SI-7 |
| `USER root` in a Dockerfile | Explicitly running the container as root grants the process full filesystem and system-call access, violating the principle of least privilege | AC-6 |
| `privileged: true` or `--privileged` | A privileged container has access to all host devices and capabilities, making container escape trivial | AC-6 |
| `--cap-add ALL` | Granting all Linux capabilities is functionally equivalent to running as root; any single dangerous capability can be leveraged for privilege escalation | AC-6 |
| `--cap-add SYS_ADMIN`, `SYS_PTRACE`, or `NET_ADMIN` | These high-risk capabilities individually permit actions such as mounting filesystems, tracing arbitrary processes, or reconfiguring the host network — each a container-escape vector | AC-6 |
| `allowPrivilegeEscalation: true` | Permits setuid/setgid binaries inside the container to elevate privileges beyond the container's assigned UID | AC-6 |
| `runAsNonRoot: false` | Explicitly allows the container entrypoint to run as UID 0, undermining the securityContext non-root guarantee | AC-6 |
| `hostNetwork: true` | Shares the host's network namespace, exposing all host-bound ports and bypassing Kubernetes NetworkPolicy | SC-7 |
| `hostPort` binding | Binds a container port directly to a host port, bypassing Kubernetes NetworkPolicy enforcement and exposing the service on every node | SC-7 |
| `readOnlyRootFilesystem: false` | A writable root filesystem lets an attacker persist backdoors, modify binaries, or tamper with configuration files inside a running container | SC-39 |
| `hostPID: true` | Shares the host's PID namespace, allowing the container to observe and signal arbitrary host processes — a well-known container-escape technique | SC-39 |
| `hostIPC: true` | Shares the host IPC namespace, enabling cross-container and cross-process shared memory access | SC-39 |
| Seccomp profile set to `Unconfined` | Removes the syscall filter entirely, allowing the container to invoke any system call and significantly increasing the kernel attack surface | SC-39 |
| Logging driver set to `none` (YAML or CLI) | Discards all container stdout/stderr, making it impossible to audit container activity or detect anomalous behaviour after the fact | AU-12 |
| Empty `resources: {}` block | No CPU or memory limits means a single runaway container can exhaust node resources and cause a cluster-wide denial-of-service | CM-6 |
| Unlimited memory via `--memory=-1` | Explicitly removes the memory ceiling, allowing unbounded memory consumption | CM-6 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files (Dockerfiles, docker-compose.yml, Kubernetes YAML, shell scripts)

---

## Known Limitations

- Does not scan deleted or removed lines; a configuration that was previously secure but has had its security context removed will not be flagged if the removal is expressed as a deleted line rather than a changed one
- Does not perform cross-file analysis; a Kubernetes Pod spec that inherits dangerous defaults from a Helm chart or a Kustomize base layer is not detected
- Image integrity checks are regex-based and apply to any file; a comment or documentation example containing `FROM python:latest` will produce a false positive
- The `hostPort` pattern matches any numeric port value and does not distinguish between development and production manifests
- The seccomp-unconfined pattern is case-insensitive but matches only single-line expressions; multi-line seccomp configuration blocks are not detected
- Resource limit detection checks only for the `resources: {}` empty-object shorthand and the `--memory=-1` flag; omitting the `resources` key entirely or setting limits to very high values is not flagged

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| CM-6 | Configuration Settings | Detects empty resource blocks and unlimited memory allocations that violate secure baseline configuration requirements for container workloads |
| CM-7 | Least Functionality | Declared in `mapped_control_ids`; no patterns currently emitted — container capability allow-list enforcement deferred (see Known Debt in the implementation reference) |
| SC-7 | Boundary Protection | Detects `hostNetwork: true` and `hostPort` bindings that bypass Kubernetes NetworkPolicy and expose workloads outside their intended network boundary |
| SC-39 | Process Isolation | Detects configurations that share host namespaces (PID, IPC) or permit unrestricted syscalls (seccomp Unconfined), each of which breaks the process isolation guarantee between containers and the host |
| AC-6 | Least Privilege | Detects root user execution, privileged mode, capability grants (ALL, SYS_ADMIN, SYS_PTRACE, NET_ADMIN), and security context flags that permit privilege escalation inside the container |
| SI-7 | Software, Firmware, and Information Integrity | Detects unpinned or untagged base images and remote ADD directives that undermine build reproducibility and allow unverified content to enter the image |
| AU-12 | Audit Record Generation | Detects logging driver configurations set to `none`, which discard all container output and make post-incident audit impossible |
| SA-10 | Developer Security Testing and Evaluation | Declared in `mapped_control_ids`; no patterns currently emitted — image signing and SBOM verification deferred (see Known Debt in the implementation reference) |
| SR-3 | Supply Chain Controls and Processes | Declared in `mapped_control_ids`; no patterns currently emitted — base image provenance and supply chain checks deferred (see Known Debt in the implementation reference) |
