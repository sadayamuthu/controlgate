# Gate 18 — Container Security Gate: Implementation Reference

**Source file:** `src/controlgate/gates/container_gate.py`
**Test file:** `tests/test_gates/test_container_gate.py`
**Class:** `ContainerGate`
**gate_id:** `container`
**mapped_control_ids:** `["CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"]`

---

## Scan Method

`scan()` iterates every `diff_file` in the provided list and then iterates every added line via `diff_file.all_added_lines`, which yields `(line_no, line)` tuples. For each added line the method iterates `_ALL_PATTERN_GROUPS`, a module-level list of six pattern group lists. Each pattern group is itself a list of four-tuples of `(compiled_regex, description, control_id, remediation)`. When a pattern's `.search()` call matches the line, `_make_finding()` is called with the corresponding control ID, file path, line number, description, the first 120 characters of the stripped line as evidence, and the remediation string. All findings are collected into a flat list and returned. There is no early-exit per line; a single added line can produce multiple findings if it matches patterns in more than one group.

---

## Patterns

### Image Integrity (SI-7)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `FROM\s+\S+:latest` | Unpinned `:latest` tag — image may change between builds, breaking reproducibility | SI-7 | Pin to a specific version tag or use a digest: `FROM python@sha256:<hash>` |
| 2 | `^FROM\s+[^\s@:]+\s*$` (MULTILINE) | Base image has no tag — always pin to a specific digest or version | SI-7 | Add a version tag or SHA256 digest: `FROM python:3.11-slim@sha256:<hash>` |
| 3 | `ADD\s+https?://` | Remote ADD fetches content at build time without checksum verification | SI-7 | Use `RUN curl ... \| sha256sum -c` and COPY instead of ADD with remote URLs |

### Least Privilege (AC-6)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `USER\s+root` | Container explicitly set to run as root — violates least privilege | AC-6 | Create a dedicated non-root user: `RUN useradd -r app && USER app` |
| 2 | `(?i)privileged:\s*true\|--privileged` | Privileged container grants full host access — enables container escape | AC-6 | Remove `privileged: true`; grant only specific capabilities if needed |
| 3 | `--cap-add\s+ALL` | ALL Linux capabilities granted — equivalent to running as root | AC-6 | Enumerate only the specific capabilities required (e.g. `--cap-add NET_BIND_SERVICE`) |
| 4 | `--cap-add\s+(?:SYS_ADMIN\|SYS_PTRACE\|NET_ADMIN)` | High-risk Linux capability granted — can lead to host privilege escalation | AC-6 | Audit whether this capability is truly needed; prefer dropping all caps and adding selectively |
| 5 | `allowPrivilegeEscalation:\s*true` | `allowPrivilegeEscalation: true` permits setuid/setgid escalation inside the container | AC-6 | Set `allowPrivilegeEscalation: false` in securityContext |
| 6 | `runAsNonRoot:\s*false` | `runAsNonRoot: false` explicitly permits the container to run as root | AC-6 | Set `runAsNonRoot: true` and specify `runAsUser` with a non-zero UID |

### Network Isolation (SC-7)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `hostNetwork:\s*true` | `hostNetwork: true` exposes the container on the host network namespace | SC-7 | Use ClusterIP or NodePort Services; avoid sharing the host network namespace |
| 2 | `hostPort:\s*\d+` | `hostPort` bypasses Kubernetes NetworkPolicy — use Service resources instead | SC-7 | Replace `hostPort` with a Kubernetes Service of type NodePort or LoadBalancer |

### Runtime Hardening (SC-39)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `readOnlyRootFilesystem:\s*false` | Writable root filesystem — allows attacker to modify container files | SC-39 | Set `readOnlyRootFilesystem: true` and use emptyDir/PVC mounts for writable paths |
| 2 | `hostPID:\s*true` | `hostPID: true` shares the host process namespace — enables container escape vectors | SC-39 | Remove `hostPID: true`; process isolation must be maintained |
| 3 | `hostIPC:\s*true` | `hostIPC: true` shares host IPC namespace — allows cross-container memory access | SC-39 | Remove `hostIPC: true`; IPC namespace isolation must be maintained |
| 4 | `(?i)seccompProfile.*Unconfined\|seccomp.*unconfined` | Seccomp profile set to Unconfined — all syscalls permitted | SC-39 | Use RuntimeDefault seccomp profile or create a custom restricted profile |

### Audit (AU-12)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)log.?driver.*none` | Container logging driver set to `none` — all container output is discarded | AU-12 | Use a persistent logging driver (json-file, awslogs, fluentd, splunk) |
| 2 | `--log-driver=none` | Container logging disabled via CLI flag — cannot audit container activity | AU-12 | Remove `--log-driver=none`; use a centralised logging destination |

### Resource Limits (CM-6)

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `resources:\s*\{\}` | Empty resources block — no CPU/memory limits set; enables denial-of-service | CM-6 | Set explicit `resources.requests` and `resources.limits` for CPU and memory |
| 2 | `--memory[= ]["']?-1` | Unlimited container memory allocation — no ceiling for memory consumption | CM-6 | Set an explicit `--memory` limit (e.g. `--memory=512m`) |

---

## Known Debt / Deferred Patterns

- CM-7 (Least Functionality): declared in `mapped_control_ids` but no patterns emit CM-7; container capability allow-list enforcement deferred
- SA-10 (Developer Security Testing and Evaluation): declared but no patterns emit SA-10; image signing and SBOM verification deferred
- SR-3 (Supply Chain Controls): declared but no patterns emit SR-3; base image provenance and supply chain checks deferred

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_user_root` | A diff adding `USER root` triggers at least one finding with control ID AC-6 |
| `test_detects_privileged_mode` | A diff adding `privileged: true` or `--privileged` triggers at least one finding with control ID AC-6 |
| `test_detects_latest_tag` | A diff adding a `FROM` line with the `:latest` tag triggers at least one finding with control ID SI-7 |
| `test_detects_host_network` | A diff adding `hostNetwork: true` triggers at least one finding with control ID SC-7 |
| `test_detects_host_pid` | A diff adding `hostPID: true` triggers at least one finding with control ID SC-39 |
| `test_clean_dockerfile_no_findings` | A diff adding a well-configured Dockerfile (pinned digest, non-root user, no dangerous flags) produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "container"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"}` |
