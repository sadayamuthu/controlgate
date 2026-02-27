# Gate 14 — Observability Gate

**gate_id:** `observability`
**NIST Controls:** SI-4, AU-12
**Priority:** High

---

## Purpose

Guards against code changes that silently disable or omit the monitoring, logging, and health-check infrastructure that organisations rely on to detect system failures and security events in production. Disabling enhanced monitoring on a database instance removes the continuous performance and anomaly signals that feed into security dashboards; setting a container logging driver to `none` means all process output — including error messages and security events — is discarded the moment it is written; and deploying a Kubernetes workload without a liveness probe means the platform cannot detect or automatically recover from a hung or crashed container. By flagging these patterns at diff time, the gate ensures that observability capability is never quietly eroded during routine infrastructure or configuration changes.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `enable_monitoring = false` or `monitoring = false` in infrastructure configuration | Explicitly disabling monitoring removes continuous visibility into resource health and anomalous behaviour, leaving security and operations teams blind to events that would otherwise trigger alerts | SI-4 |
| `monitoring_interval = 0` in infrastructure configuration | Setting the monitoring interval to zero disables enhanced monitoring on database and compute resources, eliminating the high-frequency metrics used for anomaly detection and capacity planning | SI-4 |
| Container logging driver set to `none` | A `none` logging driver silently discards all container stdout and stderr output; any audit-relevant events, errors, or security signals written by the process are permanently lost | AU-12 |
| `--log-driver=none` CLI flag | Passing `--log-driver=none` at container start time overrides any default logging configuration and discards all container output, bypassing audit record generation requirements | AU-12 |
| Kubernetes workload file with `containers:` but no `livenessProbe` | Without a liveness probe the Kubernetes control plane cannot determine whether a container is healthy; a hung or deadlocked process will continue to receive traffic and will not be automatically restarted, hiding failures from operators | SI-4 |

---

## Scope

- **Scans:** added lines in git diffs (pattern scan) + full file content for Kubernetes workload files
- **File types targeted:** all files (pattern scan); Kubernetes deployment/statefulset/daemonset YAML files (liveness probe check)
- **Special detection:** Kubernetes liveness probe absence check

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- The `--log-driver=none` pattern matches the exact CLI flag string; equivalent Docker API options or Compose `logging.driver` set through environment variable interpolation are detected only by the separate `driver: none` pattern
- The Kubernetes liveness probe check matches on the literal string `livenessProbe` anywhere in the file; a probe defined in a separate ConfigMap or applied via a mutating admission webhook will not be found and the check will produce a false positive
- The Kubernetes check applies to any file whose path matches `deployment`, `statefulset`, or `daemonset` (case-insensitive) followed by `.yaml` or `.yml`; files that do not follow this naming convention will not be checked even if they define workload resources
- The `monitoring_interval = 0` pattern is case-insensitive and separator-agnostic but does not detect equivalent zero-value expressions such as `monitoring_interval = 0.0` or values supplied through variable references

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SI-4 | Information System Monitoring | Detects infrastructure configuration that disables enhanced monitoring or sets the monitoring interval to zero, and detects Kubernetes workloads that omit a liveness probe — all of which degrade the organisation's ability to continuously monitor system components for anomalies and failures |
| AU-12 | Audit Record Generation | Detects container logging configuration that routes all output to the `none` driver, whether expressed as a YAML key or a CLI flag, ensuring that containers generate and retain audit records for all security-relevant process output |
