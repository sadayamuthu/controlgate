# Gate 14 — Observability Gate: Implementation Reference

**Source file:** `src/controlgate/gates/observability_gate.py`
**Test file:** `tests/test_gates/test_observability_gate.py`
**Class:** `ObservabilityGate`
**gate_id:** `observability`
**mapped_control_ids:** `["SI-4", "AU-12"]`

---

## Scan Method

`scan()` runs two distinct detection passes over the provided list of `DiffFile` objects and collects all findings into a single flat list that is returned at the end.

**Pass 1 — Standard pattern loop:** For every `diff_file`, the method iterates `diff_file.all_added_lines`, which yields `(line_no, line)` tuples for each added line in the diff. For every added line, each of the four entries in the module-level `_PATTERNS` list is evaluated in order. Each entry is a four-tuple of `(compiled_regex, description, control_id, remediation)`. When a pattern's `.search()` call matches the line, `_make_finding()` is called with the corresponding control ID, file path, line number, description, the first 120 characters of the stripped line as evidence, and the remediation string. There is no early-exit per line; a single added line can produce multiple findings if it matches more than one pattern.

**Pass 2 — Kubernetes liveness probe absence check:** After the pattern loop, the gate tests whether `diff_file.path` matches the module-level `_K8S_FILE_PATTERN` regex (see Special Detection Logic below). If it does, the gate reads `diff_file.full_content` — the complete current file content, not just added lines — and checks two conditions: (a) the string `"containers:"` is present in the full content, and (b) the `_LIVENESS_PROBE_PATTERN` regex does not match anywhere in the full content. If both conditions are true, one SI-4 finding is emitted pointing to line 1 of the file. This check is file-level rather than line-level.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?i)enable.?monitoring\s*[:=]\s*false\|monitoring\s*[:=]\s*false` | Monitoring disabled in infrastructure configuration | SI-4 | Enable monitoring and set `monitoring_interval` > 0 for all production resources |
| 2 | `(?i)monitoring.?interval\s*[:=]\s*0` | `monitoring_interval = 0` disables enhanced monitoring | SI-4 | Set `monitoring_interval` to 60 or higher for production database instances |
| 3 | `(?i)(?:log.?driver\s*[:=]\s*["\']?none\|driver:\s*none)` | Container logging driver set to `none` — all output is discarded | AU-12 | Use a persistent logging driver (`json-file`, `awslogs`, `fluentd`) for all containers |
| 4 | `--log-driver=none` | Container logging disabled via CLI flag | AU-12 | Remove `--log-driver=none`; all container output must be captured for audit |

---

## Special Detection Logic

### Kubernetes Liveness Probe Absence Check

This check runs as a second pass inside the same `diff_file` loop, after the standard pattern scan, and operates at file level rather than line level.

**File matching — `_K8S_FILE_PATTERN`:**

```python
_K8S_FILE_PATTERN = re.compile(r"""(?i)(?:deployment|statefulset|daemonset).*\.ya?ml$""")
```

The gate first tests `diff_file.path` against `_K8S_FILE_PATTERN`. The pattern matches any file path that contains the word `deployment`, `statefulset`, or `daemonset` (case-insensitive) and ends with `.yaml` or `.yml`. Files that do not match this pattern skip the liveness probe check entirely.

**Content inspection — `_LIVENESS_PROBE_PATTERN`:**

```python
_LIVENESS_PROBE_PATTERN = re.compile(r"""livenessProbe""")
```

For matching files, the gate reads `diff_file.full_content` (the complete file content, not just the diff hunks) and evaluates two conditions:

1. The literal string `"containers:"` is present anywhere in the full content.
2. `_LIVENESS_PROBE_PATTERN.search(full_content)` returns no match — that is, the string `livenessProbe` does not appear anywhere in the file.

**Finding emitted when both conditions are true:**

- `control_id`: `"SI-4"`
- `file`: `diff_file.path`
- `line`: `1` (file-level finding; no specific line number is available)
- `description`: `"Kubernetes workload added without a livenessProbe — failure will not be detected"`
- `evidence`: `"No livenessProbe found in <diff_file.path>"`
- `remediation`: `"Add a livenessProbe (httpGet, tcpSocket, or exec) to all container specs"`

Because the check examines `full_content` rather than added lines, it fires even if the `containers:` block was present before the diff — the gate treats any diff touching a workload file without a probe as a violation.

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_monitoring_false` | A diff adding `monitoring_interval = 0` and `enable_monitoring = false` in a Terraform file produces at least one finding whose description contains "monitor" |
| `test_detects_log_driver_none` | A diff adding `driver: none` under a Docker Compose `logging` key produces at least one finding |
| `test_detects_k8s_missing_liveness_probe` | A diff adding a Kubernetes Deployment YAML with a `containers:` spec but no `livenessProbe` key produces at least one finding |
| `test_k8s_with_liveness_probe_no_findings` | A diff adding a Kubernetes Deployment YAML that includes a `livenessProbe` with an `httpGet` check produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "observability"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"SI-4", "AU-12"}` |
