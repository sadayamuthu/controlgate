"""Gate 14 — Observability Gate.

Detects removal of metrics, health probes, and monitoring configuration —
distinct from the Audit gate which focuses on log content.

NIST Controls: SI-4, AU-12
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?i)enable.?monitoring\s*[:=]\s*false|monitoring\s*[:=]\s*false"""),
        "Monitoring disabled in infrastructure configuration",
        "SI-4",
        "Enable monitoring and set monitoring_interval > 0 for all production resources",
    ),
    (
        re.compile(r"""(?i)monitoring.?interval\s*[:=]\s*0"""),
        "monitoring_interval = 0 disables enhanced monitoring",
        "SI-4",
        "Set monitoring_interval to 60 or higher for production database instances",
    ),
    (
        re.compile(r"""(?i)(?:log.?driver\s*[:=]\s*["\']?none|driver:\s*none)"""),
        "Container logging driver set to 'none' — all output is discarded",
        "AU-12",
        "Use a persistent logging driver (json-file, awslogs, fluentd) for all containers",
    ),
    (
        re.compile(r"""--log-driver=none"""),
        "Container logging disabled via CLI flag",
        "AU-12",
        "Remove --log-driver=none; all container output must be captured for audit",
    ),
]

# Kubernetes deployment file pattern — needs separate handling
_K8S_FILE_PATTERN = re.compile(r"""(?i)(?:deployment|statefulset|daemonset).*\.ya?ml$""")
_LIVENESS_PROBE_PATTERN = re.compile(r"""livenessProbe""")


class ObservabilityGate(BaseGate):
    """Gate 14: Detect removal of monitoring, health probes, and observability."""

    name = "Observability Gate"
    gate_id = "observability"
    mapped_control_ids = ["SI-4", "AU-12"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            # Line-level pattern scan
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )

            # Kubernetes workload: flag if containers spec has no liveness probe
            if _K8S_FILE_PATTERN.search(diff_file.path):
                full_content = diff_file.full_content
                if "containers:" in full_content and not _LIVENESS_PROBE_PATTERN.search(
                    full_content
                ):
                    findings.append(
                        self._make_finding(
                            control_id="SI-4",
                            file=diff_file.path,
                            line=1,
                            description="Kubernetes workload added without a livenessProbe — failure will not be detected",
                            evidence=f"No livenessProbe found in {diff_file.path}",
                            remediation="Add a livenessProbe (httpGet, tcpSocket, or exec) to all container specs",
                        )
                    )

        return findings
