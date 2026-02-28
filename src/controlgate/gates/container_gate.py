"""Gate 18 — Container Security Gate.

Detects container and Kubernetes misconfigurations across five security domains:
image integrity, least privilege, network isolation, runtime hardening, and audit.

NIST Controls: CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3

Note: Each pattern uses a single primary control ID (most directly relevant).
Secondary controls are noted in remediation text.
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# ── IMAGE INTEGRITY (primary: SI-7) ──────────────────────────────────────────
_IMAGE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""FROM\s+\S+:latest"""),
        "Unpinned :latest tag — image may change between builds, breaking reproducibility",
        "SI-7",
        "Pin to a specific version tag or use a digest: FROM python@sha256:<hash>",
    ),
    (
        re.compile(r"""^FROM\s+[^\s@:]+\s*$""", re.MULTILINE),
        "Base image has no tag — always pin to a specific digest or version",
        "SI-7",
        "Add a version tag or SHA256 digest: FROM python:3.11-slim@sha256:<hash>",
    ),
    (
        re.compile(r"""ADD\s+https?://"""),
        "Remote ADD fetches content at build time without checksum verification",
        "SI-7",
        "Use RUN curl ... | sha256sum -c and COPY instead of ADD with remote URLs",
    ),
]

# ── LEAST PRIVILEGE (primary: AC-6) ──────────────────────────────────────────
_PRIVILEGE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""USER\s+root"""),
        "Container explicitly set to run as root — violates least privilege",
        "AC-6",
        "Create a dedicated non-root user: RUN useradd -r app && USER app",
    ),
    (
        re.compile(r"""(?i)privileged:\s*true|--privileged"""),
        "Privileged container grants full host access — enables container escape",
        "AC-6",
        "Remove privileged: true; grant only specific capabilities if needed",
    ),
    (
        re.compile(r"""--cap-add\s+ALL"""),
        "ALL Linux capabilities granted — equivalent to running as root",
        "AC-6",
        "Enumerate only the specific capabilities required (e.g. --cap-add NET_BIND_SERVICE)",
    ),
    (
        re.compile(r"""--cap-add\s+(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN)"""),
        "High-risk Linux capability granted — can lead to host privilege escalation",
        "AC-6",
        "Audit whether this capability is truly needed; prefer dropping all caps and adding selectively",
    ),
    (
        re.compile(r"""allowPrivilegeEscalation:\s*true"""),
        "allowPrivilegeEscalation: true permits setuid/setgid escalation inside the container",
        "AC-6",
        "Set allowPrivilegeEscalation: false in securityContext",
    ),
    (
        re.compile(r"""runAsNonRoot:\s*false"""),
        "runAsNonRoot: false explicitly permits the container to run as root",
        "AC-6",
        "Set runAsNonRoot: true and specify runAsUser with a non-zero UID",
    ),
]

# ── NETWORK ISOLATION (primary: SC-7) ────────────────────────────────────────
_NETWORK_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""hostNetwork:\s*true"""),
        "hostNetwork: true exposes the container on the host network namespace",
        "SC-7",
        "Use ClusterIP or NodePort Services; avoid sharing the host network namespace",
    ),
    (
        re.compile(r"""hostPort:\s*\d+"""),
        "hostPort bypasses Kubernetes NetworkPolicy — use Service resources instead",
        "SC-7",
        "Replace hostPort with a Kubernetes Service of type NodePort or LoadBalancer",
    ),
]

# ── RUNTIME HARDENING (primary: SC-39) ───────────────────────────────────────
_RUNTIME_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""readOnlyRootFilesystem:\s*false"""),
        "Writable root filesystem — allows attacker to modify container files",
        "SC-39",
        "Set readOnlyRootFilesystem: true and use emptyDir/PVC mounts for writable paths",
    ),
    (
        re.compile(r"""hostPID:\s*true"""),
        "hostPID: true shares the host process namespace — enables container escape vectors",
        "SC-39",
        "Remove hostPID: true; process isolation must be maintained",
    ),
    (
        re.compile(r"""hostIPC:\s*true"""),
        "hostIPC: true shares host IPC namespace — allows cross-container memory access",
        "SC-39",
        "Remove hostIPC: true; IPC namespace isolation must be maintained",
    ),
    (
        re.compile(r"""(?i)seccompProfile.*Unconfined|seccomp.*unconfined"""),
        "Seccomp profile set to Unconfined — all syscalls permitted",
        "SC-39",
        "Use RuntimeDefault seccomp profile or create a custom restricted profile",
    ),
]

# ── AUDIT (primary: AU-12) ────────────────────────────────────────────────────
_AUDIT_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?i)log.?driver.*none"""),
        "Container logging driver set to 'none' — all container output is discarded",
        "AU-12",
        "Use a persistent logging driver (json-file, awslogs, fluentd, splunk)",
    ),
    (
        re.compile(r"""--log-driver=none"""),
        "Container logging disabled via CLI flag — cannot audit container activity",
        "AU-12",
        "Remove --log-driver=none; use a centralised logging destination",
    ),
]

# ── RESOURCE LIMITS (primary: CM-6) ──────────────────────────────────────────
_RESOURCE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""resources:\s*\{\}"""),
        "Empty resources block — no CPU/memory limits set; enables denial-of-service",
        "CM-6",
        "Set explicit resources.requests and resources.limits for CPU and memory",
    ),
    (
        re.compile(r"""--memory[= ]["\']?-1"""),
        "Unlimited container memory allocation — no ceiling for memory consumption",
        "CM-6",
        "Set an explicit --memory limit (e.g. --memory=512m)",
    ),
]

_ALL_PATTERN_GROUPS = [
    _IMAGE_PATTERNS,
    _PRIVILEGE_PATTERNS,
    _NETWORK_PATTERNS,
    _RUNTIME_PATTERNS,
    _AUDIT_PATTERNS,
    _RESOURCE_PATTERNS,
]


class ContainerGate(BaseGate):
    """Gate 18: Detect container and Kubernetes security misconfigurations."""

    name = "Container Security Gate"
    gate_id = "container"
    mapped_control_ids = ["CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern_group in _ALL_PATTERN_GROUPS:
                    for pattern, description, control_id, remediation in pattern_group:
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
        return findings
