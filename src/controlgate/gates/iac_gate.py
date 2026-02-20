"""Gate 5 — Infrastructure-as-Code (IaC) Gate.

Detects insecure infrastructure configurations in Terraform,
CloudFormation, Kubernetes YAML, and Dockerfiles.

NIST Controls: CM-2, CM-6, CM-7, SC-7
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_IAC_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # Network exposure
    (
        re.compile(r"""0\.0\.0\.0/0"""),
        "Unrestricted ingress rule (0.0.0.0/0) — publicly accessible",
        "SC-7",
        "Restrict ingress to specific IP ranges or CIDR blocks",
    ),
    (
        re.compile(r"""::/0"""),
        "Unrestricted IPv6 ingress rule (::/0) — publicly accessible",
        "SC-7",
        "Restrict IPv6 ingress to specific CIDR blocks",
    ),
    # Public storage
    (
        re.compile(
            r"""(?i)(?:acl|access)\s*[:=]\s*["\']?(?:public-read|public-read-write|authenticated-read)["\']?"""
        ),
        "Public access configured on storage resource",
        "SC-7",
        "Set storage ACL to private and use pre-signed URLs for controlled access",
    ),
    (
        re.compile(r"""(?i)block_public_acls\s*[:=]\s*(?:false|0)"""),
        "S3 public access block disabled",
        "SC-7",
        "Enable all S3 public access blocks: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets",
    ),
    # Container security
    (
        re.compile(
            r"""(?i)(?:USER\s+root|user:\s*["\']?root["\']?|runAsUser:\s*0|privileged:\s*true)"""
        ),
        "Container configured to run as root or privileged",
        "CM-6",
        "Run containers as non-root user. Add 'USER nonroot' in Dockerfile or set runAsNonRoot: true",
    ),
    (
        re.compile(r"""(?i)securityContext:\s*\{\s*\}|securityContext:\s*null"""),
        "Empty or null security context in Kubernetes",
        "CM-6",
        "Define securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities",
    ),
    (
        re.compile(r"""(?i)allowPrivilegeEscalation:\s*true"""),
        "Privilege escalation allowed in container",
        "CM-6",
        "Set allowPrivilegeEscalation: false",
    ),
    (
        re.compile(r"""(?i)hostNetwork:\s*true"""),
        "Container using host network",
        "CM-7",
        "Avoid hostNetwork unless absolutely necessary; use network policies instead",
    ),
    (
        re.compile(r"""(?i)hostPID:\s*true|hostIPC:\s*true"""),
        "Container sharing host PID or IPC namespace",
        "CM-7",
        "Disable hostPID and hostIPC unless required for specific system containers",
    ),
    # Resource limits
    (
        re.compile(r"""(?i)resources:\s*\{\s*\}|resources:\s*null"""),
        "No resource limits defined for container",
        "CM-6",
        "Define CPU and memory resource limits to prevent resource exhaustion attacks",
    ),
    # Exposed ports
    (
        re.compile(
            r"""(?i)(?:containerPort|hostPort|port):\s*(?:22|3389|5432|3306|6379|27017|9200)\b"""
        ),
        "Sensitive service port directly exposed",
        "CM-7",
        "Avoid exposing sensitive service ports directly; use network policies and internal load balancers",
    ),
    # Insecure defaults
    (
        re.compile(
            r"""(?i)(?:encryption|encrypted|encrypt)\s*[:=]\s*(?:false|0|off|none|disabled)"""
        ),
        "Encryption explicitly disabled in infrastructure configuration",
        "CM-6",
        "Enable encryption at rest and in transit for all data stores and communication channels",
    ),
    (
        re.compile(r"""(?i)logging\s*[:=]\s*(?:false|disabled|off|0)"""),
        "Logging disabled in infrastructure configuration",
        "CM-6",
        "Enable logging for all infrastructure components for audit and incident response",
    ),
    (
        re.compile(r"""(?i)versioning\s*[:=]\s*(?:false|disabled|off|0)"""),
        "Versioning disabled on storage resource",
        "CM-2",
        "Enable versioning for data protection and recovery capability",
    ),
]


class IaCGate(BaseGate):
    """Gate 5: Detect insecure infrastructure-as-code configurations."""

    name = "Infrastructure-as-Code Gate"
    gate_id = "iac"
    mapped_control_ids = ["CM-2", "CM-6", "CM-7", "SC-7"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            # Focus on IaC files
            if not self._is_iac_file(diff_file.path):
                continue

            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _is_iac_file(self, path: str) -> bool:
        """Check if a file is an infrastructure-as-code file."""
        iac_extensions = (
            ".tf",
            ".tfvars",
            ".hcl",  # Terraform
            ".yaml",
            ".yml",  # K8s, CloudFormation, Docker Compose
            ".json",  # CloudFormation, ARM templates
            "Dockerfile",  # Docker
        )
        iac_paths = (
            "terraform/",
            "infra/",
            "infrastructure/",
            "deploy/",
            "k8s/",
            "kubernetes/",
            "helm/",
            ".github/",
            "cloudformation/",
            "cdk/",
        )
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in iac_extensions):
            return True
        if any(segment in lower_path for segment in iac_paths):  # pragma: no cover
            return True
        return bool("Dockerfile" in path or "docker-compose" in path.lower())

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []

        for pattern, description, control_id, remediation in _IAC_PATTERNS:
            if pattern.search(line):
                findings.append(
                    self._make_finding(
                        control_id=control_id,
                        file=file_path,
                        line=line_no,
                        description=description,
                        evidence=line.strip()[:120],
                        remediation=remediation,
                    )
                )

        return findings
