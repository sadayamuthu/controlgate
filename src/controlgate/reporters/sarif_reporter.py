"""SARIF 2.1.0 verdict reporter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from controlgate.models import Verdict

_SARIF_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


class SARIFReporter:
    """Render a Verdict in SARIF 2.1.0 format for GitHub Code Scanning."""

    def render(self, verdict: Verdict) -> str:
        """Render the verdict as a SARIF 2.1.0 JSON string."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        seen_rules: dict[str, int] = {}

        for finding in verdict.findings:
            # Build rule entry (deduplicate by control_id + gate)
            rule_id = f"controlgate/{finding.gate}/{finding.control_id}"
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "name": finding.control_name,
                        "shortDescription": {
                            "text": f"[{finding.control_id}] {finding.control_name}"
                        },
                        "fullDescription": {"text": finding.description},
                        "helpUri": f"https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#/control?version=5.1&number={finding.control_id}",
                        "properties": {
                            "tags": [
                                "security",
                                f"nist-{finding.control_id}",
                                finding.gate,
                            ]
                        },
                    }
                )

            # Build result entry
            results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": seen_rules[rule_id],
                    "level": _SARIF_SEVERITY_MAP.get(finding.severity, "note"),
                    "message": {
                        "text": f"{finding.description}\n\n"
                        f"**Remediation**: {finding.remediation}\n\n"
                        f"**NIST Control**: {finding.control_id} — {finding.control_name}\n"
                        f"**Non-negotiable**: {'Yes' if finding.non_negotiable else 'No'}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file},
                                "region": {
                                    "startLine": finding.line,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "controlgate-action": finding.action,
                        "controlgate-gate": finding.gate,
                        "non-negotiable": finding.non_negotiable,
                    },
                }
            )

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ControlGate",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/controlgate",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def write(self, verdict: Verdict, output_path: str) -> None:
        """Write the verdict to a SARIF file."""
        from pathlib import Path

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(verdict), encoding="utf-8")
