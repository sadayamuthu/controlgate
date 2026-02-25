"""Configuration management for ControlGate."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore

_DEFAULT_CONFIG = {
    "baseline": "moderate",
    "gov": False,
    "catalog": "baseline/nist80053r5_full_catalog_enriched.json",
    "gates": {
        "secrets": {"enabled": True, "action": "block"},
        "crypto": {"enabled": True, "action": "block"},
        "iam": {"enabled": True, "action": "warn"},
        "sbom": {"enabled": True, "action": "warn"},
        "iac": {"enabled": True, "action": "block"},
        "input": {"enabled": True, "action": "block"},
        "audit": {"enabled": True, "action": "warn"},
        "change": {"enabled": True, "action": "warn"},
    },
    "thresholds": {
        "block_on": ["CRITICAL", "HIGH"],
        "warn_on": ["MEDIUM"],
        "ignore": ["LOW"],
    },
    "exclusions": {
        "paths": ["tests/**", "docs/**", "*.md"],
        "controls": ["AC-13", "AC-15"],
    },
    "reporting": {
        "format": ["json", "markdown"],
        "sarif": False,
        "output_dir": ".controlgate/reports",
    },
}


@dataclass
class GateConfig:
    """Configuration for a single gate."""

    enabled: bool = True
    action: str = "warn"


@dataclass
class ControlGateConfig:
    """Full ControlGate configuration loaded from `.controlgate.yml`."""

    baseline: str = "moderate"
    is_gov: bool = False
    catalog_path: str = "baseline/nist80053r5_full_catalog_enriched.json"
    gates: dict[str, GateConfig] = field(default_factory=dict)
    block_on: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    warn_on: list[str] = field(default_factory=lambda: ["MEDIUM"])
    ignore: list[str] = field(default_factory=lambda: ["LOW"])
    excluded_paths: list[str] = field(default_factory=lambda: ["tests/**", "docs/**", "*.md"])
    excluded_controls: list[str] = field(default_factory=lambda: ["AC-13", "AC-15"])
    report_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    sarif_enabled: bool = False
    output_dir: str = ".controlgate/reports"

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> ControlGateConfig:
        """Load configuration from a YAML file, falling back to defaults.

        Search order:
        1. Explicit ``config_path`` argument
        2. ``.controlgate.yml`` in the current directory
        3. Built-in defaults
        """
        raw: dict[str, Any] = dict(_DEFAULT_CONFIG)

        search_paths: list[Path] = []
        if config_path:
            search_paths.append(Path(config_path))
        search_paths.append(Path(".controlgate.yml"))

        for path in search_paths:
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                if loaded and isinstance(loaded, dict):
                    raw = _deep_merge(raw, loaded)
                break

        return cls._from_raw(raw)

    @classmethod
    def _from_raw(cls, raw: dict[str, Any]) -> ControlGateConfig:
        """Build config from a raw dict (merged defaults + user overrides)."""
        cfg = cls()
        cfg.baseline = raw.get("baseline", cfg.baseline)
        cfg.is_gov = raw.get("gov", cfg.is_gov)
        cfg.catalog_path = raw.get("catalog", cfg.catalog_path)

        # Gates
        gates_raw = raw.get("gates", {})
        for name, settings in gates_raw.items():
            if isinstance(settings, dict):
                cfg.gates[name] = GateConfig(
                    enabled=settings.get("enabled", True),
                    action=settings.get("action", "warn"),
                )

        # Thresholds
        thresholds = raw.get("thresholds", {})
        cfg.block_on = thresholds.get("block_on", cfg.block_on)
        cfg.warn_on = thresholds.get("warn_on", cfg.warn_on)
        cfg.ignore = thresholds.get("ignore", cfg.ignore)

        # Exclusions
        exclusions = raw.get("exclusions", {})
        cfg.excluded_paths = exclusions.get("paths", cfg.excluded_paths)
        cfg.excluded_controls = exclusions.get("controls", cfg.excluded_controls)

        # Reporting
        reporting = raw.get("reporting", {})
        cfg.report_formats = reporting.get("format", cfg.report_formats)
        cfg.sarif_enabled = reporting.get("sarif", cfg.sarif_enabled)
        cfg.output_dir = reporting.get("output_dir", cfg.output_dir)

        return cfg

    def is_gate_enabled(self, gate_name: str) -> bool:
        """Check if a gate is enabled in the config."""
        gc = self.gates.get(gate_name)
        if gc is None:
            return True  # enabled by default
        return gc.enabled

    def is_path_excluded(self, file_path: str) -> bool:
        """Check if a file path is excluded by glob patterns."""
        from fnmatch import fnmatch

        return any(fnmatch(file_path, pattern) for pattern in self.excluded_paths)

    def is_control_excluded(self, control_id: str) -> bool:
        """Check if a control ID is explicitly excluded."""
        return control_id in self.excluded_controls


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge override dict into base dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
