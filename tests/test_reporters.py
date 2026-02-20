"""Tests for reporters (JSON, Markdown, SARIF)."""

import json
import tempfile
from pathlib import Path

import pytest

from controlgate.models import Action, Finding, GateSummary, Verdict
from controlgate.reporters.json_reporter import JSONReporter
from controlgate.reporters.markdown_reporter import MarkdownReporter
from controlgate.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_verdict():
    findings = [
        Finding(
            gate="secrets",
            control_id="SC-28",
            control_name="Protection of Information at Rest",
            severity="HIGH",
            non_negotiable=True,
            file="config.py",
            line=10,
            description="Hardcoded credential detected",
            evidence='DB_PASSWORD = "secret"',
            remediation="Use environment variable",
            action=Action.BLOCK.value,
        ),
        Finding(
            gate="crypto",
            control_id="SC-13",
            control_name="Cryptographic Protection",
            severity="MEDIUM",
            non_negotiable=True,
            file="auth.py",
            line=5,
            description="Weak hash algorithm MD5 detected",
            evidence="hashlib.md5(data)",
            remediation="Use SHA-256",
            action=Action.WARN.value,
        ),
    ]
    return Verdict(
        verdict=Action.BLOCK.value,
        timestamp="2026-02-20T00:00:00+00:00",
        summary="1 BLOCK, 1 WARN, 0 PASS findings",
        baseline_target="moderate",
        findings=findings,
        gate_summary={
            "secrets": GateSummary(status=Action.BLOCK.value, findings=1),
            "crypto": GateSummary(status=Action.WARN.value, findings=1),
        },
    )


@pytest.fixture
def clean_verdict():
    return Verdict(
        verdict=Action.PASS.value,
        timestamp="2026-02-20T00:00:00+00:00",
        summary="0 BLOCK, 0 WARN, 0 PASS findings",
        baseline_target="moderate",
        findings=[],
        gate_summary={},
    )


class TestJSONReporter:
    def test_render_valid_json(self, sample_verdict):
        reporter = JSONReporter()
        output = reporter.render(sample_verdict)
        data = json.loads(output)
        assert data["verdict"] == "BLOCK"
        assert len(data["findings"]) == 2

    def test_render_clean_verdict(self, clean_verdict):
        reporter = JSONReporter()
        output = reporter.render(clean_verdict)
        data = json.loads(output)
        assert data["verdict"] == "PASS"
        assert len(data["findings"]) == 0

    def test_write_to_file(self, sample_verdict):
        reporter = JSONReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/output/verdict.json"
            reporter.write(sample_verdict, path)
            assert Path(path).exists()
            data = json.loads(Path(path).read_text())
            assert data["verdict"] == "BLOCK"


class TestMarkdownReporter:
    def test_render_contains_verdict(self, sample_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(sample_verdict)
        assert "BLOCK" in output
        assert "ControlGate Verdict" in output

    def test_render_contains_gate_table(self, sample_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(sample_verdict)
        assert "| Gate | Status | Findings |" in output
        assert "Secrets" in output
        assert "Crypto" in output

    def test_render_contains_blocking_findings(self, sample_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(sample_verdict)
        assert "Blocking Findings" in output
        assert "SC-28" in output
        assert "Hardcoded credential" in output

    def test_render_contains_warnings(self, sample_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(sample_verdict)
        assert "Warnings" in output
        assert "SC-13" in output

    def test_render_clean_verdict(self, clean_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(clean_verdict)
        assert "All clear" in output
        assert "PASS" in output

    def test_render_non_negotiable_label(self, sample_verdict):
        reporter = MarkdownReporter()
        output = reporter.render(sample_verdict)
        assert "non-negotiable" in output

    def test_write_to_file(self, sample_verdict):
        reporter = MarkdownReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/output/verdict.md"
            reporter.write(sample_verdict, path)
            assert Path(path).exists()
            content = Path(path).read_text()
            assert "BLOCK" in content


class TestSARIFReporter:
    def test_render_valid_json(self, sample_verdict):
        reporter = SARIFReporter()
        output = reporter.render(sample_verdict)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_render_has_results(self, sample_verdict):
        reporter = SARIFReporter()
        output = reporter.render(sample_verdict)
        data = json.loads(output)
        run = data["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 2

    def test_result_severity_mapping(self, sample_verdict):
        reporter = SARIFReporter()
        output = reporter.render(sample_verdict)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels  # HIGH → error
        assert "warning" in levels  # MEDIUM → warning

    def test_result_locations(self, sample_verdict):
        reporter = SARIFReporter()
        output = reporter.render(sample_verdict)
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "config.py"
        assert loc["region"]["startLine"] == 10

    def test_render_clean_verdict(self, clean_verdict):
        reporter = SARIFReporter()
        output = reporter.render(clean_verdict)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0

    def test_deduplicated_rules(self):
        """Same gate+control should only produce one rule entry."""
        findings = [
            Finding(
                gate="secrets",
                control_id="SC-28",
                control_name="Test",
                severity="HIGH",
                non_negotiable=True,
                file="a.py",
                line=1,
                description="Finding 1",
                evidence="ev1",
                remediation="fix",
                action="BLOCK",
            ),
            Finding(
                gate="secrets",
                control_id="SC-28",
                control_name="Test",
                severity="HIGH",
                non_negotiable=True,
                file="b.py",
                line=2,
                description="Finding 2",
                evidence="ev2",
                remediation="fix",
                action="BLOCK",
            ),
        ]
        verdict = Verdict(
            verdict="BLOCK",
            timestamp="t",
            summary="s",
            baseline_target="moderate",
            findings=findings,
            gate_summary={},
        )
        reporter = SARIFReporter()
        data = json.loads(reporter.render(verdict))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # Deduplicated
        assert len(data["runs"][0]["results"]) == 2

    def test_write_to_file(self, sample_verdict):
        reporter = SARIFReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/verdict.sarif"
            reporter.write(sample_verdict, path)
            assert Path(path).exists()
