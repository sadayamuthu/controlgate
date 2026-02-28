"""Tests for the controlgate init command."""

import argparse
from unittest.mock import patch

from controlgate.init_command import (
    _build_bitbucket_pipelines,
    _build_controlgate_md,
    _build_controlgate_yml,
    _build_github_workflow,
    _build_gitlab_ci,
    _build_precommit_config,
)


class TestTemplates:
    def test_controlgate_yml_contains_all_18_gates(self):
        content = _build_controlgate_yml("moderate")
        for gate in [
            "secrets",
            "crypto",
            "iam",
            "sbom",
            "iac",
            "input_validation",
            "audit",
            "change_control",
            "deps",
            "api",
            "privacy",
            "resilience",
            "incident",
            "observability",
            "memsafe",
            "license",
            "aiml",
            "container",
        ]:
            assert gate in content, f"Gate '{gate}' missing from template"

    def test_controlgate_yml_has_chosen_baseline(self):
        content = _build_controlgate_yml("high")
        assert "baseline: high" in content

    def test_precommit_config_has_controlgate_hook(self):
        content = _build_precommit_config()
        assert "controlgate" in content
        assert "pre-commit" in content

    def test_controlgate_md_has_all_modes(self):
        content = _build_controlgate_md()
        assert "--mode pre-commit" in content
        assert "--mode pr" in content
        assert "--mode full" in content

    def test_controlgate_md_has_18_gates_table(self):
        content = _build_controlgate_md()
        for gate_name in [
            "Secrets",
            "Crypto",
            "IAM",
            "Supply Chain",
            "IaC",
            "Input Validation",
            "Audit",
            "Change Control",
            "Dependencies",
            "API Security",
            "Privacy",
            "Resilience",
            "Incident Response",
            "Observability",
            "Memory Safety",
            "License Compliance",
            "AI/ML Security",
            "Container Security",
        ]:
            assert gate_name in content, f"Gate '{gate_name}' missing from CONTROLGATE.md"

    def test_github_workflow_has_pr_trigger(self):
        content = _build_github_workflow()
        assert "pull_request" in content
        assert "controlgate scan" in content

    def test_gitlab_ci_has_controlgate_job(self):
        content = _build_gitlab_ci()
        assert "controlgate" in content
        assert "controlgate scan" in content

    def test_bitbucket_pipelines_has_controlgate_step(self):
        content = _build_bitbucket_pipelines()
        assert "controlgate" in content
        assert "controlgate scan" in content


class TestInitCommand:
    def test_creates_controlgate_yml(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".controlgate.yml").exists()

    def test_creates_precommit_config(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".pre-commit-config.yaml").exists()

    def test_creates_controlgate_md_by_default(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / "CONTROLGATE.md").exists()

    def test_no_docs_skips_controlgate_md(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=True)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert not (tmp_path / "CONTROLGATE.md").exists()

    def test_creates_github_workflow_when_confirmed(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "y", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert (tmp_path / ".github" / "workflows" / "controlgate.yml").exists()

    def test_skips_github_workflow_when_denied(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        assert not (tmp_path / ".github" / "workflows" / "controlgate.yml").exists()

    def test_overwrite_prompt_on_existing_file(self, tmp_path):
        from controlgate.init_command import init_command

        (tmp_path / ".controlgate.yml").write_text("existing: true\n")
        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        # overwrite .controlgate.yml prompt → n, then CI prompts → n, n, n
        inputs = iter(["moderate", "n", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            init_command(args)
        # Original content preserved
        assert "existing: true" in (tmp_path / ".controlgate.yml").read_text()

    def test_returns_zero_on_success(self, tmp_path):
        from controlgate.init_command import init_command

        args = argparse.Namespace(path=str(tmp_path), baseline="moderate", no_docs=False)
        inputs = iter(["moderate", "n", "n", "n"])
        with patch("builtins.input", side_effect=inputs):
            result = init_command(args)
        assert result == 0
