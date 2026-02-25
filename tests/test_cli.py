"""Tests for the CLI entry point (__main__.py)."""

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from controlgate.__main__ import (
    _get_diff,
    _resolve_catalog_path,
    build_parser,
    catalog_info_command,
    main,
    scan_command,
    update_catalog_command,
)
from controlgate.catalog_downloader import get_catalog_path
from controlgate.config import ControlGateConfig

_SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,2 @@
+DB_PASSWORD = "secret123"
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
"""


class TestBuildParser:
    def test_parser_has_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.command == "scan"

    def test_parser_has_update_catalog_command(self):
        parser = build_parser()
        args = parser.parse_args(["update-catalog"])
        assert args.command == "update-catalog"

    def test_parser_has_catalog_info_command(self):
        parser = build_parser()
        args = parser.parse_args(["catalog-info"])
        assert args.command == "catalog-info"

    def test_scan_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.mode == "pre-commit"
        assert args.target_branch == "main"
        assert args.format is None
        assert args.baseline is None

    def test_scan_with_options(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "scan",
                "--mode",
                "pr",
                "--baseline",
                "high",
                "--format",
                "json",
                "sarif",
                "--target-branch",
                "develop",
            ]
        )
        assert args.mode == "pr"
        assert args.baseline == "high"
        assert args.format == ["json", "sarif"]
        assert args.target_branch == "develop"


class TestGetDiff:
    def test_pre_commit_mode(self):
        with patch("controlgate.__main__.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="diff output")
            result = _get_diff("pre-commit")
            assert result == "diff output"
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "--cached" in cmd

    def test_pr_mode(self):
        with patch("controlgate.__main__.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="diff output")
            result = _get_diff("pr", "develop")
            assert result == "diff output"
            cmd = mock_run.call_args[0][0]
            assert "develop...HEAD" in cmd

    def test_git_error_exits(self):
        with patch("controlgate.__main__.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git", stderr="error")
            with pytest.raises(SystemExit):
                _get_diff("pre-commit")

    def test_git_not_found_exits(self):
        with patch("controlgate.__main__.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            with pytest.raises(SystemExit):
                _get_diff("pre-commit")


class TestResolveCatalogPath:
    def test_finds_bundled_catalog(self):
        config = ControlGateConfig()
        path = _resolve_catalog_path(config)
        assert path.exists()
        assert "nist80053r5" in path.name

    def test_finds_absolute_path(self):
        config = ControlGateConfig()
        config.catalog_path = str(get_catalog_path())
        with (
            patch("controlgate.catalog_downloader.get_catalog_path", side_effect=ConnectionError),
            patch("controlgate.catalog_downloader.download_catalog", side_effect=ConnectionError),
        ):
            path = _resolve_catalog_path(config)
            assert path.exists()

    def test_exits_when_not_found(self):
        config = ControlGateConfig()
        config.catalog_path = "/nonexistent/catalog.json"
        with (
            patch("controlgate.catalog_downloader._PACKAGE_DATA_DIR", Path("/nonexistent")),
            patch("controlgate.catalog_downloader.download_catalog", side_effect=ConnectionError),
            patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError),
            pytest.raises(SystemExit),
        ):
            _resolve_catalog_path(config)


class TestScanCommand:
    def test_scan_with_diff_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "json",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 1  # BLOCK due to secrets

    def test_scan_clean_code(self):
        clean_diff = """\
diff --git a/utils.py b/utils.py
new file mode 100644
--- /dev/null
+++ b/utils.py
@@ -0,0 +1,2 @@
+import os
+env = os.environ.get("KEY")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(clean_diff)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "json",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 0  # PASS

    def test_scan_empty_diff(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write("")
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "json",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 0

    def test_scan_markdown_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "markdown",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 1

    def test_scan_sarif_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "sarif",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 1

    def test_scan_with_output_dir(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            with tempfile.TemporaryDirectory() as tmpdir:
                parser = build_parser()
                args = parser.parse_args(
                    [
                        "scan",
                        "--diff-file",
                        f.name,
                        "--format",
                        "json",
                        "markdown",
                        "sarif",
                        "--output-dir",
                        tmpdir,
                    ]
                )
                scan_command(args)
                assert (Path(tmpdir) / "verdict.json").exists()
                assert (Path(tmpdir) / "verdict.md").exists()
                assert (Path(tmpdir) / "verdict.sarif").exists()

    def test_scan_with_baseline_override(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "json",
                    "--baseline",
                    "high",
                ]
            )
            exit_code = scan_command(args)
            assert exit_code == 1

    def test_scan_with_gov_flag(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write(_SAMPLE_DIFF)
            f.flush()
            parser = build_parser()
            args = parser.parse_args(
                [
                    "scan",
                    "--diff-file",
                    f.name,
                    "--format",
                    "json",
                    "--gov",
                ]
            )
            # Just asserting it doesn't crash and returns 1 because of findings
            exit_code = scan_command(args)
            assert exit_code == 1

    def test_scan_uses_git_diff_when_no_file(self):
        """When no --diff-file is given, it uses git diff."""
        parser = build_parser()
        args = parser.parse_args(["scan", "--format", "json"])
        with patch("controlgate.__main__._get_diff", return_value="") as mock_diff:
            exit_code = scan_command(args)
            assert exit_code == 0
            mock_diff.assert_called_once()

    def test_scan_default_formats_from_config(self):
        """When no --format given, uses config.report_formats."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write("")
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["scan", "--diff-file", f.name])
            exit_code = scan_command(args)
            assert exit_code == 0


class TestUpdateCatalogCommand:
    def test_successful_update(self):
        with patch("controlgate.catalog_downloader.download_catalog") as mock_dl:
            mock_dl.return_value = Path("/fake/path/catalog.json")
            exit_code = update_catalog_command()
            assert exit_code == 0

    def test_failed_update(self):
        with patch("controlgate.catalog_downloader.download_catalog") as mock_dl:
            mock_dl.side_effect = ConnectionError("Network error")
            exit_code = update_catalog_command()
            assert exit_code == 1


class TestCatalogInfoCommand:
    def test_catalog_info(self):
        exit_code = catalog_info_command()
        assert exit_code == 0

    def test_catalog_info_no_catalog(self):
        with (
            patch("controlgate.catalog_downloader._PACKAGE_DATA_DIR", Path("/nonexistent")),
            patch("controlgate.catalog_downloader.download_catalog", side_effect=ConnectionError),
        ):
            exit_code = catalog_info_command()
            assert exit_code == 1


class TestMain:
    def test_main_no_command(self):
        with patch("sys.argv", ["controlgate"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_main_scan_command(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write("")
            f.flush()
            with patch(
                "sys.argv", ["controlgate", "scan", "--diff-file", f.name, "--format", "json"]
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

    def test_main_update_catalog(self):
        with patch("controlgate.catalog_downloader.download_catalog") as mock_dl:
            mock_dl.return_value = Path("/fake/path")
            with patch("sys.argv", ["controlgate", "update-catalog"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

    def test_main_catalog_info(self):
        with patch("sys.argv", ["controlgate", "catalog-info"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
