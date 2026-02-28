"""Tests for hooks/bump_version.py"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# bump_version.py lives in hooks/, not src/ — import it directly
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))
import bump_version  # noqa: E402

PYPROJECT_SAME = '[project]\nname = "controlgate"\nversion = "0.1.7"\n'
PYPROJECT_MAIN = '[project]\nname = "controlgate"\nversion = "0.1.7"\n'
PYPROJECT_HIGHER = '[project]\nname = "controlgate"\nversion = "0.2.0"\n'


class TestParseVersion:
    def test_parses_version_from_content(self):
        assert bump_version.parse_version(PYPROJECT_SAME) == (0, 1, 7)

    def test_raises_on_missing_version(self):
        with pytest.raises(SystemExit):
            bump_version.parse_version("[project]\nname = 'x'\n")


class TestBumpMinor:
    def test_bumps_minor_and_resets_patch(self):
        assert bump_version.bump_minor((0, 1, 7)) == (0, 2, 0)

    def test_bumps_minor_on_zero_patch(self):
        assert bump_version.bump_minor((0, 2, 0)) == (0, 3, 0)

    def test_preserves_major(self):
        assert bump_version.bump_minor((1, 5, 3)) == (1, 6, 0)


class TestWriteVersion:
    def test_replaces_version_in_content(self):
        result = bump_version.write_version(PYPROJECT_SAME, (0, 2, 0))
        assert 'version = "0.2.0"' in result
        assert 'version = "0.1.7"' not in result


class TestGetMainVersion:
    def test_returns_tuple_when_origin_available(self):
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with patch("subprocess.run", return_value=mock_result):
            assert bump_version.get_main_version() == (0, 1, 7)

    def test_returns_none_when_origin_unavailable(self, capsys):
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, "git")):
            result = bump_version.get_main_version()
        assert result is None
        captured = capsys.readouterr()
        assert "warning" in captured.out.lower()

    def test_returns_none_when_git_not_found(self, capsys):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = bump_version.get_main_version()
        assert result is None


class TestMain:
    def test_bumps_and_stages_when_versions_match(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_SAME)
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", return_value=mock_result),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        assert 'version = "0.2.0"' in pyproject.read_text()

    def test_skips_when_versions_differ(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_HIGHER)
        mock_result = type("R", (), {"returncode": 0, "stdout": PYPROJECT_MAIN})()
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", return_value=mock_result),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        assert 'version = "0.2.0"' in pyproject.read_text()  # unchanged

    def test_passes_when_origin_unavailable(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(PYPROJECT_SAME)
        with (
            patch("bump_version.PYPROJECT_PATH", pyproject),
            patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, "git")),
        ):
            exit_code = bump_version.main()
        assert exit_code == 0
        # Version unchanged since we couldn't compare
        assert 'version = "0.1.7"' in pyproject.read_text()
