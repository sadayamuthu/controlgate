"""Tests for full-repo scan mode."""

from unittest.mock import MagicMock, patch

from controlgate.__main__ import _get_full_files
from controlgate.config import ControlGateConfig


class TestGetFullFiles:
    def test_returns_diff_files(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\ny = 2\n")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert any(f.path.endswith("app.py") for f in files)

    def test_all_lines_are_added(self, tmp_path):
        (tmp_path / "app.py").write_text("line1\nline2\nline3\n")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        py_file = next(f for f in files if f.path.endswith("app.py"))
        assert len(py_file.all_added_lines) == 3
        assert py_file.all_added_lines[0] == (1, "line1")
        assert py_file.all_added_lines[2] == (3, "line3")

    def test_skips_excluded_paths(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "readme.md").write_text("# Docs")
        config = ControlGateConfig.load()
        # docs/** is in default exclusions
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        paths = [f.path for f in files]
        assert not any("docs" in p for p in paths)

    def test_skips_skip_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text("module.exports = {}")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any("node_modules" in f.path for f in files)

    def test_skips_unlisted_extensions(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith(".png") for f in files)

    def test_skips_binary_files(self, tmp_path):
        (tmp_path / "app.py").write_bytes(b"normal\x00binary\x00content")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith("app.py") for f in files)

    def test_uses_git_ls_files_when_available(self, tmp_path):
        (tmp_path / "tracked.py").write_text("x = 1")
        config = ControlGateConfig.load()
        mock_result = MagicMock()
        mock_result.stdout = "tracked.py\n"
        mock_result.returncode = 0
        with patch("controlgate.__main__.subprocess.run", return_value=mock_result):
            files = _get_full_files(tmp_path, config)
        assert any(f.path.endswith("tracked.py") for f in files)

    def test_skips_empty_files(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        config = ControlGateConfig.load()
        with patch("controlgate.__main__.subprocess.run", side_effect=FileNotFoundError):
            files = _get_full_files(tmp_path, config)
        assert not any(f.path.endswith("empty.py") for f in files)
