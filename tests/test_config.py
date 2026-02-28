# tests/test_config.py
from controlgate.config import ControlGateConfig


class TestFullScanConfig:
    def test_default_full_scan_extensions(self):
        config = ControlGateConfig.load()
        assert ".py" in config.full_scan_extensions
        assert ".tf" in config.full_scan_extensions

    def test_default_full_scan_skip_dirs(self):
        config = ControlGateConfig.load()
        assert ".git" in config.full_scan_skip_dirs
        assert "node_modules" in config.full_scan_skip_dirs

    def test_full_scan_extensions_override(self, tmp_path):
        cfg_file = tmp_path / ".controlgate.yml"
        cfg_file.write_text("full_scan:\n  extensions: [.py, .rb]\n")
        config = ControlGateConfig.load(cfg_file)
        assert config.full_scan_extensions == [".py", ".rb"]

    def test_full_scan_skip_dirs_override(self, tmp_path):
        cfg_file = tmp_path / ".controlgate.yml"
        cfg_file.write_text("full_scan:\n  skip_dirs: [vendor]\n")
        config = ControlGateConfig.load(cfg_file)
        assert config.full_scan_skip_dirs == ["vendor"]
