"""Tests for the ControlGate engine."""

import pytest

from controlgate.config import ControlGateConfig
from controlgate.diff_parser import parse_diff
from controlgate.engine import ControlGateEngine


@pytest.fixture
def config():
    return ControlGateConfig.load()


@pytest.fixture
def engine(config, catalog):
    return ControlGateEngine(config, catalog)


_SECRETS_DIFF = """\
diff --git a/config/database.py b/config/database.py
new file mode 100644
--- /dev/null
+++ b/config/database.py
@@ -0,0 +1,4 @@
+import os
+
+DB_PASSWORD = "super_secret_123"
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
"""

_CLEAN_DIFF = """\
diff --git a/utils.py b/utils.py
new file mode 100644
--- /dev/null
+++ b/utils.py
@@ -0,0 +1,4 @@
+import os
+
+def get_env(key):
+    return os.environ.get(key)
"""

_EXCLUDED_PATH_DIFF = """\
diff --git a/tests/test_something.py b/tests/test_something.py
new file mode 100644
--- /dev/null
+++ b/tests/test_something.py
@@ -0,0 +1,3 @@
+DB_PASSWORD = "test_fixture_secret"
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
+eval("test code")
"""


class TestEngine:
    def test_scan_with_secrets_produces_findings(self, engine):
        diff_files = parse_diff(_SECRETS_DIFF)
        verdict = engine.scan(diff_files)
        assert len(verdict.findings) > 0
        assert verdict.verdict in ("BLOCK", "WARN", "PASS")

    def test_clean_code_passes(self, engine):
        diff_files = parse_diff(_CLEAN_DIFF)
        verdict = engine.scan(diff_files)
        assert verdict.verdict == "PASS"
        assert "0 BLOCK" in verdict.summary

    def test_excluded_paths_skipped(self, engine):
        diff_files = parse_diff(_EXCLUDED_PATH_DIFF)
        verdict = engine.scan(diff_files)
        # tests/** is excluded by default, so no findings
        assert len(verdict.findings) == 0
        assert verdict.verdict == "PASS"

    def test_verdict_has_gate_summaries(self, engine):
        diff_files = parse_diff(_SECRETS_DIFF)
        verdict = engine.scan(diff_files)
        assert len(verdict.gate_summary) > 0
        for gs in verdict.gate_summary.values():
            assert gs.status in ("BLOCK", "WARN", "PASS")
            assert gs.findings >= 0

    def test_verdict_has_timestamp(self, engine):
        diff_files = parse_diff(_CLEAN_DIFF)
        verdict = engine.scan(diff_files)
        assert verdict.timestamp is not None
        assert "T" in verdict.timestamp  # ISO format

    def test_verdict_to_dict(self, engine):
        diff_files = parse_diff(_SECRETS_DIFF)
        verdict = engine.scan(diff_files)
        d = verdict.to_dict()
        assert "verdict" in d
        assert "findings" in d
        assert "gate_summary" in d
        assert isinstance(d["findings"], list)

    def test_verdict_baseline_target(self, engine):
        diff_files = parse_diff(_CLEAN_DIFF)
        verdict = engine.scan(diff_files)
        assert verdict.baseline_target == "moderate"
