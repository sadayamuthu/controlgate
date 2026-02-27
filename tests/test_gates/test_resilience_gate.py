"""Tests for the Resilience & Backup Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.resilience_gate import ResilienceGate


@pytest.fixture
def gate(catalog):
    return ResilienceGate(catalog)


_DELETION_PROTECTION_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,5 @@
+resource "aws_db_instance" "main" {
+  identifier        = "prod-db"
+  deletion_protection = false
+  instance_class    = "db.t3.micro"
+}
"""

_SKIP_SNAPSHOT_DIFF = """\
diff --git a/database.tf b/database.tf
--- /dev/null
+++ b/database.tf
@@ -0,0 +1,4 @@
+resource "aws_db_instance" "prod" {
+  skip_final_snapshot = true
+  deletion_protection = false
+}
"""

_MAX_RETRIES_ZERO_DIFF = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+MAX_RETRIES = 0
+RETRY_DELAY = 1
"""

_CLEAN_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,5 @@
+resource "aws_db_instance" "main" {
+  identifier          = "prod-db"
+  deletion_protection = true
+  skip_final_snapshot = false
+}
"""


class TestResilienceGate:
    def test_detects_deletion_protection_false(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("deletion_protection" in f.description.lower() or "backup" in f.description.lower() for f in findings)

    def test_detects_skip_final_snapshot(self, gate):
        diff_files = parse_diff(_SKIP_SNAPSHOT_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_max_retries_zero(self, gate):
        diff_files = parse_diff(_MAX_RETRIES_ZERO_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_config_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "resilience"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"CP-9", "CP-10", "SI-13"}
        for f in findings:
            assert f.control_id in valid_ids
