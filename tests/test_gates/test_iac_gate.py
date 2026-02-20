"""Tests for the IaC Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.iac_gate import IaCGate


@pytest.fixture
def gate(catalog):
    return IaCGate(catalog)


_PUBLIC_INGRESS_DIFF = """\
diff --git a/terraform/main.tf b/terraform/main.tf
new file mode 100644
--- /dev/null
+++ b/terraform/main.tf
@@ -0,0 +1,4 @@
+resource "aws_security_group_rule" "allow_all" {
+  type        = "ingress"
+  cidr_blocks = ["0.0.0.0/0"]
+}
"""

_ROOT_CONTAINER_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
new file mode 100644
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,2 @@
+FROM ubuntu:22.04
+USER root
"""

_NON_IAC_FILE_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,1 @@
+cidr = "0.0.0.0/0"
"""


class TestIaCGate:
    def test_detects_public_ingress(self, gate):
        diff_files = parse_diff(_PUBLIC_INGRESS_DIFF)
        findings = gate.scan(diff_files)
        assert any("0.0.0.0/0" in f.description for f in findings)

    def test_detects_root_container(self, gate):
        diff_files = parse_diff(_ROOT_CONTAINER_DIFF)
        findings = gate.scan(diff_files)
        assert any("root" in f.description.lower() for f in findings)

    def test_skips_non_iac_files(self, gate):
        diff_files = parse_diff(_NON_IAC_FILE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0
