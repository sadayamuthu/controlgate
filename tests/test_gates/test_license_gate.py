"""Tests for the License Compliance Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.license_gate import LicenseGate


@pytest.fixture
def gate(catalog):
    return LicenseGate(catalog)


_GPL_PIP_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 requests==2.31.0
+gpl-licensed-lib==1.0.0  # GPL-3.0
"""

_AGPL_PACKAGE_JSON_DIFF = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,5 +1,8 @@
 {
   "dependencies": {
+    "some-agpl-package": "^1.0.0"
   }
 }
"""

_SPDX_GPL_DIFF = """\
diff --git a/src/vendor/lib.py b/src/vendor/lib.py
--- /dev/null
+++ b/src/vendor/lib.py
@@ -0,0 +1,2 @@
+# SPDX-License-Identifier: GPL-3.0-only
+def helper(): pass
"""

_MIT_CLEAN_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 requests==2.31.0
+flask==3.0.0  # MIT
"""


class TestLicenseGate:
    def test_detects_gpl_in_requirements(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "gpl" in f.description.lower() or "license" in f.description.lower() for f in findings
        )

    def test_detects_agpl_in_package_json(self, gate):
        diff_files = parse_diff(_AGPL_PACKAGE_JSON_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_spdx_gpl_in_source(self, gate):
        diff_files = parse_diff(_SPDX_GPL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_mit_license_no_findings(self, gate):
        diff_files = parse_diff(_MIT_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "license"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SA-4", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids
