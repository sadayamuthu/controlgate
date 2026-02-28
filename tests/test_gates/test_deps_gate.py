"""Tests for the Dependency Vulnerability Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.deps_gate import DepsGate


@pytest.fixture
def gate(catalog):
    return DepsGate(catalog)


_NO_VERIFY_DIFF = """\
diff --git a/Makefile b/Makefile
--- a/Makefile
+++ b/Makefile
@@ -1,3 +1,4 @@
 install:
+\tpip install --no-verify requests
"""

_IGNORE_SCRIPTS_DIFF = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
+  "install": "npm install --ignore-scripts"
"""

_HTTP_REGISTRY_DIFF = """\
diff --git a/.npmrc b/.npmrc
--- /dev/null
+++ b/.npmrc
@@ -0,0 +1,1 @@
+registry=http://registry.npmjs.org/
"""

_UNPINNED_PIP_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+RUN pip install requests flask
+CMD ["python", "app.py"]
"""

_CLEAN_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+RUN pip install requests==2.31.0 flask==3.0.0
+CMD ["python", "app.py"]
"""

_GIT_NO_VERIFY_DIFF = """\
diff --git a/Makefile b/Makefile
--- a/Makefile
+++ b/Makefile
@@ -1,3 +1,4 @@
 release:
+\tgit commit --no-verify -m "release"
"""

_RANGE_SPECIFIER_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,2 @@
+FROM python:3.11
+RUN pip install requests>=2.0.0
"""


class TestDepsGate:
    def test_detects_no_verify(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "no-verify" in f.description.lower() or "integrity" in f.description.lower()
            for f in findings
        )

    def test_detects_ignore_scripts(self, gate):
        diff_files = parse_diff(_IGNORE_SCRIPTS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_http_registry(self, gate):
        diff_files = parse_diff(_HTTP_REGISTRY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("http" in f.description.lower() for f in findings)

    def test_detects_unpinned_pip_install(self, gate):
        diff_files = parse_diff(_UNPINNED_PIP_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_pinned_install_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_git_no_verify_not_flagged(self, gate):
        diff_files = parse_diff(_GIT_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_detects_range_specifier(self, gate):
        diff_files = parse_diff(_RANGE_SPECIFIER_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "deps"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"RA-5", "SI-2", "SA-12"}
        for f in findings:
            assert f.control_id in valid_ids
