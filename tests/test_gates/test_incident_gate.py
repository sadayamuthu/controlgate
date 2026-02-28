"""Tests for the Incident Response Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.incident_gate import IncidentGate


@pytest.fixture
def gate(catalog):
    return IncidentGate(catalog)


_SILENT_EXCEPT_DIFF = """\
diff --git a/worker.py b/worker.py
--- a/worker.py
+++ b/worker.py
@@ -1,4 +1,6 @@
 def process():
+    try:
+        do_work()
+    except:
+        pass
"""

_EMPTY_CATCH_JS_DIFF = """\
diff --git a/handler.js b/handler.js
--- /dev/null
+++ b/handler.js
@@ -0,0 +1,5 @@
+async function handle() {
+  try {
+    await process();
+  } catch(e) {}
+}
"""

_TRACEBACK_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,4 @@
+@app.errorhandler(500)
+def server_error(e):
+    traceback.print_exc()
+    return str(e), 500
"""

_NOTIFY_FALSE_DIFF = """\
diff --git a/alerting.yaml b/alerting.yaml
--- /dev/null
+++ b/alerting.yaml
@@ -0,0 +1,3 @@
+alerts:
+  notify: false
+  threshold: critical
"""

_CLEAN_DIFF = """\
diff --git a/worker.py b/worker.py
--- /dev/null
+++ b/worker.py
@@ -0,0 +1,6 @@
+def process():
+    try:
+        do_work()
+    except ValueError as e:
+        logger.error("Processing failed: %s", e)
+        raise
"""


class TestIncidentGate:
    def test_detects_bare_except_pass(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "exception" in f.description.lower() or "silent" in f.description.lower()
            for f in findings
        )

    def test_detects_empty_catch_js(self, gate):
        diff_files = parse_diff(_EMPTY_CATCH_JS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_traceback_exposure(self, gate):
        diff_files = parse_diff(_TRACEBACK_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_notify_false(self, gate):
        diff_files = parse_diff(_NOTIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_logged_exception_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "incident"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"IR-4", "IR-6", "AU-6"}
        for f in findings:
            assert f.control_id in valid_ids
