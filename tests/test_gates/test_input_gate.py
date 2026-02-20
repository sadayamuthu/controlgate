"""Tests for the Input Validation Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.input_gate import InputGate


@pytest.fixture
def gate(catalog):
    return InputGate(catalog)


_SQL_INJECTION_DIFF = """\
diff --git a/db.py b/db.py
new file mode 100644
--- /dev/null
+++ b/db.py
@@ -0,0 +1,2 @@
+def get_user(name):
+    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""

_EVAL_DIFF = """\
diff --git a/handler.py b/handler.py
new file mode 100644
--- /dev/null
+++ b/handler.py
@@ -0,0 +1,2 @@
+def process(data):
+    result = eval(data)
"""

_BARE_EXCEPT_DIFF = """\
diff --git a/utils.py b/utils.py
new file mode 100644
--- /dev/null
+++ b/utils.py
@@ -0,0 +1,4 @@
+try:
+    do_something()
+except: pass
+
"""


class TestInputGate:
    def test_detects_sql_injection(self, gate):
        diff_files = parse_diff(_SQL_INJECTION_DIFF)
        findings = gate.scan(diff_files)
        assert any("SQL" in f.description for f in findings)

    def test_detects_eval(self, gate):
        diff_files = parse_diff(_EVAL_DIFF)
        findings = gate.scan(diff_files)
        assert any("eval" in f.description.lower() for f in findings)

    def test_detects_bare_except(self, gate):
        diff_files = parse_diff(_BARE_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        assert any("except" in f.description.lower() for f in findings)
