"""Tests for the IAM Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.iam_gate import IAMGate


@pytest.fixture
def gate(catalog):
    return IAMGate(catalog)


_WILDCARD_POLICY_DIFF = """\
diff --git a/policy.json b/policy.json
new file mode 100644
--- /dev/null
+++ b/policy.json
@@ -0,0 +1,6 @@
+{
+  "Effect": "Allow",
+  "Action": "*",
+  "Resource": "*"
+}
"""

_CORS_WILDCARD_DIFF = """\
diff --git a/server.py b/server.py
new file mode 100644
--- /dev/null
+++ b/server.py
@@ -0,0 +1,1 @@
+access-control-allow-origin: *
"""


class TestIAMGate:
    def test_detects_wildcard_action(self, gate):
        diff_files = parse_diff(_WILDCARD_POLICY_DIFF)
        findings = gate.scan(diff_files)
        assert any(
            "wildcard" in f.description.lower() or "Action" in f.description for f in findings
        )

    def test_detects_cors_wildcard(self, gate):
        diff_files = parse_diff(_CORS_WILDCARD_DIFF)
        findings = gate.scan(diff_files)
        assert any("CORS" in f.description for f in findings)
