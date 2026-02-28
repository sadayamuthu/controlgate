"""Tests for the Data Privacy Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.privacy_gate import PrivacyGate


@pytest.fixture
def gate(catalog):
    return PrivacyGate(catalog)


_PII_IN_LOG_DIFF = """\
diff --git a/views.py b/views.py
--- a/views.py
+++ b/views.py
@@ -1,4 +1,5 @@
 def register(request):
+    logging.debug("User SSN: %s, DOB: %s", user.ssn, user.date_of_birth)
     save(user)
"""

_SERIALIZE_ALL_DIFF = """\
diff --git a/serializers.py b/serializers.py
--- /dev/null
+++ b/serializers.py
@@ -0,0 +1,3 @@
+class UserSerializer(ModelSerializer):
+    serialize_all_fields = True
+    model = User
"""

_NO_EXPIRY_DIFF = """\
diff --git a/models.py b/models.py
--- /dev/null
+++ b/models.py
@@ -0,0 +1,3 @@
+class Session(Model):
+    token = CharField()
+    expires_at = None
"""

_CLEAN_DIFF = """\
diff --git a/views.py b/views.py
--- /dev/null
+++ b/views.py
@@ -0,0 +1,3 @@
+def register(request):
+    logging.info("User registered: user_id=%s", user.id)
+    save(user)
"""


class TestPrivacyGate:
    def test_detects_pii_in_log(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "pii" in f.description.lower() or "log" in f.description.lower() for f in findings
        )

    def test_detects_serialize_all_fields(self, gate):
        diff_files = parse_diff(_SERIALIZE_ALL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_no_expiry(self, gate):
        diff_files = parse_diff(_NO_EXPIRY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_code_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "privacy"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"PT-2", "PT-3", "SC-28"}
        for f in findings:
            assert f.control_id in valid_ids
