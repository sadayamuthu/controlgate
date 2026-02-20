"""Tests for the Secrets Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.secrets_gate import SecretsGate


@pytest.fixture
def gate(catalog):
    return SecretsGate(catalog)


_AWS_KEY_DIFF = """\
diff --git a/config.py b/config.py
new file mode 100644
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
+AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

_PASSWORD_DIFF = """\
diff --git a/db.py b/db.py
--- a/db.py
+++ b/db.py
@@ -1,3 +1,4 @@
 import psycopg2
+DB_PASSWORD = "super_secret_123"

 def connect():
"""

_PRIVATE_KEY_DIFF = """\
diff --git a/key.pem b/key.pem
new file mode 100644
--- /dev/null
+++ b/key.pem
@@ -0,0 +1,3 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIICXgIBAAJBANp0i4rewerewr...
+-----END RSA PRIVATE KEY-----
"""

_CLEAN_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,4 @@
+import os
+
+def get_password():
+    return os.environ.get("DB_PASSWORD")
"""

_DB_URI_DIFF = """\
diff --git a/settings.py b/settings.py
new file mode 100644
--- /dev/null
+++ b/settings.py
@@ -0,0 +1,1 @@
+DATABASE_URL = "postgres://admin:s3cret@db.example.com:5432/mydb"
"""

_GITHUB_TOKEN_DIFF = """\
diff --git a/ci.py b/ci.py
new file mode 100644
--- /dev/null
+++ b/ci.py
@@ -0,0 +1,1 @@
+GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
"""


class TestSecretsGate:
    def test_detects_aws_key(self, gate):
        diff_files = parse_diff(_AWS_KEY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("AWS" in f.description for f in findings)

    def test_detects_hardcoded_password(self, gate):
        diff_files = parse_diff(_PASSWORD_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "credential" in f.description.lower() or "password" in f.description.lower()
            for f in findings
        )

    def test_detects_private_key(self, gate):
        diff_files = parse_diff(_PRIVATE_KEY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("key" in f.description.lower() for f in findings)

    def test_clean_code_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_detects_database_uri(self, gate):
        diff_files = parse_diff(_DB_URI_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "connection string" in f.description.lower() or "credential" in f.description.lower()
            for f in findings
        )

    def test_detects_github_token(self, gate):
        diff_files = parse_diff(_GITHUB_TOKEN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_AWS_KEY_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "secrets"

    def test_findings_have_control_ids(self, gate):
        diff_files = parse_diff(_AWS_KEY_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"IA-5", "IA-6", "SC-12", "SC-28"}
        for f in findings:
            assert f.control_id in valid_ids
