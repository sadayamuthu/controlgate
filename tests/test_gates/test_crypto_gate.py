"""Tests for the Crypto Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.crypto_gate import CryptoGate


@pytest.fixture
def gate(catalog):
    return CryptoGate(catalog)


_WEAK_HASH_DIFF = """\
diff --git a/auth.py b/auth.py
new file mode 100644
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,2 @@
+import hashlib
+password_hash = hashlib.md5(password.encode()).hexdigest()
"""

_SSL_VERIFY_DIFF = """\
diff --git a/client.py b/client.py
new file mode 100644
--- /dev/null
+++ b/client.py
@@ -0,0 +1,1 @@
+response = requests.get(url, verify=False)
"""

_HTTP_URL_DIFF = """\
diff --git a/api.py b/api.py
new file mode 100644
--- /dev/null
+++ b/api.py
@@ -0,0 +1,1 @@
+API_ENDPOINT = "http://api.production.example.com/v1"
"""


class TestCryptoGate:
    def test_detects_md5(self, gate):
        diff_files = parse_diff(_WEAK_HASH_DIFF)
        findings = gate.scan(diff_files)
        assert any("MD5" in f.description for f in findings)

    def test_detects_ssl_verify_false(self, gate):
        diff_files = parse_diff(_SSL_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "verification" in f.description.lower() or "ssl" in f.description.lower()
            for f in findings
        )

    def test_detects_http_url(self, gate):
        diff_files = parse_diff(_HTTP_URL_DIFF)
        findings = gate.scan(diff_files)
        assert any("HTTP" in f.description or "http" in f.description.lower() for f in findings)

    def test_findings_have_crypto_gate_id(self, gate):
        diff_files = parse_diff(_WEAK_HASH_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "crypto"
