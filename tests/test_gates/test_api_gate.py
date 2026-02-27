"""Tests for the API Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.api_gate import APIGate


@pytest.fixture
def gate(catalog):
    return APIGate(catalog)


_VERIFY_FALSE_DIFF = """\
diff --git a/client.py b/client.py
--- a/client.py
+++ b/client.py
@@ -1,3 +1,4 @@
 import requests
+response = requests.get("https://api.example.com", verify=False)
"""

_CORS_ALL_DIFF = """\
diff --git a/settings.py b/settings.py
--- /dev/null
+++ b/settings.py
@@ -0,0 +1,2 @@
+CORS_ORIGIN_ALLOW_ALL = True
+ALLOWED_HOSTS = ["*"]
"""

_API_KEY_QUERY_DIFF = """\
diff --git a/api.py b/api.py
--- a/api.py
+++ b/api.py
@@ -1,3 +1,4 @@
+url = f"https://api.example.com/data?api_key={key}&format=json"
"""

_CREDENTIALED_CORS_DIFF = """\
diff --git a/headers.py b/headers.py
--- /dev/null
+++ b/headers.py
@@ -0,0 +1,2 @@
+response.headers["Access-Control-Allow-Origin"] = "*"
+response.headers["Access-Control-Allow-Credentials"] = "true"
"""

_GRAPHQL_INTROSPECTION_DIFF = """\
diff --git a/schema.py b/schema.py
--- /dev/null
+++ b/schema.py
@@ -0,0 +1,2 @@
+app.add_url_rule("/graphql", view_func=GraphQLView.as_view("graphql", schema=schema, graphiql=True))
+GRAPHQL_INTROSPECTION = True
"""

_CLEAN_DIFF = """\
diff --git a/client.py b/client.py
--- /dev/null
+++ b/client.py
@@ -0,0 +1,3 @@
+import requests
+response = requests.get("https://api.example.com")
+assert response.status_code == 200
"""


class TestAPIGate:
    def test_detects_verify_false(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "verify" in f.description.lower() or "tls" in f.description.lower() for f in findings
        )

    def test_detects_cors_allow_all(self, gate):
        diff_files = parse_diff(_CORS_ALL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_api_key_in_query(self, gate):
        diff_files = parse_diff(_API_KEY_QUERY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_credentialed_cors(self, gate):
        diff_files = parse_diff(_CREDENTIALED_CORS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_code_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "api"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SC-8", "AC-3", "SC-5", "SI-10"}
        for f in findings:
            assert f.control_id in valid_ids

    def test_detects_graphql_introspection(self, gate):
        diff_files = parse_diff(_GRAPHQL_INTROSPECTION_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "graphql" in f.description.lower() or "introspection" in f.description.lower()
            for f in findings
        )
