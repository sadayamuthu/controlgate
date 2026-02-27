"""Tests for the Container Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.container_gate import ContainerGate


@pytest.fixture
def gate(catalog):
    return ContainerGate(catalog)


_ROOT_USER_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+USER root
+CMD ["python", "app.py"]
"""

_PRIVILEGED_DIFF = """\
diff --git a/docker-compose.yml b/docker-compose.yml
--- /dev/null
+++ b/docker-compose.yml
@@ -0,0 +1,5 @@
+services:
+  app:
+    image: myapp:1.0
+    privileged: true
"""

_LATEST_TAG_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,2 @@
+FROM nginx:latest
+EXPOSE 80
"""

_HOST_NETWORK_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,5 @@
+spec:
+  template:
+    spec:
+      hostNetwork: true
+      containers: []
"""

_HOST_PID_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,4 @@
+spec:
+  template:
+    spec:
+      hostPID: true
"""

_CLEAN_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,5 @@
+FROM python:3.11-slim@sha256:abc123
+RUN groupadd -r app && useradd -r -g app app
+COPY . /app
+USER app
+CMD ["python", "app.py"]
"""


class TestContainerGate:
    def test_detects_user_root(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("root" in f.description.lower() for f in findings)

    def test_detects_privileged_mode(self, gate):
        diff_files = parse_diff(_PRIVILEGED_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_latest_tag(self, gate):
        diff_files = parse_diff(_LATEST_TAG_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "latest" in f.description.lower() or "unpinned" in f.description.lower()
            for f in findings
        )

    def test_detects_host_network(self, gate):
        diff_files = parse_diff(_HOST_NETWORK_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_host_pid(self, gate):
        diff_files = parse_diff(_HOST_PID_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_dockerfile_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "container"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids
