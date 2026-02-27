"""Tests for the Observability Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.observability_gate import ObservabilityGate


@pytest.fixture
def gate(catalog):
    return ObservabilityGate(catalog)


_MONITORING_FALSE_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,4 @@
+resource "aws_db_instance" "prod" {
+  monitoring_interval = 0
+  enable_monitoring   = false
+}
"""

_LOG_DRIVER_NONE_DIFF = """\
diff --git a/docker-compose.yml b/docker-compose.yml
--- /dev/null
+++ b/docker-compose.yml
@@ -0,0 +1,5 @@
+services:
+  app:
+    image: myapp:1.0
+    logging:
+      driver: none
"""

_K8S_NO_PROBE_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,8 @@
+apiVersion: apps/v1
+kind: Deployment
+spec:
+  template:
+    spec:
+      containers:
+      - name: app
+        image: myapp:1.0
"""

_CLEAN_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,10 @@
+apiVersion: apps/v1
+kind: Deployment
+spec:
+  template:
+    spec:
+      containers:
+      - name: app
+        image: myapp:1.0
+        livenessProbe:
+          httpGet: {path: /health, port: 8080}
"""


class TestObservabilityGate:
    def test_detects_monitoring_false(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("monitor" in f.description.lower() for f in findings)

    def test_detects_log_driver_none(self, gate):
        diff_files = parse_diff(_LOG_DRIVER_NONE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_k8s_missing_liveness_probe(self, gate):
        diff_files = parse_diff(_K8S_NO_PROBE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_k8s_with_liveness_probe_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "observability"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-4", "AU-12"}
        for f in findings:
            assert f.control_id in valid_ids
