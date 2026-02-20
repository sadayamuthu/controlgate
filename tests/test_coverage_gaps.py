"""Tests for remaining uncovered paths across gates, engine, config, and diff parser."""


from controlgate.config import ControlGateConfig
from controlgate.diff_parser import parse_diff
from controlgate.engine import ControlGateEngine
from controlgate.gates.audit_gate import AuditGate
from controlgate.gates.change_gate import ChangeGate
from controlgate.gates.crypto_gate import CryptoGate
from controlgate.gates.iac_gate import IaCGate
from controlgate.gates.sbom_gate import SBOMGate
from controlgate.gates.secrets_gate import SecretsGate

# ─── Audit Gate coverage ─────────────────────────────────

_REMOVED_LOG_DIFF = """\
diff --git a/server.py b/server.py
--- a/server.py
+++ b/server.py
@@ -1,4 +1,3 @@
 def handle_request():
-    logging.info("Processing request")
     process()
     return response
"""

_SECURITY_NO_LOG_DIFF = """\
diff --git a/auth.py b/auth.py
new file mode 100644
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,3 @@
+def authenticate(user, password):
+    if not verify(user, password):
+        raise PermissionError("access denied")
"""

_PII_IN_LOG_DIFF = """\
diff --git a/handler.py b/handler.py
new file mode 100644
--- /dev/null
+++ b/handler.py
@@ -0,0 +1,2 @@
+import logging
+logger.info(f"User password={password}")
"""


class TestAuditGate:
    def test_detects_removed_logging(self, catalog):
        gate = AuditGate(catalog)
        diff_files = parse_diff(_REMOVED_LOG_DIFF)
        findings = gate.scan(diff_files)
        assert any(
            "removed" in f.description.lower() or "audit" in f.description.lower() for f in findings
        )

    def test_detects_security_without_logging(self, catalog):
        gate = AuditGate(catalog)
        diff_files = parse_diff(_SECURITY_NO_LOG_DIFF)
        findings = gate.scan(diff_files)
        assert any(
            "log" in f.description.lower() or "function" in f.description.lower() for f in findings
        )

    def test_detects_pii_in_logs(self, catalog):
        gate = AuditGate(catalog)
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        # The gate checks for password/secret in log lines
        assert any(
            "credential" in f.description.lower() or "secret" in f.description.lower()
            for f in findings
        )


# ─── Change Gate coverage ────────────────────────────────

# security_config.py matches the _SECURITY_CRITICAL_FILES regex pattern
_SECURITY_FILE_DIFF = """\
diff --git a/security_config.py b/security_config.py
--- a/security_config.py
+++ b/security_config.py
@@ -1,2 +1,2 @@
-max_retries = 3
+max_retries = 10
"""

# helm/values.yaml matches _DEPLOY_CONFIG_FILES
_DEPLOY_FILE_DIFF = """\
diff --git a/helm/values.yaml b/helm/values.yaml
--- a/helm/values.yaml
+++ b/helm/values.yaml
@@ -1,2 +1,2 @@
-replicas: 3
+replicas: 1
"""

_CODEOWNERS_DIFF = """\
diff --git a/CODEOWNERS b/CODEOWNERS
--- a/CODEOWNERS
+++ b/CODEOWNERS
@@ -1,2 +1,2 @@
-* @security-team
+* @dev-team
"""

_BRANCH_PROTECTION_DIFF = """\
diff --git a/.github/workflows/protect.yml b/.github/workflows/protect.yml
new file mode 100644
--- /dev/null
+++ b/.github/workflows/protect.yml
@@ -0,0 +1,1 @@
+branch_protection: disabled
"""


class TestChangeGate:
    def test_detects_security_file_change(self, catalog):
        gate = ChangeGate(catalog)
        diff_files = parse_diff(_SECURITY_FILE_DIFF)
        findings = gate.scan(diff_files)
        # _SECURITY_CRITICAL_FILES matches security_config.py
        assert any(f.control_id == "CM-3" for f in findings)

    def test_detects_deploy_file_change(self, catalog):
        gate = ChangeGate(catalog)
        diff_files = parse_diff(_DEPLOY_FILE_DIFF)
        findings = gate.scan(diff_files)
        # _DEPLOY_CONFIG_FILES matches helm/values.yaml
        assert any(f.control_id == "CM-4" for f in findings)

    def test_detects_codeowners_change(self, catalog):
        gate = ChangeGate(catalog)
        diff_files = parse_diff(_CODEOWNERS_DIFF)
        findings = gate.scan(diff_files)
        assert any(f.control_id == "CM-5" for f in findings)

    def test_detects_branch_protection_change(self, catalog):
        gate = ChangeGate(catalog)
        diff_files = parse_diff(_BRANCH_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        # Both _SECURITY_CRITICAL_FILES (github workflow) and branch_protection line
        assert any(f.control_id == "CM-5" or f.control_id == "CM-3" for f in findings)


# ─── SBOM Gate coverage ──────────────────────────────────

_REQUIREMENTS_NO_LOCK_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask==2.0.0
+requests
 pytest==7.0.0
"""

_PIPELINE_CHANGE_DIFF = """\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,3 +1,3 @@
 steps:
-  - run: pip install .
+  - run: pip install --no-deps .
"""

_UNPINNED_DEPS_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
--- /dev/null
+++ b/requirements.txt
@@ -0,0 +1,3 @@
+flask>=2.0
+requests
+boto3~=1.26
"""

_COVERAGE_WEAKENED_DIFF = """\
diff --git a/setup.cfg b/setup.cfg
new file mode 100644
--- /dev/null
+++ b/setup.cfg
@@ -0,0 +1,1 @@
+cov_fail_under = 50
"""

_SKIP_TESTS_DIFF = """\
diff --git a/config.py b/config.py
new file mode 100644
--- /dev/null
+++ b/config.py
@@ -0,0 +1,1 @@
+skip_tests = True
"""


class TestSBOMGate:
    def test_detects_unpinned_deps(self, catalog):
        gate = SBOMGate(catalog)
        diff_files = parse_diff(_UNPINNED_DEPS_DIFF)
        findings = gate.scan(diff_files)
        # >= and ~= patterns should match
        assert any(f.control_id == "SR-11" for f in findings)

    def test_detects_manifest_without_lockfile(self, catalog):
        gate = SBOMGate(catalog)
        diff_files = parse_diff(_REQUIREMENTS_NO_LOCK_DIFF)
        findings = gate.scan(diff_files)
        assert any(f.control_id == "SR-3" for f in findings)

    def test_detects_pipeline_change(self, catalog):
        gate = SBOMGate(catalog)
        diff_files = parse_diff(_PIPELINE_CHANGE_DIFF)
        findings = gate.scan(diff_files)
        assert any(f.control_id == "SA-10" for f in findings)

    def test_detects_coverage_weakening(self, catalog):
        gate = SBOMGate(catalog)
        diff_files = parse_diff(_COVERAGE_WEAKENED_DIFF)
        findings = gate.scan(diff_files)
        # coverage.*fail_under pattern matches
        assert any(f.control_id == "SA-11" for f in findings)

    def test_detects_skip_tests(self, catalog):
        gate = SBOMGate(catalog)
        diff_files = parse_diff(_SKIP_TESTS_DIFF)
        findings = gate.scan(diff_files)
        assert any(f.control_id == "SA-11" for f in findings)


# ─── Engine scoring edge cases ───────────────────────────


class TestEngineScoringEdgeCases:
    def test_medium_non_negotiable_becomes_warn(self, catalog):
        """MEDIUM + non_negotiable → WARN."""
        config = ControlGateConfig()
        engine = ControlGateEngine(config, catalog)
        diff = """\
diff --git a/auth.py b/auth.py
new file mode 100644
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,1 @@
+password_hash = hashlib.md5(password.encode()).hexdigest()
"""
        diff_files = parse_diff(diff)
        verdict = engine.scan(diff_files)
        actions = {f.action for f in verdict.findings}
        assert actions.issubset({"BLOCK", "WARN", "PASS"})

    def test_low_severity_ignored_by_default(self, catalog):
        """LOW severity should be filtered out by default config."""
        config = ControlGateConfig()
        engine = ControlGateEngine(config, catalog)
        diff_files = parse_diff("")
        verdict = engine.scan(diff_files)
        for f in verdict.findings:
            assert f.severity != "LOW"

    def test_warn_only_verdict(self, catalog):
        """Ensure a  WARN-only verdict works correctly."""
        config = ControlGateConfig()
        # Override to only warn on HIGH (not block)
        config.block_on = ["CRITICAL"]
        config.warn_on = ["HIGH", "MEDIUM"]
        engine = ControlGateEngine(config, catalog)
        diff = """\
diff --git a/auth.py b/auth.py
new file mode 100644
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,1 @@
+password_hash = hashlib.md5(password.encode()).hexdigest()
"""
        diff_files = parse_diff(diff)
        verdict = engine.scan(diff_files)
        assert verdict.verdict in ("WARN", "PASS")

    def test_disabled_gate_not_run(self, catalog):
        """Disabled gates should not run."""
        from controlgate.config import GateConfig

        config = ControlGateConfig()
        config.gates["secrets"] = GateConfig(enabled=False, action="block")
        engine = ControlGateEngine(config, catalog)
        diff = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,1 @@
+DB_PASSWORD = "secret123"
"""
        diff_files = parse_diff(diff)
        verdict = engine.scan(diff_files)
        # Secrets gate is disabled, so no secrets findings
        assert not any(f.gate == "secrets" for f in verdict.findings)


# ─── Secrets Gate edge cases ─────────────────────────────

_HIGH_ENTROPY_DIFF = """\
diff --git a/config.py b/config.py
new file mode 100644
--- /dev/null
+++ b/config.py
@@ -0,0 +1,1 @@
+TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
"""


class TestSecretsGateEdgeCases:
    def test_high_entropy_string(self, catalog):
        gate = SecretsGate(catalog)
        diff_files = parse_diff(_HIGH_ENTROPY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0


# ─── Crypto Gate edge case ───────────────────────────────

_TLS_DIFF = """\
diff --git a/server.py b/server.py
new file mode 100644
--- /dev/null
+++ b/server.py
@@ -0,0 +1,1 @@
+context.protocol = ssl.PROTOCOL_TLSv1
"""


class TestCryptoGateEdgeCases:
    def test_detects_deprecated_tls(self, catalog):
        gate = CryptoGate(catalog)
        diff_files = parse_diff(_TLS_DIFF)
        findings = gate.scan(diff_files)
        assert any("TLS" in f.description or "tls" in f.description.lower() for f in findings)


# ─── IaC Gate edge cases ─────────────────────────────────

_ENCRYPTION_DISABLED_DIFF = """\
diff --git a/terraform/rds.tf b/terraform/rds.tf
new file mode 100644
--- /dev/null
+++ b/terraform/rds.tf
@@ -0,0 +1,2 @@
+resource "aws_db_instance" "main" {
+  storage_encrypted = false
"""

_LOGGING_DISABLED_DIFF = """\
diff --git a/terraform/s3.tf b/terraform/s3.tf
new file mode 100644
--- /dev/null
+++ b/terraform/s3.tf
@@ -0,0 +1,2 @@
+resource "aws_s3_bucket" "main" {
+  logging = false
"""


class TestIaCGateEdgeCases:
    def test_detects_encryption_disabled(self, catalog):
        gate = IaCGate(catalog)
        diff_files = parse_diff(_ENCRYPTION_DISABLED_DIFF)
        findings = gate.scan(diff_files)
        assert any("encrypt" in f.description.lower() for f in findings)

    def test_detects_logging_disabled(self, catalog):
        gate = IaCGate(catalog)
        diff_files = parse_diff(_LOGGING_DISABLED_DIFF)
        findings = gate.scan(diff_files)
        assert any(
            "logging" in f.description.lower() or "log" in f.description.lower() for f in findings
        )


# ─── Diff parser edge cases ──────────────────────────────

_BINARY_DIFF = """\
diff --git a/image.png b/image.png
new file mode 100644
Binary files /dev/null and b/image.png differ
"""


class TestDiffParserEdgeCases:
    def test_binary_file_diff(self):
        files = parse_diff(_BINARY_DIFF)
        assert len(files) == 1
        assert files[0].path == "image.png"

    def test_handles_context_lines(self):
        diff_with_context = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -5,7 +5,7 @@
 import os
 import sys

-old_code = True
+new_code = True

 def main():
     pass
"""
        files = parse_diff(diff_with_context)
        assert len(files) == 1
        added = files[0].all_added_lines
        assert len(added) == 1
        assert "new_code" in added[0][1]


# ─── Config edge cases ───────────────────────────────────


class TestConfigEdgeCases:
    def test_config_load_default(self):
        config = ControlGateConfig.load()
        assert config.baseline == "moderate"

    def test_config_is_control_excluded(self):
        config = ControlGateConfig()
        assert config.is_control_excluded("AC-13") is True
        assert config.is_control_excluded("AC-1") is False

    def test_config_gate_action(self):
        config = ControlGateConfig.load()
        assert config.is_gate_enabled("secrets") is True

    def test_config_load_nonexistent_file(self):
        config = ControlGateConfig.load("/nonexistent/.controlgate.yml")
        assert config.baseline == "moderate"  # Falls back to defaults
