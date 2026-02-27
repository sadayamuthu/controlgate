"""Tests for the AI/ML Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.aiml_gate import AIMLGate


@pytest.fixture
def gate(catalog):
    return AIMLGate(catalog)


_TRUST_REMOTE_CODE_DIFF = """\
diff --git a/model.py b/model.py
--- /dev/null
+++ b/model.py
@@ -0,0 +1,3 @@
+from transformers import AutoModelForCausalLM
+model = AutoModelForCausalLM.from_pretrained("some/model", trust_remote_code=True)
"""

_PICKLE_LOAD_DIFF = """\
diff --git a/inference.py b/inference.py
--- /dev/null
+++ b/inference.py
@@ -0,0 +1,4 @@
+import pickle
+with open("model.pkl", "rb") as f:
+    model = pickle.load(f)
"""

_HTTP_MODEL_DIFF = """\
diff --git a/download.py b/download.py
--- /dev/null
+++ b/download.py
@@ -0,0 +1,3 @@
+import urllib.request
+urllib.request.urlretrieve("http://models.example.com/weights.bin", "weights.bin")
"""

_PROMPT_INJECTION_DIFF = """\
diff --git a/llm.py b/llm.py
--- /dev/null
+++ b/llm.py
@@ -0,0 +1,4 @@
+def query_llm(user_input):
+    prompt = f"Answer this: {user_input}"
+    return llm.complete(prompt)
"""

_PLAINTEXT_WEIGHTS_DIFF = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+MODEL_WEIGHTS = "/data/models/prod_weights.bin"
+checkpoint_path = "s3://bucket/model.pt"
+weights_path = "/mnt/nfs/weights.ckpt"
"""

_CLEAN_DIFF = """\
diff --git a/model.py b/model.py
--- /dev/null
+++ b/model.py
@@ -0,0 +1,4 @@
+import torch
+model = torch.load("model.pt", map_location="cpu")
+model.eval()
"""

# NOTE: comment-line trade-off — all_added_lines (models.py) collects every
# added line verbatim; no comment-prefix stripping is applied by the diff
# parser.  A commented-out path like `# model_path = "/data/weights.bin"`
# would still fire SC-28.  This is an accepted, consistent behaviour across
# all 18 gates (see test_memsafe_gate.py, test_secrets_gate.py — neither
# gates filters comment lines either).  Document with a test below so the
# behaviour is intentional and visible.
_SAFE_WEIGHTS_DIFF = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+model_path = os.environ["MODEL_PATH"]
+checkpoint_path = config.get("checkpoint")
+weights_path = vault.read_secret("weights_path")
"""


class TestAIMLGate:
    def test_detects_trust_remote_code(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "trust_remote_code" in f.description.lower() or "remote" in f.description.lower()
            for f in findings
        )

    def test_detects_pickle_load(self, gate):
        diff_files = parse_diff(_PICKLE_LOAD_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_http_model_download(self, gate):
        diff_files = parse_diff(_HTTP_MODEL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_prompt_injection_pattern(self, gate):
        diff_files = parse_diff(_PROMPT_INJECTION_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_model_load_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "aiml"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-10", "SC-28", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids

    def test_detects_plaintext_model_weights(self, gate):
        diff_files = parse_diff(_PLAINTEXT_WEIGHTS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any(
            "plaintext" in f.description.lower() or "weight" in f.description.lower()
            for f in findings
        )
        assert all(f.control_id == "SC-28" for f in findings)

    def test_no_false_positive_safe_model_path_access(self, gate):
        # Safe alternatives: env var lookup, config dict access, and secrets
        # manager calls do NOT hardcode a path string, so SC-28 must not fire.
        diff_files = parse_diff(_SAFE_WEIGHTS_DIFF)
        findings = gate.scan(diff_files)
        sc28_findings = [f for f in findings if f.control_id == "SC-28"]
        assert len(sc28_findings) == 0
