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

_CLEAN_DIFF = """\
diff --git a/model.py b/model.py
--- /dev/null
+++ b/model.py
@@ -0,0 +1,4 @@
+import torch
+model = torch.load("model.pt", map_location="cpu")
+model.eval()
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
