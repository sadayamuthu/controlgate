"""Tests for the Memory Safety Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.memsafe_gate import MemSafeGate


@pytest.fixture
def gate(catalog):
    return MemSafeGate(catalog)


_EVAL_DYNAMIC_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+def process(user_input):
+    result = eval(user_input)
+    return result
"""

_EXEC_DYNAMIC_DIFF = """\
diff --git a/template.py b/template.py
--- /dev/null
+++ b/template.py
@@ -0,0 +1,2 @@
+code = f"x = {request.form['value']}"
+exec(code)
"""

_UNSAFE_RUST_DIFF = """\
diff --git a/src/lib.rs b/src/lib.rs
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,5 @@
+pub fn read_ptr(ptr: *const u8) -> u8 {
+    unsafe {
+        *ptr
+    }
+}
"""

_STRCPY_DIFF = """\
diff --git a/handler.c b/handler.c
--- /dev/null
+++ b/handler.c
@@ -0,0 +1,4 @@
+void copy_name(char *dest, char *src) {
+    strcpy(dest, src);
+}
"""

_CLEAN_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+import ast
+def process(user_input):
+    return ast.literal_eval(user_input)
"""


_CFFI_DIFF = """\
diff --git a/bridge.py b/bridge.py
--- /dev/null
+++ b/bridge.py
@@ -0,0 +1,4 @@
+import cffi
+ffi = cffi.FFI()
+buf = ffi.buffer(ptr, size)
+data = ffi.cast("uint8_t *", ptr)
"""

_CFFI_FALSE_POSITIVE_DIFF = """\
diff --git a/audio.py b/audio.py
--- /dev/null
+++ b/audio.py
@@ -0,0 +1,3 @@
+# audio_ffi is a non-cffi library wrapper
+result = audio_ffi.cast("int", value)
+buf = mock_ffi.buffer(ptr, size)
"""


class TestMemSafeGate:
    def test_detects_eval_dynamic(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("eval" in f.description.lower() for f in findings)

    def test_detects_exec_dynamic(self, gate):
        diff_files = parse_diff(_EXEC_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_unsafe_rust(self, gate):
        diff_files = parse_diff(_UNSAFE_RUST_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_strcpy(self, gate):
        diff_files = parse_diff(_STRCPY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_ast_literal_eval_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "memsafe"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-16", "CM-7"}
        for f in findings:
            assert f.control_id in valid_ids

    def test_detects_cffi_memory_ops(self, gate):
        diff_files = parse_diff(_CFFI_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("cffi" in f.description.lower() for f in findings)

    def test_no_false_positive_non_cffi_ffi_variable(self, gate):
        diff_files = parse_diff(_CFFI_FALSE_POSITIVE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0
