# Gate Gap Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 3 concrete gaps between the approved gate design and the current implementation: a control-ID mismatch in APIGate, a missing `cffi.` pattern in MemSafeGate, and a missing SC-28 plaintext weights pattern in AIMLGate.

**Architecture:** Pure additive changes — no new files, no new gate classes, no changes to engine, base, or reporters. Each fix touches at most 3 files: the gate module, its test file, and `catalog.py`.

**Tech Stack:** Python 3.10+, pytest, re (stdlib). Run tests with `.venv/bin/pytest tests/ -v`.

---

## Context

Reference files before starting:
- `docs/plans/2026-02-27-gates-gap-analysis.md` — full gap analysis
- `docs/plans/2026-02-27-new-gates-design.md` — original approved design

---

## Task 1: Fix APIGate — Add SC-5 and SI-10 to control map

**Files:**
- Modify: `src/controlgate/catalog.py` (line ~21, the `"api"` entry)
- Modify: `src/controlgate/gates/api_gate.py` (line ~61, `mapped_control_ids`)
- Modify: `tests/test_gates/test_api_gate.py` (update `valid_ids` in control ID test)

**Background:** The design specifies `["SC-8", "AC-3", "SC-5", "SI-10"]` for the API gate. The current implementation only has `["SC-8", "AC-3"]`. SC-5 (Denial of Service Protection) and SI-10 (Information Input Validation) are genuinely covered by the existing CORS-wildcard and GraphQL introspection patterns.

### Step 1: Update the failing test to assert SC-5/SI-10 are valid

Open `tests/test_gates/test_api_gate.py` and find `test_findings_have_valid_control_ids`. Change:

```python
valid_ids = {"SC-8", "AC-3", "SC-5", "SI-10"}
```

It already says this — confirm it does. If it only says `{"SC-8", "AC-3"}`, update it.

### Step 2: Run tests to confirm current state

```bash
.venv/bin/pytest tests/test_gates/test_api_gate.py -v
```

Expected: All pass (the test already uses `{"SC-8", "AC-3", "SC-5", "SI-10"}` as valid_ids — this passes because it's a superset check; findings only use SC-8/AC-3 which are in the set).

### Step 3: Update `catalog.py` GATE_CONTROL_MAP

In `src/controlgate/catalog.py`, change:

```python
"api": ["SC-8", "AC-3"],
```

to:

```python
"api": ["SC-8", "AC-3", "SC-5", "SI-10"],
```

### Step 4: Update `APIGate.mapped_control_ids`

In `src/controlgate/gates/api_gate.py`, change:

```python
mapped_control_ids = ["SC-8", "AC-3"]
```

to:

```python
mapped_control_ids = ["SC-8", "AC-3", "SC-5", "SI-10"]
```

### Step 5: Run full test suite to confirm nothing breaks

```bash
.venv/bin/pytest tests/ -v --tb=short
```

Expected: All 223 tests pass.

### Step 6: Commit

```bash
git add src/controlgate/catalog.py src/controlgate/gates/api_gate.py
PATH="$PWD/.venv/bin:$PATH" git commit -m "fix: add SC-5 and SI-10 to APIGate control map (align with design)"
```

---

## Task 2: Add `cffi.` memory patterns to MemSafeGate

**Files:**
- Modify: `src/controlgate/gates/memsafe_gate.py` (add 1 pattern to `_PATTERNS`)
- Modify: `tests/test_gates/test_memsafe_gate.py` (add 1 new test)

**Background:** The design specifies `"ctypes. / cffi. direct memory function calls"` as a SI-16 pattern. Current implementation covers `ctypes.*` only. `cffi` is a widely used C FFI library for Python whose `cast`, `buffer`, and `from_buffer` functions bypass memory safety.

### Step 1: Write the failing test

Add to `tests/test_gates/test_memsafe_gate.py`, inside `TestMemSafeGate`:

```python
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

def test_detects_cffi_memory_ops(self, gate):
    diff_files = parse_diff(_CFFI_DIFF)
    findings = gate.scan(diff_files)
    assert len(findings) > 0
    assert any("cffi" in f.description.lower() for f in findings)
```

### Step 2: Run test to verify it fails

```bash
.venv/bin/pytest tests/test_gates/test_memsafe_gate.py::TestMemSafeGate::test_detects_cffi_memory_ops -v
```

Expected: FAIL — `assert 0 > 0` (no findings, pattern not implemented yet).

### Step 3: Add the cffi pattern to `memsafe_gate.py`

In `src/controlgate/gates/memsafe_gate.py`, add to `_PATTERNS` after the ctypes entry:

```python
(
    re.compile(r"""ffi\.(?:cast|buffer|from_buffer|memmove)\s*\("""),
    "cffi raw memory operation — bypasses Python memory safety",
    "SI-16",
    "Audit cffi usage; ensure pointer arithmetic is bounds-checked and never uses untrusted lengths",
),
```

### Step 4: Run the new test to verify it passes

```bash
.venv/bin/pytest tests/test_gates/test_memsafe_gate.py -v
```

Expected: All 8 tests pass (7 existing + 1 new).

### Step 5: Run full suite

```bash
.venv/bin/pytest tests/ -v --tb=short
```

Expected: All 224 tests pass.

### Step 6: Commit

```bash
git add src/controlgate/gates/memsafe_gate.py tests/test_gates/test_memsafe_gate.py
PATH="$PWD/.venv/bin:$PATH" git commit -m "feat: add cffi memory operation detection to MemSafeGate (SI-16)"
```

---

## Task 3: Add plaintext model weights pattern to AIMLGate

**Files:**
- Modify: `src/controlgate/gates/aiml_gate.py` (add 1 pattern to `_PATTERNS`)
- Modify: `tests/test_gates/test_aiml_gate.py` (add 1 new test)

**Background:** The design specifies `"Model weights in plaintext config fields"` → SC-28. This catches hardcoded model weight paths or checkpoint references in config files/code that indicate weights are stored in plaintext (no vault or encryption reference). Pattern: detect `model_path`, `weights_path`, `checkpoint_path`, `model_weights` assigned to a bare string literal.

### Step 1: Write the failing test

Add to `tests/test_gates/test_aiml_gate.py`, inside `TestAIMLGate`:

```python
_PLAINTEXT_WEIGHTS_DIFF = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+MODEL_WEIGHTS = "/data/models/prod_weights.bin"
+checkpoint_path = "s3://bucket/model.pt"
+weights_path = "/mnt/nfs/weights.ckpt"
"""

def test_detects_plaintext_model_weights(self, gate):
    diff_files = parse_diff(_PLAINTEXT_WEIGHTS_DIFF)
    findings = gate.scan(diff_files)
    assert len(findings) > 0
    assert any("plaintext" in f.description.lower() or "weight" in f.description.lower() for f in findings)
    assert all(f.control_id == "SC-28" for f in findings)
```

### Step 2: Run test to verify it fails

```bash
.venv/bin/pytest tests/test_gates/test_aiml_gate.py::TestAIMLGate::test_detects_plaintext_model_weights -v
```

Expected: FAIL — `assert 0 > 0`.

### Step 3: Add the pattern to `aiml_gate.py`

In `src/controlgate/gates/aiml_gate.py`, add to `_PATTERNS`:

```python
(
    re.compile(
        r"""(?i)(?:model_path|weights_path|checkpoint_path|model_weights)\s*=\s*["\'][^"\']+["\']"""
    ),
    "Model weights path stored in plaintext config — weights location exposed without encryption",
    "SC-28",
    "Store model paths in a secrets manager or encrypted config; avoid hardcoding weight locations",
),
```

### Step 4: Run the new test to verify it passes

```bash
.venv/bin/pytest tests/test_gates/test_aiml_gate.py -v
```

Expected: All 8 tests pass (7 existing + 1 new).

### Step 5: Run full suite

```bash
.venv/bin/pytest tests/ -v --tb=short
```

Expected: All 225 tests pass.

### Step 6: Commit

```bash
git add src/controlgate/gates/aiml_gate.py tests/test_gates/test_aiml_gate.py
PATH="$PWD/.venv/bin:$PATH" git commit -m "feat: add plaintext model weights detection to AIMLGate (SC-28)"
```

---

## Task 4: Final verification

### Step 1: Run full test suite

```bash
.venv/bin/pytest tests/ -v --tb=short
```

Expected: All 225 tests pass across 18 gates.

### Step 2: Verify gate catalog completeness

```bash
.venv/bin/python -c "
from controlgate.catalog import GATE_CONTROL_MAP
from controlgate.gates import ALL_GATES
print(f'{len(ALL_GATES)} gates, {len(GATE_CONTROL_MAP)} catalog entries')
for g in ALL_GATES:
    ids = GATE_CONTROL_MAP.get(g.gate_id, [])
    cls_ids = g.mapped_control_ids
    match = set(ids) == set(cls_ids)
    status = '✓' if match else '✗ MISMATCH'
    print(f'  {g.gate_id:16} catalog={ids} class={cls_ids} {status}')
"
```

Expected: All 18 gates show `✓` — catalog and class `mapped_control_ids` fully agree.

### Step 3: Commit checklist summary

No code changes — just a note that verification passed. Optionally update the gap analysis doc status line:

In `docs/plans/2026-02-27-gates-gap-analysis.md`, change the header status from:
```
**Status:** Approved — Approach A (fix clear bugs, document known debt)
```
to:
```
**Status:** Complete — Approach A fixes applied 2026-02-27
```

```bash
git add docs/plans/2026-02-27-gates-gap-analysis.md
PATH="$PWD/.venv/bin:$PATH" git commit -m "docs: mark gap analysis complete — all Approach A fixes applied"
```

---

## Checklist

- [ ] Task 1: APIGate — SC-5/SI-10 added to catalog and class
- [ ] Task 2: MemSafeGate — `cffi.` pattern added, 1 new test
- [ ] Task 3: AIMLGate — SC-28 plaintext weights pattern, 1 new test
- [ ] Task 4: Full suite passes (225 tests), catalog/class alignment verified
