# Gates 9–18 Gap Analysis

**Date:** 2026-02-27
**Status:** Approved — Approach A (fix clear bugs, document known debt)
**Reviewer:** Design review against `docs/plans/2026-02-27-new-gates-design.md`

---

## Summary

All 10 gates are implemented and 223 tests pass. This document records the delta between the approved design and the current implementation, and the decision on how to resolve each gap.

---

## Bugs to Fix (Approach A)

### 1. APIGate — Missing SC-5 and SI-10 in control map

**File:** `src/controlgate/catalog.py` and `src/controlgate/gates/api_gate.py`

| Location | Design | Actual |
|---|---|---|
| `GATE_CONTROL_MAP["api"]` | `["SC-8", "AC-3", "SC-5", "SI-10"]` | `["SC-8", "AC-3"]` |
| `APIGate.mapped_control_ids` | `["SC-8", "AC-3", "SC-5", "SI-10"]` | `["SC-8", "AC-3"]` |

**Fix:** Add `"SC-5"` and `"SI-10"` to both.

---

### 2. MemSafeGate — Missing `cffi.` memory patterns

**File:** `src/controlgate/gates/memsafe_gate.py`

Design spec: _"`ctypes.` / `cffi.` direct memory function calls`"_

Current implementation only covers `ctypes.*` — `cffi` raw buffer/cast calls are not detected.

**Fix:** Add pattern:
```python
re.compile(r"""cffi\.(?:cast|buffer|from_buffer|memmove)""")
```
Control: `SI-16`

---

### 3. AIMLGate — Missing SC-28 plaintext model weights pattern

**File:** `src/controlgate/gates/aiml_gate.py`

Design spec: _"Model weights in plaintext config fields"_ → `SC-28`

Current implementation has no pattern for detecting model weights/checkpoint paths stored in plaintext config (e.g. `model_path = "weights.bin"`, `checkpoint = "/models/prod.pt"`).

**Fix:** Add pattern:
```python
re.compile(r"""(?i)(?:model_path|weights_path|checkpoint_path|model_weights)\s*=\s*["\'][^"\']+["\']""")
```
Control: `SC-28`

---

## Known Debt (Requires Gate Model Extension)

These patterns from the design require scanning **removed lines** or performing **cross-file analysis** — neither is supported by the current `BaseGate.scan()` model which only iterates `all_added_lines`. Deferred to a future gate model enhancement.

| Gate | Design Pattern | Control | Blocker |
|---|---|---|---|
| `deps` (Gate 9) | Manifest changed without lockfile | `SR-3` | Cross-file analysis: check if `requirements.txt`/`package.json` appears in diff but no `.lock` file does |
| `resilience` (Gate 12) | DB connection without `connect_timeout` | `CP-10` | Absence/negative detection: flag if a DB URL appears without a timeout param |
| `observability` (Gate 14) | DLQ resource deleted | `AU-12` | Requires scanning removed lines (`all_removed_lines`) |
| `license` (Gate 16) | License header stripped | `SR-3` | Requires scanning removed lines (`all_removed_lines`) |

**Future work:** Add `all_removed_lines` property to `DiffFile` and a `scan_removed` hook to `BaseGate` to enable removal-aware gates.

---

## No-Gap Gates

The following gates fully match the design spec:

| Gate | Status |
|---|---|
| Gate 9 — DepsGate | ✅ All added-line patterns implemented |
| Gate 10 — APIGate | ⚠️ SC-5/SI-10 missing from map (tracked above) |
| Gate 11 — PrivacyGate | ✅ |
| Gate 12 — ResilienceGate | ✅ All added-line patterns; CP-10 timeout detection deferred |
| Gate 13 — IncidentGate | ✅ |
| Gate 14 — ObservabilityGate | ✅ All added-line patterns; DLQ deletion deferred |
| Gate 15 — MemSafeGate | ⚠️ `cffi.` pattern missing (tracked above) |
| Gate 16 — LicenseGate | ✅ All added-line patterns; removal detection deferred |
| Gate 17 — AIMLGate | ⚠️ SC-28 plaintext weights pattern missing (tracked above) |
| Gate 18 — ContainerGate | ✅ All pattern groups fully implemented |
