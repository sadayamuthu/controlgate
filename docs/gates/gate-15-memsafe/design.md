# Gate 15 — Memory Safety Gate

**gate_id:** `memsafe`
**NIST Controls:** SI-16, CM-7
**Priority:** 🟡 Medium

---

## Purpose

Guards against code changes that introduce dynamic code execution, unsafe memory operations, and patterns that historically lead to memory corruption or code injection across multiple languages. Python's `eval()` and `exec()` allow arbitrary code to run at runtime from attacker-controlled strings; Rust's `unsafe {}` blocks opt out of the language's memory guarantees and require explicit justification; C functions like `strcpy` and `memcpy` with untrusted lengths are the canonical source of buffer overflows; and Python's `ctypes` and `cffi` bindings provide direct access to raw memory in ways that bypass Python's own safety model. By scanning added lines at diff time, the gate prevents these patterns from being merged before they can be exploited.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `eval()` called with a dynamic (non-string-literal) argument | Evaluating a runtime-constructed or user-controlled expression gives an attacker arbitrary Python code execution | SI-16 |
| `exec()` called with any argument | Executes an arbitrary string as Python code at runtime; equivalent to a full remote code execution primitive if the argument is attacker-influenced | SI-16 |
| `unsafe { }` block in Rust source | Opts out of Rust's memory safety guarantees; without a `// SAFETY:` comment the invariants required to make the block correct are undocumented and unreviewed | CM-7 |
| `ctypes` raw memory operations (`address`, `cast`, `memmove`, `memset`) | Directly manipulates process memory from Python, bypassing all of Python's type and bounds checks | SI-16 |
| `ffi.cast`, `ffi.buffer`, `ffi.from_buffer`, or `ffi.memmove` via cffi | Performs raw pointer arithmetic and buffer access through cffi; an unchecked length or miscast pointer can corrupt arbitrary memory | SI-16 |
| `strcpy()` or `strcat()` without bounds checking | Classic C buffer overflow functions — they copy until a null terminator with no length limit, allowing writes beyond the destination buffer | SI-16 |
| `memcpy()` with a potentially untrusted source length (`req`, `input`, `user`, or `argv` in the argument list) | Copying a user-controlled number of bytes into a fixed-size buffer is the textbook buffer overflow; the untrusted length must be validated before the call | SI-16 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files (Python, Rust, C/C++, and any language using cffi/ctypes)

---

## Known Limitations

- Does not scan deleted/removed lines
- Does not perform cross-file analysis
- eval() pattern excludes string-literal arguments (`(?<!\w)eval\s*\((?!\s*["'])`) — string-literal evals are not flagged
- cffi pattern requires standalone `ffi.` (not a property on another object) — variables named `audio_ffi`, `mock_ffi`, etc. are excluded by design

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SI-16 | Memory Protection | Detects dynamic code execution via `eval()`/`exec()`, raw memory access via ctypes and cffi, and unsafe C string/memory functions (`strcpy`, `strcat`, `memcpy`) that bypass language memory safety guarantees |
| CM-7 | Least Functionality | Detects `unsafe {}` blocks in Rust that extend the set of permitted operations beyond what the compiler guarantees safe, requiring documented justification for each use |
