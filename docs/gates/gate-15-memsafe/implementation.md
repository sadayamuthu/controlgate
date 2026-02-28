# Gate 15 — Memory Safety Gate: Implementation Reference

**Source file:** `src/controlgate/gates/memsafe_gate.py`
**Test file:** `tests/test_gates/test_memsafe_gate.py`
**Class:** `MemSafeGate`
**gate_id:** `memsafe`
**mapped_control_ids:** `["SI-16", "CM-7"]`

---

## Scan Method

`scan()` iterates over every `DiffFile` in the provided list and, for each added line (via `diff_file.all_added_lines`), runs the line through all seven entries in the module-level `_PATTERNS` list in order. Each entry is a four-tuple of `(compiled_regex, description, control_id, remediation)`. When a compiled regex's `.search()` call matches, `_make_finding()` is called with the associated `control_id`, `file` path, `line` number, `description`, the first 120 characters of the stripped line as `evidence`, and the `remediation` string. All findings are collected into a flat list and returned. There is no early-exit per line; a single added line can produce multiple findings if it matches more than one pattern. Patterns span Python, Rust, C/C++, and any language using cffi or ctypes bindings.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `(?<!\w)eval\s*\((?!\s*["'])` | eval() called with dynamic argument — arbitrary code execution risk | SI-16 | Use ast.literal_eval() for data; never eval() user-controlled input |
| 2 | `(?<!\w)exec\s*\(` | exec() detected — executes arbitrary Python code at runtime | SI-16 | Avoid exec(); use explicit function dispatch or importlib for dynamic behavior |
| 3 | `unsafe\s*\{` | Unsafe Rust block — must have an explicit safety justification comment | CM-7 | Add a `// SAFETY:` comment explaining the invariants that make this block safe |
| 4 | `ctypes\.\w+.*\baddress\b\|ctypes\.cast\|ctypes\.memmove\|ctypes\.memset` | ctypes raw memory operation — bypasses Python memory safety | SI-16 | Audit ctypes usage; prefer cffi with stricter type checking or avoid direct memory access |
| 5 | `(?<!\w)ffi\.(?:cast\|buffer\|from_buffer\|memmove)\s*\(` | cffi raw memory operation — bypasses Python memory safety | SI-16 | Audit cffi usage; ensure pointer arithmetic is bounds-checked and never uses untrusted lengths |
| 6 | `\bstrcpy\s*\(\|\bstrcat\s*\(` | strcpy/strcat used without bounds checking — classic buffer overflow vector | SI-16 | Use strlcpy/strlcat or snprintf with explicit size limits |
| 7 | `\bmemcpy\s*\(.*(?:req\|input\|user\|argv)` | memcpy with potentially untrusted source length — buffer overflow risk | SI-16 | Validate source buffer size before memcpy; consider memmove for overlapping regions |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_eval_dynamic` | A diff adding `eval(user_input)` produces at least one finding whose description contains "eval" |
| `test_detects_exec_dynamic` | A diff adding `exec(code)` with a dynamically constructed string produces at least one finding |
| `test_detects_unsafe_rust` | A diff adding an `unsafe {` block in a Rust file produces at least one finding |
| `test_detects_strcpy` | A diff adding a `strcpy(dest, src)` call in a C file produces at least one finding |
| `test_ast_literal_eval_no_findings` | A diff using only `ast.literal_eval()` produces zero findings, confirming the eval() pattern does not false-positive on the safe alternative |
| `test_findings_have_gate_id` | Every finding produced from the eval diff carries `gate == "memsafe"` |
| `test_findings_have_valid_control_ids` | Every finding produced from the eval diff uses a control ID drawn from `{"SI-16", "CM-7"}` |
| `test_detects_cffi_memory_ops` | A diff adding `ffi.buffer(...)` and `ffi.cast(...)` calls produces at least one finding whose description contains "cffi" |
| `test_no_false_positive_non_cffi_ffi_variable` | A diff adding `audio_ffi.cast(...)` and `mock_ffi.buffer(...)` produces zero findings, confirming the negative lookbehind `(?<!\w)` correctly excludes compound variable names |
