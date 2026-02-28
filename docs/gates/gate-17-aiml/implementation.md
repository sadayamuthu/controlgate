# Gate 17 — AI/ML Security Gate: Implementation Reference

**Source file:** `src/controlgate/gates/aiml_gate.py`
**Test file:** `tests/test_gates/test_aiml_gate.py`
**Class:** `AIMLGate`
**gate_id:** `aiml`
**mapped_control_ids:** `["SI-10", "SC-28", "SR-3"]`

---

## Scan Method

`scan()` iterates over every `DiffFile` in the provided list and, for each added line (via `diff_file.all_added_lines`), runs the line through all six entries in the module-level `_PATTERNS` list in order. Each entry is a four-tuple of `(compiled_regex, description, control_id, remediation)`. When a compiled regex's `.search()` call matches the line, `_make_finding()` is called with the associated `control_id`, file path, line number, `description`, the first 120 characters of the stripped line as evidence, and the `remediation` string. All findings are collected into a flat list and returned. There is no early-exit per line; a single added line can produce multiple findings if it matches more than one pattern.

---

## Patterns

| # | Regex | Description | Control | Remediation |
|---|---|---|---|---|
| 1 | `trust_remote_code\s*=\s*True` | `trust_remote_code=True` executes arbitrary code from a remote model repository | SR-3 | Never use `trust_remote_code=True`; audit the model source and load from a vetted internal registry |
| 2 | `pickle\.load\s*\(\|pickle\.loads\s*\(` | `pickle.load()` deserializes arbitrary Python objects — code execution on load | SI-10 | Use safetensors or ONNX format instead of pickle; never load pickle files from untrusted sources |
| 3 | `joblib\.load\s*\(` | `joblib.load()` uses pickle internally — arbitrary code execution risk | SI-10 | Verify the source and checksum of joblib files before loading; prefer safetensors |
| 4 | `http://[^\s]*(?:model\|weight\|checkpoint\|\.bin\|\.pt\|\.pkl\|\.onnx)` | Model or weights downloaded over unencrypted HTTP | SR-3 | Use HTTPS for all model downloads and verify checksums (SHA256) after download |
| 5 | `f["'].*\{.*(?:user\|request\|input\|query\|prompt).*\}.*["']` | User input interpolated directly into LLM prompt — prompt injection risk | SI-10 | Sanitize and validate user input before including in prompts; use structured message formats |
| 6 | `(?i)(?:model_path\|weights_path\|checkpoint_path\|model_weights)\s*=\s*["'][^"']+["']` | Model weights path stored in plaintext config — weights location exposed without encryption | SC-28 | Store model paths in a secrets manager or encrypted config; avoid hardcoding weight locations |

---

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_detects_trust_remote_code` | A diff adding a `from_pretrained()` call with `trust_remote_code=True` produces at least one finding whose description contains "trust_remote_code" or "remote" |
| `test_detects_pickle_load` | A diff adding a `pickle.load(f)` call produces at least one finding |
| `test_detects_http_model_download` | A diff adding an HTTP URL referencing a `.bin` weights file produces at least one finding |
| `test_detects_prompt_injection_pattern` | A diff adding an f-string prompt that interpolates `user_input` produces at least one finding |
| `test_clean_model_load_no_findings` | A diff adding a standard `torch.load()` call with no unsafe patterns produces zero findings |
| `test_findings_have_gate_id` | Every finding produced by the gate carries `gate == "aiml"` |
| `test_findings_have_valid_control_ids` | Every finding produced by the gate uses a control ID drawn from `{"SI-10", "SC-28", "SR-3"}` |
| `test_detects_plaintext_model_weights` | A diff adding string-literal assignments to `MODEL_WEIGHTS`, `checkpoint_path`, and `weights_path` produces at least one finding whose description contains "plaintext" or "weight", and every finding carries `control_id == "SC-28"` |
| `test_no_false_positive_safe_model_path_access` | A diff assigning model path variables via `os.environ`, `config.get()`, and `vault.read_secret()` (no string literals) produces zero SC-28 findings |
