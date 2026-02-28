# Gate 17 — AI/ML Security Gate

**gate_id:** `aiml`
**NIST Controls:** SI-10, SC-28, SR-3
**Priority:** 🟡 Medium

---

## Purpose

Guards against code changes that introduce security vulnerabilities specific to AI and ML workloads. As models grow larger and supply chains more complex, teams increasingly pull weights and code from public registries, deserialize binary files with `pickle`, and compose prompts dynamically from user input — each of which carries distinct exploitation paths. `trust_remote_code=True` executes arbitrary Python from a remote repository at load time; `pickle.load()` and `joblib.load()` deserialize full Python object graphs, enabling code execution the moment a tampered file is opened; unencrypted HTTP downloads strip integrity guarantees from model artifacts in transit; f-string prompt construction with user-controlled variables creates a direct prompt injection vector; and hardcoded model weight paths in config files expose storage locations that should be managed through secrets infrastructure. By flagging these patterns at diff time, the gate prevents high-risk AI/ML anti-patterns from being merged before they can be exploited in training pipelines, inference servers, or model distribution workflows.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `trust_remote_code=True` passed to a model loader | Instructs the Hugging Face library (and compatible loaders) to download and execute arbitrary Python code from a remote model repository; a malicious or compromised model can run any code on the host | SR-3 |
| `pickle.load()` or `pickle.loads()` called on any argument | Python's pickle protocol deserializes arbitrary object graphs, including `__reduce__` methods that execute shell commands; any pickle file from an untrusted source is a remote code execution vector | SI-10 |
| `joblib.load()` called on any argument | joblib uses pickle internally for serialization; the code execution risk is identical to `pickle.load()`, and the familiar API surface makes it easy to overlook | SI-10 |
| Model or weight file downloaded over plain HTTP | Unencrypted HTTP allows a network-positioned attacker to substitute a malicious model in transit; without a checksum the substitution is undetectable by the loading code | SR-3 |
| User input interpolated directly into an LLM prompt via an f-string | Passing unvalidated user-controlled text into a prompt allows an attacker to override system instructions, exfiltrate context, or hijack the model's behaviour (prompt injection) | SI-10 |
| Model weights path hardcoded as a string literal in config | Embedding a storage path in source or config exposes the weights location to anyone who can read the repository and forgoes the access controls and audit trails provided by a secrets manager | SC-28 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files

---

## Known Limitations

- Does not scan deleted/removed lines
- Does not perform cross-file analysis
- SC-28 model-path pattern fires on commented-out lines — no comment stripping is applied (consistent behaviour across all 18 gates)
- Prompt injection pattern is heuristic (f-string with user/request/input/query/prompt variable) and may miss non-f-string concatenation

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SI-10 | Information Input Validation | Detects `pickle.load()`, `joblib.load()`, and f-string prompt construction with user-controlled variables — all of which accept unvalidated external input that can trigger code execution or hijack model behaviour |
| SC-28 | Protection of Information at Rest | Detects model weight paths hardcoded as string literals in config, flagging storage locations that should be managed through encrypted secrets infrastructure rather than exposed in source |
| SR-3 | Supply Chain Controls and Plans | Detects `trust_remote_code=True`, which pulls and executes arbitrary code from an external model registry, and model artifact downloads over unencrypted HTTP, which strip integrity assurance from the supply chain |
