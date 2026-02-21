---
description: How to run ControlGate and fix identified NIST 800-53 R5 vulnerabilities
---

# Workflow: Scan and Fix with ControlGate

This workflow defines the standard operating procedure for using ControlGate to identify and remediate security vulnerabilities in the current project.

1. **Run the Scanner:**
   Use the `run_command` tool to execute `controlgate` against the target directory or files, outputting a SARIF report.
   // turbo
   ```bash
   controlgate scan . --format sarif --output controlgate-results.sarif
   ```

2. **Check for Findings:**
   Read the `controlgate-results.sarif` file if the previous command returned a non-zero exit code indicating vulnerabilities. Find the `results` array in the JSON structure.

3. **Locate the Vulnerable Code:**
   For each finding in the `results` array, identify the `physicalLocation` (file path and line number).

4. **Understand the Violation:**
   Read the `ruleId` (e.g., NIST AC-3) and the `message` to understand what secure configuration is missing.

5. **Remediate:**
   Use the `replace_file_content` or `multi_replace_file_content` tools to modify the vulnerable file, implementing the correct, secure configuration as dictated by the NIST control.

6. **Verify the Fix:**
   Re-run the scanner to ensure the previous findings are resolved.
   // turbo
   ```bash
   controlgate scan . --format sarif --output controlgate-results.sarif
   ```

7. **Report:**
   Summarize the fixes applied to the user, referencing the specific files changed and the NIST controls that were satisfied.
