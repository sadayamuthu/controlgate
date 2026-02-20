# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-02-20

### Added
**Initial Release of ControlGate**: An AI-powered agent skill that scans code changes against the NIST SP 800-53 Rev. 5 security framework before commits and merges, ensuring highly-regulated cloud compliance.

#### Core Capabilities
- **Automated Differential Scanning**: Natively integrates with Git to scan only staged changes (`pre-commit` mode) or branch differences (`pr` mode) against the `main` branch.
- **Dynamic NIST Catalog Resolution**: Automatically fetches, caches, and utilizes the latest version of the NIST Cloud Security Baseline (NCSB) enriched catalog (1,189 controls).
- **Control Exclusions & Configuration**: Supports strict gating actions via `.controlgate.yml` (`block`, `warn`, or `ignore`) based on NIST severity levels, with the ability to define target baselines (e.g., `moderate`) and path exclusions.

#### The 8 Security Gates
- **🔑 Secrets Gate**: Prevents hardcoded credentials, high-entropy strings, and API keys. Maps to NIST IA-5, SC-12, SC-28.
- **🔒 Crypto Gate**: Detects weak hashing (MD5), unencrypted HTTP protocols, and disabled SSL verification. Maps to NIST SC-8, SC-13, SC-17.
- **🛡️ IAM Gate**: Blocks overly permissive wildcard (`*`) access in cloud policies and cross-origin resource sharing (CORS). Maps to NIST AC-3, AC-5, AC-6.
- **📦 Supply Chain Gate**: Avoids unpinned software dependencies, missing lockfiles, and pipeline modifications that could lead to build tampering. Maps to NIST SR-3, SR-11, SA-10.
- **🏗️ IaC Gate**: Hardens infrastructure by detecting public buckets, overly permissive ingress (`0.0.0.0/0`), and root containers. Maps to NIST CM-2, CM-6, SC-7.
- **✅ Input Gate**: Analyzes potential code injection paths (SQL injection), unsafe functions like `eval()`, and bare exceptions that might expose internal stack traces. Maps to NIST SI-10, SI-11.
- **📋 Audit Gate**: Detects removal or absence of secure logging wrappers and warns about Potential PII entering application logs. Maps to NIST AU-2, AU-3, AU-12.
- **🔄 Change Gate**: Alerts on unauthorized configuration changes to sensitive files, CodeOwners, or branch protections. Maps to NIST CM-3, CM-4, CM-5.

#### Multi-Format Reporting
- **Markdown (`markdown`)**: Perfect for automated Pull Request comments.
- **SARIF (`sarif`)**: Full compatibility with GitHub Code Scanning and Advanced Security.
- **JSON (`json`)**: Easily parsed for custom dashboards and automation scripting.

#### CI/CD & Verification Automation
- **Automated GitHub & PyPI Release Action**: `.github/workflows/release.yml` automatically cuts Git tags and GitHub releases, and builds/publishes packages to PyPI when `main` sees a new version in `pyproject.toml`.
- **Pre-Commit Verification**: A robust `.pre-commit-config.yaml` pipeline enforces trailing-whitespace cleanup, YAML validation, `ruff` (formatting/linting), and `mypy` (strict static typing) before local commits succeed.
- **100% Test Coverage Requirement**: Local `Makefile` guarantees that `make check` encompasses robust Pytest validations ensuring zero gaps in safety capabilities.
- **GitHub Branch Protection Enforcement**: Automated documentation recommending server-side constraints that mandate `make test-cov` and `make check` to succeed before PRs can merge.
