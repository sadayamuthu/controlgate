# 🛡️ ControlGate

[![CI](https://github.com/sadayamuthu/controlgate/actions/workflows/ci.yml/badge.svg)](https://github.com/sadayamuthu/controlgate/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**NIST RMF Cloud Security Hardening — Pre-Commit & Pre-Merge Compliance Gate**

ControlGate is an AI-powered agent skill that scans your code changes against the **NIST SP 800-53 Rev. 5** security framework before every commit and merge. It maps findings directly to specific NIST control IDs, providing traceable compliance evidence and actionable remediation guidance.

## Quick Start

```bash
# Install
pip install controlgate

# Scan staged changes
controlgate scan --mode pre-commit --format markdown

# Scan PR diff against main
controlgate scan --mode pr --target-branch main --format json markdown
```

## How It Works

```
Developer writes code
       ↓
git commit / Pull Request
       ↓
ControlGate intercepts the diff
       ↓
8 Security Gates scan against 370 non-negotiable NIST controls
       ↓
Verdict: BLOCK 🚫 / WARN ⚠️ / PASS ✅
```

## The Eight Security Gates

| # | Gate | NIST Families | What It Catches |
|---|------|---------------|-----------------|
| 1 | 🔑 Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys |
| 2 | 🔒 Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, `ssl_verify=False` |
| 3 | 🛡️ IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles |
| 4 | 📦 Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering |
| 5 | 🏗️ IaC | CM-2, CM-6, SC-7 | Public buckets, `0.0.0.0/0` rules, root containers |
| 6 | ✅ Input | SI-10, SI-11 | SQL injection, `eval()`, exposed stack traces |
| 7 | 📋 Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs |
| 8 | 🔄 Change | CM-3, CM-4, CM-5 | Unauthorized config changes, missing CODEOWNERS |

## Installation

### From Source

```bash
git clone https://github.com/YOUR_ORG/controlgate.git
cd controlgate
python3 -m venv .venv && source .venv/bin/activate
make install-dev
```

### As a Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: controlgate
        name: ControlGate Security Scan
        entry: python -m controlgate scan --mode pre-commit --format markdown
        language: python
        always_run: true
```

### As a GitHub Action

Copy [`hooks/github_action.yml`](hooks/github_action.yml) to `.github/workflows/controlgate.yml` in your repo.

## Configuration

Create a `.controlgate.yml` in your project root:

```yaml
baseline: moderate              # low | moderate | high
catalog: baseline/nist80053r5_full_catalog_enriched.json

gates:
  secrets:    { enabled: true,  action: block }
  crypto:     { enabled: true,  action: block }
  iam:        { enabled: true,  action: warn  }
  sbom:       { enabled: true,  action: warn  }
  iac:        { enabled: true,  action: block }
  input:      { enabled: true,  action: block }
  audit:      { enabled: true,  action: warn  }
  change:     { enabled: true,  action: warn  }

thresholds:
  block_on:   [CRITICAL, HIGH]
  warn_on:    [MEDIUM]
  ignore:     [LOW]

exclusions:
  paths: ["tests/**", "docs/**", "*.md"]
```

## CLI Usage

```bash
# Scan staged changes (pre-commit mode)
controlgate scan --mode pre-commit --format markdown

# Scan PR diff
controlgate scan --mode pr --target-branch main --format json markdown sarif

# Scan a saved diff file
controlgate scan --diff-file path/to/diff --format json

# Output reports to directory
controlgate scan --output-dir .controlgate/reports --format json markdown sarif
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `markdown` | PR comments, terminal output |
| `json` | Programmatic consumption, dashboards |
| `sarif` | GitHub Code Scanning integration |

## Development

```bash
make install-dev    # Install with dev dependencies
make test           # Run tests
make test-cov       # Run tests with coverage
make lint           # Lint with ruff
make format         # Auto-format code
make typecheck      # Type check with mypy
make check          # Run all checks (lint + typecheck + test)
make build          # Build distribution packages
```

## Data Source

Powered by the [NIST Cloud Security Baseline (NCSB)](https://github.com/sadayamuthu/nist-cloud-security-baseline) enriched catalog:
- **1,189** controls across 20 families
- **370** non-negotiable at Moderate baseline
- **247** code-relevant controls mapped to automated scanning rules

## License

MIT
