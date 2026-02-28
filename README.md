# 🛡️ ControlGate

[![CI](https://github.com/sadayamuthu/controlgate/actions/workflows/ci.yml/badge.svg)](https://github.com/sadayamuthu/controlgate/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**NIST RMF & FedRAMP Cloud Security Hardening — Pre-Commit & Pre-Merge Compliance Gate**

ControlGate is an AI-powered agent skill that scans your code changes against the **NIST SP 800-53 Rev. 5** (and **FedRAMP**) security framework before every commit and merge. It maps findings directly to specific NIST control IDs, providing traceable compliance evidence and actionable remediation guidance.

## Quick Start

```bash
# Install
pip install controlgate

# Bootstrap project (creates .controlgate.yml, pre-commit hook, CI workflows)
controlgate init

# Full repo audit (first-time scan)
controlgate scan --mode full --format markdown

# Scan staged changes (NIST baseline)
controlgate scan --mode pre-commit --format markdown

# Scan staged changes (FedRAMP baseline)
controlgate scan --gov --baseline moderate --mode pre-commit --format markdown

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
18 Security Gates scan against 370 non-negotiable NIST controls
       ↓
Verdict: BLOCK 🚫 / WARN ⚠️ / PASS ✅
```

## The 18 Security Gates

| # | Gate | NIST Families | What It Catches |
|---|------|---------------|-----------------|
| 1 | 🔑 Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys |
| 2 | 🔒 Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, `ssl_verify=False` |
| 3 | 🛡️ IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles |
| 4 | 📦 Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering |
| 5 | 🏗️ IaC | CM-2, CM-6, SC-7 | Public buckets, `0.0.0.0/0` rules, root containers |
| 6 | ✅ Input Validation | SI-10, SI-11 | SQL injection, `eval()`, exposed stack traces |
| 7 | 📋 Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs |
| 8 | 🔄 Change Control | CM-3, CM-4, CM-5 | Unauthorized config changes, missing CODEOWNERS |
| 9 | 🧩 Dependencies | SA-12, RA-5, SI-2 | Vulnerable packages, missing lockfiles |
| 10 | 🌐 API Security | SC-8, AC-3, SI-10 | Unauthenticated endpoints, missing rate limiting |
| 11 | 🔐 Privacy | AR-2, DM-1, IP-1 | PII exposure, missing data classification |
| 12 | 🔁 Resilience | CP-2, CP-10, SC-5 | Missing retry logic, no circuit breakers |
| 13 | 🚨 Incident Response | IR-2, IR-4, IR-6 | Missing error handlers, no alerting integration |
| 14 | 👁️ Observability | AU-6, SI-4, CA-7 | Missing health checks, no structured logging |
| 15 | 🧠 Memory Safety | SI-16, SA-11, SA-15 | Buffer overflows, unsafe memory operations |
| 16 | ⚖️ License Compliance | SA-4, SR-3 | GPL contamination, unlicensed dependencies |
| 17 | 🤖 AI/ML Security | SA-11, SI-7, AC-3 | Untrusted model sources, prompt injection risk |
| 18 | 🐳 Container Security | CM-6, AC-6, SC-7 | Root containers, privileged mode, `latest` tags |

## Installation

### From PyPI

```bash
pip install controlgate
```

[View ControlGate on PyPI](https://pypi.org/project/controlgate/)

### As a Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: controlgate
        name: ControlGate Security Scan
        # For FedRAMP baselines, add `--gov --baseline moderate` to the entry command
        entry: python -m controlgate scan --mode pre-commit --format markdown
        language: python
        always_run: true
```

### As a GitHub Action

Copy [`hooks/github_action.yml`](hooks/github_action.yml) to `.github/workflows/controlgate.yml` in your repo.

## Configuration

Create a `.controlgate.yml` in your project root:

```yaml
baseline: moderate              # low | moderate | high | privacy | li-saas
gov: false                      # set to true to evaluate against FedRAMP baselines

gates:
  secrets:          { enabled: true,  action: block }
  crypto:           { enabled: true,  action: block }
  iam:              { enabled: true,  action: warn  }
  sbom:             { enabled: true,  action: warn  }
  iac:              { enabled: true,  action: block }
  input_validation: { enabled: true,  action: block }
  audit:            { enabled: true,  action: warn  }
  change_control:   { enabled: true,  action: warn  }
  deps:             { enabled: true,  action: warn  }
  api:              { enabled: true,  action: warn  }
  privacy:          { enabled: true,  action: warn  }
  resilience:       { enabled: true,  action: warn  }
  incident:         { enabled: true,  action: warn  }
  observability:    { enabled: true,  action: warn  }
  memsafe:          { enabled: true,  action: warn  }
  license:          { enabled: true,  action: warn  }
  aiml:             { enabled: true,  action: warn  }
  container:        { enabled: true,  action: warn  }

thresholds:
  block_on:   [CRITICAL, HIGH]
  warn_on:    [MEDIUM]
  ignore:     [LOW]

exclusions:
  paths: ["tests/**", "docs/**", "*.md"]

full_scan:
  extensions: [.py, .js, .ts, .go, .tf, .yaml, .yml, .json, .sh]
  skip_dirs: [.git, node_modules, .venv, dist, build]
```

## CLI Usage

```bash
# Bootstrap project
controlgate init
controlgate init --baseline high --no-docs

# Scan staged changes (pre-commit mode)
controlgate scan --mode pre-commit --format markdown

# Full repository scan
controlgate scan --mode full --format markdown
controlgate scan --mode full --path ./src --format json

# Scan PR diff
controlgate scan --mode pr --target-branch main --format json markdown sarif

# Scan PR diff explicitly against FedRAMP baselines
controlgate scan --gov --baseline high --mode pr --target-branch main --format json markdown sarif

# Scan a saved diff file
controlgate scan --diff-file path/to/diff --format json

# Output reports to directory
controlgate scan --output-dir .controlgate/reports --format json markdown sarif

# Catalog management
controlgate update-catalog
controlgate catalog-info
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

## AI Agent Skills

ControlGate provides native skills for popular AI coding assistants. These skills teach the agents how to proactively scan your code for NIST 800-53 R5 compliance and automatically apply remediations.

The agent prompts and workflows are located in the [`skills/`](skills/) directory and are published to their respective marketplaces/repositories:

- **Antigravity**: Full workflow definitions available in `skills/antigravity/controlgate/`
- **Cursor**: Repository rules available in `skills/cursor/.cursorrules`
- **Claude Code**: System prompt instructions in `skills/claude_code/.clauderules`
- **CodeEx**: Integration prompts in `skills/codeex/instructions.md`

## Test Suite

To validate the capabilities of ControlGate, we maintain a standalone test suite at [sadayamuthu/controlgate-test-suite](https://github.com/sadayamuthu/controlgate-test-suite).
This suite contains intentionally vulnerable projects spanning multiple languages and frameworks, specifically designed to trigger each of the 18 Security Gates. It is automatically executed in the CI pipeline to ensure zero regression in detection capabilities.

## Data Source

Powered by the [NIST Cloud Security Baseline (NCSB)](https://github.com/sadayamuthu/nist-cloud-security-baseline) enriched catalog:
- **1,189** controls across 20 families
- **370** non-negotiable at Moderate baseline
- **247** code-relevant controls mapped to automated scanning rules

## License

MIT
