<div align="center">

# ControlGate

<h3>NIST RMF & FedRAMP Cloud Security Hardening</h3>

<p>Pre-Commit & Pre-Merge Compliance Gate</p>

[![CI](https://img.shields.io/github/actions/workflow/status/sadayamuthu/controlgate/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/sadayamuthu/controlgate/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)](https://www.python.org/downloads/)
[![License](https://img.shields.io/github/license/sadayamuthu/controlgate?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/controlgate?style=flat-square)](https://pypi.org/project/controlgate/)

---

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [18 Security Gates](#the-18-security-gates) · [Installation](#installation) · [Configuration](#configuration) · [CLI Usage](#cli-usage)

</div>

---

## What is ControlGate?

ControlGate is a command-line tool, with skills for AI coding agents, that scans your code changes against the **NIST SP 800-53 Rev. 5** (and **FedRAMP**) security framework before every commit and merge. It maps findings directly to specific NIST control IDs, providing traceable compliance evidence and actionable remediation guidance.

---

## Quick Start

```bash
# Install
pip install controlgate

# Bootstrap project (writes .controlgate.yml, .pre-commit-config.yaml, CONTROLGATE.md and optional CI config)
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

---

## How It Works

```
Developer writes code
       ↓
git commit / Pull Request
       ↓
ControlGate intercepts the diff
       ↓
18 Security Gates map findings to 45 NIST controls, filtered by your baseline
       ↓
Verdict: BLOCK / WARN / PASS
```

---

## The 18 Security Gates

| # | Gate | NIST Controls | What It Catches |
|---|------|---------------|-----------------|
| 1 | Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys |
| 2 | Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, `ssl_verify=False` |
| 3 | IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles |
| 4 | Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering |
| 5 | IaC | CM-2, CM-6, SC-7 | Public buckets, `0.0.0.0/0` rules, root containers |
| 6 | Input Validation | SI-10, SI-11 | SQL injection, `eval()`, exposed stack traces |
| 7 | Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs |
| 8 | Change Control | CM-3, CM-4, CM-5 | Changes to security-critical files, deploy config, CODEOWNERS, branch protection |
| 9 | Dependencies | SA-12, RA-5, SI-2 | Unpinned installs, `--no-verify`, `--ignore-scripts`, HTTP registries |
| 10 | API Security | SC-8, AC-3, SC-5, SI-10 | Wildcard CORS, disabled TLS verification, keys in URLs, GraphQL introspection |
| 11 | Privacy | PT-2, PT-3, SC-28 | PII in logs, serialize-all-fields, plaintext PII columns, no retention expiry |
| 12 | Resilience | CP-9, CP-10, SI-13 | Disabled backups or deletion protection, zero backup retention, skipped final snapshots, zero retries |
| 13 | Incident Response | IR-4, IR-6, AU-6 | Swallowed exceptions, stack traces in responses, disabled alerting |
| 14 | Observability | SI-4, AU-12 | Disabled monitoring, missing liveness probes, discarded container logs |
| 15 | Memory Safety | SI-16, CM-7 | Unsafe C string and memory calls, `eval`/`exec`, unsafe Rust, ctypes/cffi |
| 16 | License Compliance | SA-4, SR-3 | Copyleft (GPL, AGPL, LGPL, SSPL) licenses in manifests and SPDX headers |
| 17 | AI/ML Security | SI-10, SC-28, SR-3 | `trust_remote_code`, pickle/joblib loading, HTTP model downloads, prompt injection |
| 18 | Container Security | CM-6, AC-6, SC-7 | Root containers, privileged mode, `latest` tags |

---

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

---

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

---

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

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `markdown` | PR comments, terminal output |
| `json` | Programmatic consumption, dashboards |
| `sarif` | GitHub Code Scanning integration |

---

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

---

## AI Agent Skills

ControlGate provides native skills for popular AI coding assistants. These skills teach the agents how to proactively scan your code for NIST 800-53 R5 compliance and automatically apply remediations.

The agent prompts and workflows are located in the [`skills/`](skills/) directory:

- **Antigravity**: Full workflow definitions available in `skills/antigravity/controlgate/`
- **Cursor**: Repository rules available in `skills/cursor/.cursorrules`
- **Claude Code**: System prompt instructions in `skills/claude_code/.clauderules`
- **Codex**: Integration prompts in `skills/codex/instructions.md`

---

## Test Suite

To validate the capabilities of ControlGate, we maintain a standalone test suite at [sadayamuthu/controlgate-test-suite](https://github.com/sadayamuthu/controlgate-test-suite).
This suite contains intentionally vulnerable projects spanning multiple languages and frameworks, specifically designed to trigger each of the 18 Security Gates. It is automatically executed in the CI pipeline to ensure zero regression in detection capabilities.

---

## Data Source

Powered by the [NIST Cloud Security Baseline (NCSB)](https://github.com/sadayamuthu/nist-cloud-security-baseline) enriched catalog:

- **1,196** controls across 20 families (catalog v0.2.0)
- **370** flagged non-negotiable, **287** of them in the Moderate baseline
- **45** distinct controls mapped by the 18 gates

---

## Contributing

Bug reports, false positives and new gates are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the tests and
how to add a gate.

---

## Security

Please report security problems privately, not in a public issue. See
[SECURITY.md](SECURITY.md).

---

## License

[MIT License](LICENSE)

---

<div align="center">

**ControlGate is an open-source NIST RMF & FedRAMP compliance tool**

ControlGate is managed by [OpenAstra](https://openastra.org).

[PyPI](https://pypi.org/project/controlgate/) · [GitHub](https://github.com/sadayamuthu/controlgate) · [Test Suite](https://github.com/sadayamuthu/controlgate-test-suite)

</div>
