"""ControlGate init command — bootstrap project configuration files."""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Template builders
# ---------------------------------------------------------------------------


def _build_controlgate_yml(baseline: str) -> str:
    return f"""\
# .controlgate.yml — ControlGate Configuration
# Reference: https://github.com/sadayamuthu/controlgate
#
# Baseline: low | moderate | high | privacy | li-saas
baseline: {baseline}

# Set to true to evaluate against FedRAMP baselines instead of NIST
gov: false

# NIST control catalog path (auto-managed; change only if self-hosting)
# catalog: baseline/nist80053r5_full_catalog_enriched.json

# ---------------------------------------------------------------------------
# Security Gates — 18 gates mapped to NIST SP 800-53 Rev. 5 controls
# action: block | warn | disabled
# ---------------------------------------------------------------------------
gates:
  # Gate 1 — Secrets & Credentials (IA-5, SC-12, SC-28)
  secrets:          {{ enabled: true,  action: block }}

  # Gate 2 — Cryptography (SC-8, SC-13, SC-17)
  crypto:           {{ enabled: true,  action: block }}

  # Gate 3 — IAM & Access Control (AC-3, AC-5, AC-6)
  iam:              {{ enabled: true,  action: warn  }}

  # Gate 4 — Supply Chain / SBOM (SR-3, SR-11, SA-10)
  sbom:             {{ enabled: true,  action: warn  }}

  # Gate 5 — Infrastructure as Code (CM-2, CM-6, SC-7)
  iac:              {{ enabled: true,  action: block }}

  # Gate 6 — Input Validation (SI-10, SI-11)
  input_validation: {{ enabled: true,  action: block }}

  # Gate 7 — Audit Logging (AU-2, AU-3, AU-12)
  audit:            {{ enabled: true,  action: warn  }}

  # Gate 8 — Change Control (CM-3, CM-4, CM-5)
  change_control:   {{ enabled: true,  action: warn  }}

  # Gate 9 — Dependency Management (SA-12, RA-5, SI-2)
  deps:             {{ enabled: true,  action: warn  }}

  # Gate 10 — API Security (SC-8, AC-3, SI-10)
  api:              {{ enabled: true,  action: warn  }}

  # Gate 11 — Privacy (AR-2, DM-1, IP-1)
  privacy:          {{ enabled: true,  action: warn  }}

  # Gate 12 — Resilience & Reliability (CP-2, CP-10, SC-5)
  resilience:       {{ enabled: true,  action: warn  }}

  # Gate 13 — Incident Response (IR-2, IR-4, IR-6)
  incident:         {{ enabled: true,  action: warn  }}

  # Gate 14 — Observability (AU-6, SI-4, CA-7)
  observability:    {{ enabled: true,  action: warn  }}

  # Gate 15 — Memory Safety (SI-16, SA-11, SA-15)
  memsafe:          {{ enabled: true,  action: warn  }}

  # Gate 16 — License Compliance (SA-4, SR-3)
  license:          {{ enabled: true,  action: warn  }}

  # Gate 17 — AI/ML Security (SA-11, SI-7, AC-3)
  aiml:             {{ enabled: true,  action: warn  }}

  # Gate 18 — Container Security (CM-6, AC-6, SC-7)
  container:        {{ enabled: true,  action: warn  }}

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------
thresholds:
  block_on: [CRITICAL, HIGH]
  warn_on:  [MEDIUM]
  ignore:   [LOW]

# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
exclusions:
  paths:
    - "tests/**"
    - "docs/**"
    - "*.md"
  controls: []

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
reporting:
  format: [json, markdown]
  sarif: false
  output_dir: .controlgate/reports

# ---------------------------------------------------------------------------
# Full scan mode
# ---------------------------------------------------------------------------
full_scan:
  extensions:
    - .py
    - .js
    - .ts
    - .go
    - .java
    - .rb
    - .tf
    - .yaml
    - .yml
    - .json
    - .toml
    - .sh
    - .env
    - .sql
  skip_dirs:
    - .git
    - node_modules
    - .venv
    - venv
    - __pycache__
    - dist
    - build
    - .tox
"""


def _build_precommit_config() -> str:
    return """\
# .pre-commit-config.yaml — ControlGate pre-commit hook
# Install: pip install pre-commit && pre-commit install
repos:
  - repo: local
    hooks:
      - id: controlgate
        name: ControlGate Security Scan
        entry: python -m controlgate scan --mode pre-commit --format markdown
        language: python
        always_run: true
        pass_filenames: false
"""


def _build_controlgate_md() -> str:
    return """\
# ControlGate — Security Compliance Guide

ControlGate enforces **NIST SP 800-53 Rev. 5** (and **FedRAMP**) security controls
on every commit and merge through automated gate scanning.

---

## Quick Start

```bash
# Install
pip install controlgate

# Bootstrap this project
controlgate init

# Baseline audit — scan the entire repo
controlgate scan --mode full --format markdown

# Pre-commit scan (staged changes only)
controlgate scan --mode pre-commit --format markdown

# PR scan (branch diff vs main)
controlgate scan --mode pr --target-branch main --format json markdown sarif
```

---

## Scan Modes

| Mode | Command | What It Scans |
|------|---------|---------------|
| `pre-commit` | `controlgate scan --mode pre-commit` | Staged changes (`git diff --cached`) |
| `pr` | `controlgate scan --mode pr --target-branch main` | Branch diff vs target branch |
| `full` | `controlgate scan --mode full [--path ./src]` | Entire project directory |

---

## The 18 Security Gates

| # | Gate | NIST Families | What It Catches | Default Action |
|---|------|---------------|-----------------|----------------|
| 1 | Secrets | IA-5, SC-12, SC-28 | Hardcoded creds, API keys, private keys | BLOCK |
| 2 | Crypto | SC-8, SC-13, SC-17 | Weak algorithms, missing TLS, ssl_verify=False | BLOCK |
| 3 | IAM | AC-3, AC-5, AC-6 | Wildcard IAM, missing auth, overprivileged roles | WARN |
| 4 | Supply Chain | SR-3, SR-11, SA-10 | Unpinned deps, missing lockfiles, build tampering | WARN |
| 5 | IaC | CM-2, CM-6, SC-7 | Public buckets, 0.0.0.0/0 rules, root containers | BLOCK |
| 6 | Input Validation | SI-10, SI-11 | SQL injection, eval(), exposed stack traces | BLOCK |
| 7 | Audit | AU-2, AU-3, AU-12 | Missing security logging, PII in logs | WARN |
| 8 | Change Control | CM-3, CM-4, CM-5 | Unauthorized config changes, missing CODEOWNERS | WARN |
| 9 | Dependencies | SA-12, RA-5, SI-2 | Vulnerable packages, missing lockfiles | WARN |
| 10 | API Security | SC-8, AC-3, SI-10 | Unauthenticated endpoints, missing rate limits | WARN |
| 11 | Privacy | AR-2, DM-1, IP-1 | PII exposure, missing data classification | WARN |
| 12 | Resilience | CP-2, CP-10, SC-5 | Missing retry logic, no circuit breakers | WARN |
| 13 | Incident Response | IR-2, IR-4, IR-6 | Missing error handlers, no alerting hooks | WARN |
| 14 | Observability | AU-6, SI-4, CA-7 | Missing health checks, no structured logging | WARN |
| 15 | Memory Safety | SI-16, SA-11, SA-15 | Buffer overflows, unsafe memory ops | WARN |
| 16 | License Compliance | SA-4, SR-3 | GPL contamination, unlicensed dependencies | WARN |
| 17 | AI/ML Security | SA-11, SI-7, AC-3 | Untrusted model sources, prompt injection risk | WARN |
| 18 | Container Security | CM-6, AC-6, SC-7 | Root containers, privileged mode, latest tags | WARN |

---

## Configuration Reference

```yaml
baseline: moderate              # low | moderate | high | privacy | li-saas
gov: false                      # true = FedRAMP baselines

gates:
  secrets: { enabled: true, action: block }
  # ... (all 18 gates)

thresholds:
  block_on: [CRITICAL, HIGH]
  warn_on:  [MEDIUM]
  ignore:   [LOW]

exclusions:
  paths: ["tests/**", "docs/**", "*.md"]
  controls: []

reporting:
  format: [json, markdown]
  sarif: false
  output_dir: .controlgate/reports

full_scan:
  extensions: [.py, .js, .ts, .tf, .yaml, .yml, .json, .sh]
  skip_dirs: [.git, node_modules, .venv, dist, build]
```

---

## CLI Reference

```bash
controlgate init [--path PATH] [--baseline LEVEL] [--no-docs]
controlgate scan [--mode pre-commit|pr|full] [--path PATH]
                 [--target-branch BRANCH] [--diff-file FILE]
                 [--format json|markdown|sarif] [--output-dir DIR]
                 [--baseline LEVEL] [--gov] [--config FILE]
controlgate update-catalog
controlgate catalog-info
```
"""


def _build_github_workflow() -> str:
    return """\
name: ControlGate Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  controlgate:
    name: ControlGate Compliance Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ControlGate
        run: pip install controlgate

      - name: Run ControlGate scan
        id: scan
        run: |
          controlgate scan \\
            --mode pr \\
            --target-branch ${{ github.base_ref || 'main' }} \\
            --format json markdown sarif \\
            --output-dir .controlgate/reports
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .controlgate/reports/verdict.sarif
        continue-on-error: true

      - name: Comment on PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const reportPath = '.controlgate/reports/verdict.md';
            if (fs.existsSync(reportPath)) {
              const body = fs.readFileSync(reportPath, 'utf8');
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: body,
              });
            }

      - name: Enforce gate
        if: steps.scan.outcome == 'failure'
        run: |
          echo "ControlGate blocked this change due to security findings."
          exit 1
"""


def _build_gitlab_ci() -> str:
    return """\
stages:
  - security

controlgate:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install controlgate
  script:
    - >
      controlgate scan
      --mode pr
      --target-branch ${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-main}
      --format json markdown sarif
      --output-dir .controlgate/reports
  artifacts:
    paths:
      - .controlgate/reports/
    when: always
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


def _build_bitbucket_pipelines() -> str:
    return """\
image: python:3.12-slim

pipelines:
  pull-requests:
    '**':
      - step:
          name: ControlGate Security Scan
          script:
            - pip install controlgate
            - >
              controlgate scan
              --mode pr
              --target-branch main
              --format json markdown
              --output-dir .controlgate/reports
          artifacts:
            - .controlgate/reports/**
  branches:
    main:
      - step:
          name: ControlGate Full Scan
          script:
            - pip install controlgate
            - >
              controlgate scan
              --mode full
              --format json markdown
              --output-dir .controlgate/reports
          artifacts:
            - .controlgate/reports/**
"""


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------


def _prompt(question: str, default: str = "") -> str:
    """Prompt with an optional default value."""
    if default:
        answer = input(f"  {question} [{default}]: ").strip()
        return answer if answer else default
    return input(f"  {question}: ").strip()


def _prompt_yn(question: str, default: bool = False) -> bool:
    """Yes/no prompt."""
    default_str = "Y/n" if default else "y/N"
    answer = input(f"  {question} [{default_str}]: ").strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def _write_file(path: Path, content: str) -> bool:
    """Write file, prompting if it already exists. Returns True if written."""
    if path.exists() and not _prompt_yn(f"{path} already exists. Overwrite?", default=False):
        print(f"  Skipped: {path}")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  Creating {path} ... done")
    return True


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------


def init_command(args: object) -> int:
    """Execute the init command — interactive project bootstrap.

    Args:
        args: Parsed CLI arguments with optional ``path``, ``baseline``,
              and ``no_docs`` attributes.

    Returns:
        0 on success.
    """
    root = Path(getattr(args, "path", None) or ".").resolve()
    no_docs = getattr(args, "no_docs", False)

    print()
    print("ControlGate Init")
    print("-" * 50)

    # Baseline
    default_baseline = getattr(args, "baseline", None) or "moderate"
    baseline = _prompt("Baseline? (low/moderate/high/privacy/li-saas)", default=default_baseline)
    if baseline not in ("low", "moderate", "high", "privacy", "li-saas"):
        print(f"  Unknown baseline '{baseline}', using 'moderate'")
        baseline = "moderate"

    # CI/CD choices
    gen_github = _prompt_yn("Generate GitHub Actions workflow?", default=False)
    gen_gitlab = _prompt_yn("Generate GitLab CI job?", default=False)
    gen_bitbucket = _prompt_yn("Generate Bitbucket Pipelines step?", default=False)

    print("-" * 50)

    _write_file(root / ".controlgate.yml", _build_controlgate_yml(baseline))
    _write_file(root / ".pre-commit-config.yaml", _build_precommit_config())

    if not no_docs:
        _write_file(root / "CONTROLGATE.md", _build_controlgate_md())

    if gen_github:
        _write_file(
            root / ".github" / "workflows" / "controlgate.yml",
            _build_github_workflow(),
        )

    if gen_gitlab:
        _write_file(root / ".gitlab-ci.yml", _build_gitlab_ci())

    if gen_bitbucket:
        _write_file(root / "bitbucket-pipelines.yml", _build_bitbucket_pipelines())

    print("-" * 50)
    print("Done! ControlGate is configured for this project.")
    print()
    print("  Next steps:")
    print("    1. Review .controlgate.yml and adjust gate settings")
    print("    2. pip install pre-commit && pre-commit install")
    print("    3. controlgate scan --mode full   (baseline audit)")
    print()
    return 0
