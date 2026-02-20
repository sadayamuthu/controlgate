#!/usr/bin/env python3
"""Git pre-commit hook for ControlGate.

Install by copying or symlinking this file to `.git/hooks/pre-commit`,
or use with the pre-commit framework:

    # .pre-commit-config.yaml
    repos:
      - repo: local
        hooks:
          - id: controlgate
            name: ControlGate Security Scan
            entry: python -m controlgate scan --mode pre-commit --format markdown
            language: python
            always_run: true
"""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    """Run ControlGate on staged changes."""
    cmd = [
        sys.executable,
        "-m",
        "controlgate",
        "scan",
        "--mode",
        "pre-commit",
        "--format",
        "markdown",
    ]

    result = subprocess.run(cmd)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
