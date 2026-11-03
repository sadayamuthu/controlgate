# Contributing to ControlGate

Thanks for helping. ControlGate is only useful if its findings can be
trusted, so most of this guide is about keeping it precise: every change in
behaviour comes with a test that proves it, and the suite has to stay at
100% coverage.

- [Ways to help](#ways-to-help)
- [Reporting a wrong or missed finding](#reporting-a-wrong-or-missed-finding)
- [Development setup](#development-setup)
- [Tests](#tests)
- [Code layout](#code-layout)
- [Adding a gate](#adding-a-gate)
- [Pull requests](#pull-requests)
- [Security](#security)
- [License](#license)

## Ways to help

- **Report a false positive or a missed finding.** This is the most useful
  contribution. See the next section.
- **Run it on your repository** (`controlgate scan --mode full`) and tell us
  what it found, in an issue. Real-world results guide what to fix next.
- **Pick up an issue** labelled
  [`good first issue`](https://github.com/sadayamuthu/controlgate/labels/good%20first%20issue)
  or [`help wanted`](https://github.com/sadayamuthu/controlgate/labels/help%20wanted).
- **Add a vulnerable example** to the
  [controlgate-test-suite](https://github.com/sadayamuthu/controlgate-test-suite)
  repository, which CI runs against every change.

For anything larger than a small fix, open an issue first so we can agree on
the approach before you write the code.

## Reporting a wrong or missed finding

Please include:

1. `pip show controlgate` output (the version) and `controlgate catalog-info`
   output (the catalog version, since findings depend on it).
2. The command you ran, your `.controlgate.yml` if you have one, and the
   `--format json` output.
3. What you expected instead, and why. For a wrong control mapping, name the
   NIST SP 800-53 control you think applies.
4. A minimal reproduction: the few lines of code or the small diff that
   triggers it (or should). `controlgate scan --diff-file <file>` runs on a
   saved diff, so a diff file is the easiest thing to attach, and it becomes
   the test.

If the code is private, reduce it to a made-up example that still shows the
problem.

## Development setup

You need **Python 3.10** or newer and **git**.

```sh
git clone https://github.com/sadayamuthu/controlgate.git
cd controlgate
python3 -m venv .venv && . .venv/bin/activate
make install-dev      # pip install -e ".[dev]" and pre-commit install
controlgate catalog-info
```

The NIST catalog isn't in the repository. ControlGate downloads it on first
use (or with `make fetch-catalog`) into `src/controlgate/data/`, which is
git-ignored, so the first test run needs network access.

`make install-dev` also installs the pre-commit hooks in
`.pre-commit-config.yaml`: whitespace and YAML checks, ruff, mypy, and a
`bump-version` hook that bumps the minor version in `pyproject.toml` (and
`__version__` in `src/controlgate/__init__.py`) when it still matches
`origin/main`. If your change should be a patch release instead, set the
version in both files by hand before you commit; `tests/test_version.py`
checks that they match.

Before pushing, run what CI runs (`.github/workflows/ci.yml`, on Python
3.10, 3.11 and 3.12):

```sh
python -m ruff check src/ tests/
python -m ruff format --check src/ tests/
python -m mypy src/controlgate/
python -m pytest tests/ -v --cov=controlgate
```

`make check` runs lint, typecheck and tests together, and `make format`
fixes formatting. CI also runs the
[controlgate-test-suite](https://github.com/sadayamuthu/controlgate-test-suite)
and expects ControlGate to block its intentionally vulnerable projects, and
on pull requests it fails if the version in `pyproject.toml` hasn't changed.

## Tests

Tests live in [`tests/`](tests) and use pytest. Coverage must stay at 100%
(`fail_under = 100` in `pyproject.toml`).

| Path | What it covers |
|------|----------------|
| `tests/test_gates/test_<gate>_gate.py` | One file per gate: diffs that must and must not produce findings |
| `tests/test_coverage_gaps.py`, `tests/test_final_coverage.py` | Remaining paths, including the audit, change control and SBOM gates |
| `tests/test_engine.py` | Baseline filtering, thresholds and the verdict |
| `tests/test_diff_parser.py` | Unified diff parsing |
| `tests/test_full_scan.py` | `--mode full` file enumeration |
| `tests/test_cli.py` | The `controlgate` command line |
| `tests/test_init_command.py` | `controlgate init` |
| `tests/test_config.py`, `tests/test_catalog.py`, `tests/test_catalog_downloader.py` | Config loading, catalog queries, catalog download |
| `tests/test_reporters.py` | JSON, Markdown and SARIF output |
| `tests/test_bump_version.py` | The `bump-version` pre-commit hook |

Gate tests feed a unified diff string through `parse_diff` and assert on the
findings, using the `catalog` fixture from `tests/conftest.py`:

```python
_GPL_PIP_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 requests==2.31.0
+gpl-licensed-lib==1.0.0  # GPL-3.0
"""
```

**Every behaviour change needs a test.** For a bug fix, add a test that fails
before your change and passes after it. For a false positive, add a test
that the offending diff produces no finding.

## Code layout

| Path | What it does |
|------|--------------|
| `src/controlgate/__main__.py` | CLI entry point: `scan`, `init`, `update-catalog`, `catalog-info` |
| `src/controlgate/engine.py` | Runs the enabled gates, filters findings by baseline, applies thresholds, builds the verdict |
| `src/controlgate/gates/` | One file per gate, on the `BaseGate` class in `base.py`; `__init__.py` lists them in `ALL_GATES` |
| `src/controlgate/diff_parser.py` | Parses unified diffs into `DiffFile` objects |
| `src/controlgate/catalog.py` | Loads the NIST catalog; `GATE_CONTROL_MAP` maps gates to control IDs |
| `src/controlgate/catalog_downloader.py` | Downloads the catalog from the NCSB repository |
| `src/controlgate/config.py` | `.controlgate.yml` loading and defaults |
| `src/controlgate/models.py` | `Control`, `DiffFile`, `Finding`, `Verdict` |
| `src/controlgate/reporters/` | JSON, Markdown and SARIF reporters |
| `src/controlgate/init_command.py` | `controlgate init` and the files it generates |
| `hooks/` | The example GitHub Actions workflow and the `bump-version` hook |
| `skills/` | Instructions for AI coding agents |
| `docs/gates/` | Design and implementation notes for each gate |
| `schemas/verdict_schema.json` | JSON schema for the verdict |

## Adding a gate

1. Add `src/controlgate/gates/<name>_gate.py` with a class that subclasses
   `BaseGate` and sets `name`, `gate_id` and `mapped_control_ids`. Its
   `scan()` walks `diff_file.all_added_lines` and builds findings with
   `self._make_finding(...)`, which fills in the control's name, severity
   and non-negotiable flag from the catalog.
2. Every finding needs a control ID from `mapped_control_ids`, a one-line
   description, the offending line as evidence, and a remediation a person
   or an agent can act on.
3. Add the class to `ALL_GATES` and `__all__` in `gates/__init__.py`, and its
   control IDs to `GATE_CONTROL_MAP` in `catalog.py`.
4. Add the `gate_id` to the `gates` defaults in `config.py` and to the
   templates in `init_command.py`.
5. Add `tests/test_gates/test_<name>_gate.py` with positive and negative
   cases, document the gate in the README table and in `docs/gates/`, and
   add a vulnerable example to the test suite repository.

Findings are only reported when the control is in the selected baseline, so
check that the controls you map are in the baselines you expect. When a
pattern can't tell a real problem from a harmless one, prefer a narrower
pattern, or no finding, over a confident false positive.

## Pull requests

- Keep each PR to one change; small PRs get reviewed faster.
- Use the commit message style in the history: `type: summary`, for example
  `fix: scope bump-version hook to pre-commit stage only`. Types in use:
  `feat`, `fix`, `test`, `docs`, `style`, `chore`.
- Bump the version in `pyproject.toml` and add an entry to
  [CHANGELOG.md](CHANGELOG.md). A new version on `main` is published to PyPI
  and tagged by CI.
- CI must pass.
- Update README.md when you change behaviour a user can see.

## Security

Please don't report security problems in a public issue. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/controlgate/security/advisories/new)
on the repository's Security tab instead. See [SECURITY.md](SECURITY.md) for
what to include and what's in scope.

## License

ControlGate is licensed under the [MIT License](LICENSE). By contributing,
you agree that your contributions are licensed under the same license.
