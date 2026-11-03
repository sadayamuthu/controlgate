# Security Policy

## Reporting a vulnerability

Please don't report security problems in a public issue, pull request or
discussion. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/controlgate/security/advisories/new)
on the repository's Security tab instead. Only the maintainer can see the
report.

Include what you can of:

- the output of `pip show controlgate` and `controlgate catalog-info`, your
  Python version and your OS
- how ControlGate was run: the CLI (`scan`, `init`, `update-catalog`), the
  pre-commit hook, or the GitHub Actions workflow
- steps to reproduce, ideally a small repository, diff file or script that
  builds one
- what happened and what you expected

You'll get a reply when the report has been read, and again when a fix is
ready. A fix ships as a patch release; the advisory names you unless you'd
rather it didn't.

## Supported versions

ControlGate is pre-1.0. Fixes land in the latest release only; please
upgrade before reporting.

## What counts

ControlGate scans code you may not trust, such as a pull request from a
fork. It reads that code as text and matches it against patterns; it never
runs or imports it. Anything that breaks one of the following is a security
issue:

- **Scanning only reads.** `controlgate scan` reads the diff from
  `git diff`, or in `--mode full` every tracked file (every file, outside a
  git repository), plus a saved diff (`--diff-file`) and `.controlgate.yml`.
  The only files it writes are its reports, under the configured output
  directory (`.controlgate/reports/` by default), and the catalog if it has
  to download it (see below). A diff, file name, branch name or
  `.controlgate.yml` that makes it run a command, pass options of an
  attacker's choosing to `git`, write anywhere else, or change the
  repository is in scope.
- **Pattern matching is safe.** Input that makes a gate hang or use memory
  far beyond the size of the input (for example, catastrophic regular
  expression backtracking) is in scope.
- **The catalog download.** On first use, and on `controlgate
  update-catalog`, ControlGate downloads the NIST catalog over HTTPS from the
  [NCSB repository](https://github.com/sadayamuthu/nist-cloud-security-baseline)
  and saves it in the package's `data/` directory. A way to make it fetch
  from another location, write the file anywhere else, or behave unsafely on
  a malformed catalog is in scope.
- **`controlgate init`.** It writes `.controlgate.yml`,
  `.pre-commit-config.yaml`, `CONTROLGATE.md` and, if you choose, a GitHub
  Actions, GitLab CI or Bitbucket Pipelines file into the target directory,
  and asks before overwriting any of them. It doesn't run `pre-commit
  install` itself. Writing outside the target directory, overwriting without
  asking, or generating a hook or workflow that does something other than run
  ControlGate is in scope.
- **The GitHub Actions workflow** (`hooks/github_action.yml`, and the one
  `controlgate init` generates). It runs on pull requests with
  `pull-requests: write` and `security-events: write`, posts the Markdown
  report as a pull request comment and uploads the SARIF report. Script
  injection through branch names, file names or finding text, or report
  content that can do more than display in the comment or in code scanning,
  is in scope.

A wrong verdict, such as a finding ControlGate missed or a false positive, is
a bug, not a vulnerability. Report it in a normal issue; see
[CONTRIBUTING.md](CONTRIBUTING.md).
