"""ControlGate CLI entry point.

Usage:
    controlgate scan [--config PATH] [--format json|markdown|sarif] [--baseline low|moderate|high|privacy|li-saas] [--gov]
    controlgate scan --diff-file PATH  # scan a saved diff file
    python -m controlgate scan [options]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

from controlgate.catalog import CatalogIndex
from controlgate.config import ControlGateConfig
from controlgate.diff_parser import parse_diff
from controlgate.engine import ControlGateEngine
from controlgate.init_command import init_command
from controlgate.models import Action, DiffFile, DiffHunk
from controlgate.reporters.json_reporter import JSONReporter
from controlgate.reporters.markdown_reporter import MarkdownReporter
from controlgate.reporters.sarif_reporter import SARIFReporter


def _get_diff(mode: str, target_branch: str = "main") -> str:
    """Get diff text from git.

    Args:
        mode: 'pre-commit' for staged changes, 'pr' for branch diff.
        target_branch: Target branch for PR mode diff.

    Returns:
        The unified diff text.
    """
    if mode == "pre-commit":
        cmd = ["git", "diff", "--cached", "--unified=3"]
    else:
        cmd = ["git", "diff", f"{target_branch}...HEAD", "--unified=3"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running git diff: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: git is not installed or not in PATH", file=sys.stderr)
        sys.exit(1)


def _get_full_files(root: Path, config: ControlGateConfig) -> list[DiffFile]:
    """Enumerate all project files for full-repo scan mode.

    Tries ``git ls-files`` first (respects .gitignore). Falls back to
    directory walk when not in a git repo.

    Args:
        root: Project root directory to scan.
        config: ControlGate config (for extension/skip_dir filters).

    Returns:
        List of DiffFile objects with all content as added_lines.
    """
    root = root.resolve()
    candidate_paths: list[Path] = []

    # 1. Try git ls-files (honors .gitignore automatically)
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=True,
            cwd=root,
        )
        candidate_paths = [root / p for p in result.stdout.strip().splitlines() if p.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back: walk directory
        candidate_paths = [p for p in root.rglob("*") if p.is_file()]

    diff_files: list[DiffFile] = []

    for abs_path in candidate_paths:
        try:
            rel_path = str(abs_path.relative_to(root))
        except ValueError:
            rel_path = str(abs_path)

        # Skip paths excluded by config glob patterns
        if config.is_path_excluded(rel_path):
            continue

        # Skip any path component matching a pattern in skip_dirs
        path_parts = Path(rel_path).parts
        if any(
            any(fnmatch(part, pattern) for pattern in config.full_scan_skip_dirs)
            for part in path_parts
        ):
            continue

        # Filter by extension allowlist (empty list = allow all)
        if config.full_scan_extensions and abs_path.suffix not in config.full_scan_extensions:
            continue

        # Skip binary files (null-byte heuristic)
        try:
            sample = abs_path.read_bytes()[:8192]
            if b"\x00" in sample:
                continue
        except (OSError, PermissionError):
            continue

        # Read text content
        try:
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        lines = content.splitlines()
        if not lines:
            continue

        hunk = DiffHunk(
            start_line=1,
            line_count=len(lines),
            added_lines=list(enumerate(lines, start=1)),
        )
        df = DiffFile(path=rel_path)
        df.hunks = [hunk]
        diff_files.append(df)

    return diff_files


def _resolve_catalog_path(config: ControlGateConfig) -> Path:
    """Resolve the catalog path, auto-downloading if needed.

    Search order:
    1. Bundled/cached catalog in the package data dir
    2. Explicit path from config
    3. Relative to current directory or git root
    4. Auto-download from GitHub (NCSB repository)
    """
    from controlgate.catalog_downloader import get_catalog_path

    # 1. Check bundled/cached catalog (auto-downloads if missing)
    try:
        return get_catalog_path()
    except ConnectionError:
        pass  # Fall through to config-based resolution

    # 2. Explicit config path (absolute)
    catalog_path = Path(config.catalog_path)
    if catalog_path.is_absolute() and catalog_path.exists():
        return catalog_path

    # 3. Relative to current directory
    if catalog_path.exists():
        return catalog_path

    # 4. Relative to git project root
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        project_root = Path(result.stdout.strip())
        resolved = project_root / catalog_path
        if resolved.exists():
            return resolved
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print(
        "Error: catalog file not found and download failed.\n"
        "Run 'controlgate update-catalog' or set 'catalog' in .controlgate.yml.",
        file=sys.stderr,
    )
    sys.exit(1)


def scan_command(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    # Load config
    config = ControlGateConfig.load(args.config)
    if args.baseline:
        config.baseline = args.baseline
    if args.gov:
        config.is_gov = True

    # Resolve and load catalog
    catalog_path = _resolve_catalog_path(config)
    catalog = CatalogIndex(catalog_path)
    print(f"📚 Loaded catalog: {catalog.count} controls", file=sys.stderr)

    # Get diff
    if args.mode == "full":
        scan_root = Path(getattr(args, "path", None) or ".").resolve()
        diff_files = _get_full_files(scan_root, config)
        if not diff_files:
            print("ℹ️  No files found to scan.", file=sys.stderr)
            return 0
        print(
            f"📄 Full scan: {len(diff_files)} file(s) in {scan_root}...",
            file=sys.stderr,
        )
    elif args.diff_file:
        diff_text = Path(args.diff_file).read_text(encoding="utf-8")
        if not diff_text.strip():
            print("ℹ️  No changes to scan.", file=sys.stderr)
            return 0
        diff_files = parse_diff(diff_text)
        print(f"📄 Scanning {len(diff_files)} changed file(s)...", file=sys.stderr)
    else:
        diff_text = _get_diff(args.mode, args.target_branch)
        if not diff_text.strip():
            print("ℹ️  No changes to scan.", file=sys.stderr)
            return 0
        diff_files = parse_diff(diff_text)
        print(f"📄 Scanning {len(diff_files)} changed file(s)...", file=sys.stderr)

    # Run engine
    engine = ControlGateEngine(config, catalog)
    verdict = engine.scan(diff_files)

    # Determine output format(s)
    formats = args.format if args.format else config.report_formats

    # Output reports
    for fmt in formats:
        if fmt == "json":
            json_reporter = JSONReporter()
            print(json_reporter.render(verdict))
        elif fmt == "markdown":
            md_reporter = MarkdownReporter()
            print(md_reporter.render(verdict))
        elif fmt == "sarif":
            sarif_reporter = SARIFReporter()
            print(sarif_reporter.render(verdict))

    # Write to output dir if configured
    if args.output_dir or config.output_dir:
        output_dir = args.output_dir or config.output_dir
        for fmt in formats:
            if fmt == "json":
                JSONReporter().write(verdict, f"{output_dir}/verdict.json")
            elif fmt == "markdown":
                MarkdownReporter().write(verdict, f"{output_dir}/verdict.md")
            elif fmt == "sarif":
                SARIFReporter().write(verdict, f"{output_dir}/verdict.sarif")
        print(f"📁 Reports written to {output_dir}/", file=sys.stderr)

    # Print summary to stderr
    emoji = {"BLOCK": "🚫", "WARN": "⚠️", "PASS": "✅"}.get(verdict.verdict, "❓")
    print(
        f"\n{emoji} Verdict: {verdict.verdict} — {verdict.summary}",
        file=sys.stderr,
    )

    # Exit code
    if verdict.verdict == Action.BLOCK.value:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="controlgate",
        description="ControlGate — NIST RMF Cloud Security Hardening Compliance Gate",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan code changes for security compliance")
    scan_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to .controlgate.yml config file",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        nargs="+",
        choices=["json", "markdown", "sarif"],
        default=None,
        help="Output format(s)",
    )
    scan_parser.add_argument(
        "--baseline",
        type=str,
        choices=["low", "moderate", "high", "privacy", "li-saas"],
        default=None,
        help="Target NIST/FedRAMP baseline level",
    )
    scan_parser.add_argument(
        "--gov",
        action="store_true",
        help="Evaluate against FedRAMP baselines instead of standard NIST",
    )
    scan_parser.add_argument(
        "--mode",
        type=str,
        choices=["pre-commit", "pr", "full"],
        default="pre-commit",
        help="Scan mode: pre-commit (staged), pr (branch diff), or full (entire repo)",
    )
    scan_parser.add_argument(
        "--target-branch",
        type=str,
        default="main",
        help="Target branch for PR mode diff (default: main)",
    )
    scan_parser.add_argument(
        "--diff-file",
        type=str,
        default=None,
        help="Path to a saved diff file to scan (instead of git diff)",
    )
    scan_parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write report files to",
    )
    scan_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Root directory for full scan mode (default: current directory)",
    )

    # update-catalog subcommand
    subparsers.add_parser(
        "update-catalog",
        help="Download the latest NIST catalog from NCSB",
    )

    # catalog-info subcommand
    subparsers.add_parser(
        "catalog-info",
        help="Show information about the current catalog",
    )

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Bootstrap ControlGate config files for this project",
    )
    init_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Target directory to initialize (default: current directory)",
    )
    init_parser.add_argument(
        "--baseline",
        type=str,
        choices=["low", "moderate", "high", "privacy", "li-saas"],
        default=None,
        help="Pre-select the NIST/FedRAMP baseline level",
    )
    init_parser.add_argument(
        "--no-docs",
        action="store_true",
        default=False,
        help="Skip generating CONTROLGATE.md",
    )

    return parser


def update_catalog_command() -> int:
    """Download the latest catalog from GitHub."""
    from controlgate.catalog_downloader import download_catalog

    try:
        path = download_catalog()
        print(f"📦 Catalog saved to: {path}", file=sys.stderr)
        return 0
    except ConnectionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1


def catalog_info_command() -> int:
    """Show info about the current catalog."""
    from controlgate.catalog_downloader import catalog_info, get_catalog_path

    try:
        path = get_catalog_path()
    except ConnectionError:
        print("❌ No catalog available. Run 'controlgate update-catalog'.", file=sys.stderr)
        return 1

    info = catalog_info(path)
    print("📚 NIST Catalog Info:")
    print(f"   Project:    {info['project']}")
    print(f"   Version:    {info['version']}")
    print(f"   Framework:  {info['framework']}")
    print(f"   Controls:   {info['control_count']}")
    print(f"   Generated:  {info['generated_at']}")
    print(f"   Path:       {info['path']}")
    return 0


def main() -> None:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        exit_code = scan_command(args)
        sys.exit(exit_code)
    elif args.command == "update-catalog":
        sys.exit(update_catalog_command())
    elif args.command == "catalog-info":
        sys.exit(catalog_info_command())
    elif args.command == "init":
        sys.exit(init_command(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
