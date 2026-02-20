"""Dynamic catalog downloader for ControlGate.

Downloads the latest NIST 800-53 R5 enriched catalog from the
NIST Cloud Security Baseline (NCSB) GitHub repository.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Source of truth for the enriched catalog
CATALOG_REPO = "sadayamuthu/nist-cloud-security-baseline"
CATALOG_BRANCH = "main"
CATALOG_PATH = "baseline/nist80053r5_full_catalog_enriched.json"
CATALOG_URL = f"https://raw.githubusercontent.com/{CATALOG_REPO}/{CATALOG_BRANCH}/{CATALOG_PATH}"

# Where to cache the downloaded catalog
_PACKAGE_DATA_DIR = Path(__file__).resolve().parent / "data"
_CATALOG_FILENAME = "nist80053r5_full_catalog_enriched.json"


def get_catalog_path() -> Path:
    """Get the path to the catalog, downloading if needed.

    Returns the path to the catalog JSON file. If no local copy exists,
    downloads the latest from GitHub automatically.
    """
    local_path = _PACKAGE_DATA_DIR / _CATALOG_FILENAME
    if local_path.exists():
        return local_path

    # Auto-download on first use
    print("📥 No local catalog found. Downloading latest from NCSB...", file=sys.stderr)
    return download_catalog()


def download_catalog(target_dir: Path | None = None) -> Path:
    """Download the latest enriched catalog from GitHub.

    Args:
        target_dir: Directory to save the catalog to.
                    Defaults to the package's data/ directory.

    Returns:
        Path to the downloaded catalog file.

    Raises:
        ConnectionError: If the download fails.
    """
    dest_dir = target_dir or _PACKAGE_DATA_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / _CATALOG_FILENAME

    try:
        print(f"📥 Downloading catalog from {CATALOG_URL}...", file=sys.stderr)
        req = urllib.request.Request(
            CATALOG_URL,
            headers={"User-Agent": "ControlGate/0.1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()

        # Validate it's valid JSON with the expected structure
        catalog = json.loads(data)
        if "controls" not in catalog:
            raise ValueError("Downloaded file is not a valid NCSB catalog (missing 'controls' key)")

        control_count = len(catalog.get("controls", []))

        # Write atomically (write to tmp then rename)
        tmp_path = dest_path.with_suffix(".tmp")
        tmp_path.write_bytes(data)
        tmp_path.rename(dest_path)

        print(
            f"✅ Catalog downloaded: {control_count} controls "
            f"(v{catalog.get('project_version', 'unknown')})",
            file=sys.stderr,
        )
        return dest_path

    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to download catalog from {CATALOG_URL}: {e}") from e
    except (json.JSONDecodeError, ValueError) as e:
        raise ConnectionError(f"Downloaded file is not valid: {e}") from e


def catalog_info(catalog_path: Path) -> dict:
    """Get metadata about a local catalog file."""
    with open(catalog_path, encoding="utf-8") as f:
        data = json.load(f)
    return {
        "path": str(catalog_path),
        "project": data.get("project", "unknown"),
        "version": data.get("project_version", "unknown"),
        "generated_at": data.get("generated_at_utc", "unknown"),
        "framework": data.get("framework", "unknown"),
        "control_count": len(data.get("controls", [])),
    }
