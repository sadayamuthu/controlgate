"""Tests that the package version is defined once and used consistently."""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import controlgate
from controlgate.catalog_downloader import download_catalog

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_version_matches_pyproject():
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.MULTILINE)
    assert match is not None
    assert controlgate.__version__ == match.group(1)


def test_catalog_download_user_agent_uses_package_version(tmp_path):
    response = MagicMock()
    response.read.return_value = b'{"controls": []}'
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=response) as mock_open:
        download_catalog(target_dir=tmp_path)

    request = mock_open.call_args[0][0]
    assert request.get_header("User-agent") == f"ControlGate/{controlgate.__version__}"
