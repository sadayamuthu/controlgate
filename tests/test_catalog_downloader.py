"""Tests for the catalog downloader."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from controlgate.catalog_downloader import (
    catalog_info,
    download_catalog,
    get_catalog_path,
)


class TestGetCatalogPath:
    def test_returns_existing_bundled_catalog(self):
        path = get_catalog_path()
        assert path.exists()
        assert "nist80053r5" in path.name

    def test_downloads_if_missing(self):
        with patch("controlgate.catalog_downloader._PACKAGE_DATA_DIR", Path("/nonexistent")), patch("controlgate.catalog_downloader.download_catalog") as mock_dl:
                mock_dl.return_value = Path("/downloaded/catalog.json")
                get_catalog_path()
                mock_dl.assert_called_once()


class TestDownloadCatalog:
    def test_successful_download(self):
        # Create a mock catalog JSON
        mock_catalog = json.dumps(
            {"project": "NCSB", "project_version": "0.1.0", "controls": [{"control_id": "AC-1"}]}
        ).encode()

        with tempfile.TemporaryDirectory() as tmpdir, patch("controlgate.catalog_downloader.urllib.request.urlopen") as mock_urlopen:
                mock_response = MagicMock()
                mock_response.read.return_value = mock_catalog
                mock_response.__enter__ = lambda s: s
                mock_response.__exit__ = MagicMock(return_value=False)
                mock_urlopen.return_value = mock_response

                path = download_catalog(Path(tmpdir))
                assert path.exists()
                data = json.loads(path.read_text())
                assert "controls" in data

    def test_network_error_raises(self):
        import urllib.error

        with tempfile.TemporaryDirectory() as tmpdir, patch("controlgate.catalog_downloader.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                with pytest.raises(ConnectionError, match="Failed to download"):
                    download_catalog(Path(tmpdir))

    def test_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("controlgate.catalog_downloader.urllib.request.urlopen") as mock_urlopen:
                mock_response = MagicMock()
                mock_response.read.return_value = b"not json"
                mock_response.__enter__ = lambda s: s
                mock_response.__exit__ = MagicMock(return_value=False)
                mock_urlopen.return_value = mock_response
                with pytest.raises(ConnectionError, match="not valid"):
                    download_catalog(Path(tmpdir))

    def test_missing_controls_key_raises(self):
        mock_data = json.dumps({"project": "test"}).encode()
        with tempfile.TemporaryDirectory() as tmpdir, patch("controlgate.catalog_downloader.urllib.request.urlopen") as mock_urlopen:
                mock_response = MagicMock()
                mock_response.read.return_value = mock_data
                mock_response.__enter__ = lambda s: s
                mock_response.__exit__ = MagicMock(return_value=False)
                mock_urlopen.return_value = mock_response
                with pytest.raises(ConnectionError, match="not valid"):
                    download_catalog(Path(tmpdir))


class TestCatalogInfo:
    def test_returns_metadata(self):
        info = catalog_info(get_catalog_path())
        assert info["project"] == "NIST Cloud Security Baseline (NCSB)"
        assert info["control_count"] == 1189
        assert "version" in info
        assert "framework" in info
        assert "generated_at" in info
        assert "path" in info
