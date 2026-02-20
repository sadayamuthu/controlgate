"""Shared test fixtures for ControlGate tests."""

import pytest

from controlgate.catalog import CatalogIndex
from controlgate.catalog_downloader import get_catalog_path


@pytest.fixture
def catalog_path():
    """Get the catalog path, downloading if needed."""
    return get_catalog_path()


@pytest.fixture
def catalog(catalog_path):
    """Load the NIST catalog for testing."""
    return CatalogIndex(catalog_path)
