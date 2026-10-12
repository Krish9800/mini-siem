"""Pytest configuration and global test fixtures for Mini SIEM."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from mini_siem.config.settings import SIEMSettings, get_settings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary directory cleaned up after test execution."""
    with tempfile.TemporaryDirectory() as tmp_path:
        yield Path(tmp_path)


@pytest.fixture
def test_settings(
    temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[SIEMSettings, None, None]:
    """Provide isolated test settings with overridden paths and reset LRU cache."""
    db_file = temp_dir / "test_siem.db"
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("SIEM_DATABASE_URL", str(db_file))
    monkeypatch.setenv("SIEM_ENVIRONMENT", "testing")
    monkeypatch.setenv("SIEM_DEBUG", "true")

    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()
