"""Unit tests for Mini SIEM foundation, versioning, and configuration."""

from pathlib import Path

import pytest

import mini_siem
from mini_siem.config.settings import SIEMSettings, get_settings


def test_siem_version() -> None:
    """Verify package version is semantic and non-empty."""
    assert mini_siem.__version__ == "0.1.0"


def test_default_siem_settings(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify default configuration attributes and properties."""
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    get_settings.cache_clear()
    settings = get_settings()

    assert settings.app_name == "Mini SIEM"
    assert settings.wal_mode is True
    assert settings.batch_buffer_size == 1000
    assert settings.burst_threshold_events == 5
    assert settings.effective_db_path.parent == temp_dir
    get_settings.cache_clear()


def test_custom_siem_settings(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variable overrides for custom settings."""
    custom_db = temp_dir / "custom.db"
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("SIEM_DATABASE_URL", str(custom_db))
    monkeypatch.setenv("SIEM_BATCH_BUFFER_SIZE", "500")
    monkeypatch.setenv("SIEM_HEC_TOKEN", "secret-token-123")
    monkeypatch.setenv("SIEM_CORRELATION_WINDOW_SECONDS", "120")

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.batch_buffer_size == 500
    assert settings.hec_token == "secret-token-123"
    assert settings.correlation_window_seconds == 120
    assert settings.effective_db_path == custom_db
    get_settings.cache_clear()


def test_effective_db_path_absolute(temp_dir: Path) -> None:
    """Verify absolute path resolution when database_url is absolute."""
    abs_path = temp_dir / "absolute.db"
    settings = SIEMSettings(database_url=str(abs_path))
    assert settings.effective_db_path == abs_path


def test_effective_db_path_sqlite_uri(temp_dir: Path) -> None:
    """Verify URI stripping when database_url begins with sqlite:///."""
    abs_path = temp_dir / "uri_test.db"
    settings = SIEMSettings(database_url=f"sqlite:///{abs_path}")
    assert settings.effective_db_path == abs_path
