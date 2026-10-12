"""Configuration settings for Mini SIEM."""

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SIEMSettings(BaseSettings):
    """Mini SIEM application settings and runtime environment configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SIEM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core system settings
    app_name: str = "Mini SIEM"
    environment: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Debug mode flag")
    log_level: str = Field(default="INFO", description="Logging verbosity")

    # Storage paths
    data_dir: Path = Field(
        default=Path("data"),
        description="Base directory for persistence and state",
    )
    database_url: str = Field(
        default="data/siem.db",
        description="SQLite database path or connection URL",
    )
    wal_mode: bool = Field(
        default=True,
        description="Enable Write-Ahead Logging mode for SQLite",
    )

    # Ingestion & Buffer settings
    batch_buffer_size: int = Field(
        default=1000,
        ge=10,
        le=50000,
        description="Maximum events held in async ingestion memory buffer",
    )
    hec_token: str | None = Field(
        default=None,
        description="Optional shared secret token for HTTP Event Collector (HEC)",
    )
    max_payload_bytes: int = Field(
        default=1_048_576,  # 1 MB
        description="Maximum accepted size per ingestion payload",
    )

    # Correlation & Detection settings
    correlation_window_seconds: int = Field(
        default=60,
        ge=5,
        le=3600,
        description="Sliding window duration for burst/threshold detection",
    )
    burst_threshold_events: int = Field(
        default=5,
        ge=2,
        le=1000,
        description="Default burst frequency threshold to raise an alert",
    )

    # Threat Feed Enrichment
    enable_threat_intel: bool = Field(
        default=True,
        description="Flag to toggle threat intelligence feed enrichment",
    )
    threat_intel_cache_ttl: int = Field(
        default=3600,
        description="Threat intel lookup cache TTL in seconds",
    )

    @property
    def effective_db_path(self) -> Path:
        """Resolve database path relative to data_dir if not absolute."""
        db_path_str = self.database_url
        if db_path_str.startswith("sqlite:///"):
            db_path_str = db_path_str[len("sqlite:///") :]

        p = Path(db_path_str)
        if p.is_absolute():
            return p
        return Path(self.data_dir) / p.name


@lru_cache(maxsize=1)
def get_settings() -> SIEMSettings:
    """Return cached SIEMSettings instance with directory creation."""
    settings = SIEMSettings()
    os.makedirs(settings.data_dir, exist_ok=True)
    return settings
