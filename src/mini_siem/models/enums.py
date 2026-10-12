"""Enumerations for Mini SIEM domain models."""

from enum import StrEnum


class EventSeverity(StrEnum):
    """Normalized security log event severity level."""

    DEBUG = "debug"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(StrEnum):
    """Categorization of incoming log data streams."""

    HEC = "hec"
    SYSLOG = "syslog"
    AUTH = "auth"
    FIREWALL = "firewall"
    WEB_ACCESS = "web_access"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    CUSTOM = "custom"


class AlertUrgency(StrEnum):
    """Urgency / prioritization classification for triggered SIEM alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(StrEnum):
    """Detection rule evaluation model."""

    MATCH = "match"  # Single-event pattern/field match
    THRESHOLD = "threshold"  # N events matching criteria within time window T
    SEQUENCE = "sequence"  # Ordered sequence of multi-stage events


class IOCType(StrEnum):
    """Indicator of Compromise (IOC) artifact type."""

    IPV4 = "ipv4"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "sha256"
