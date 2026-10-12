"""Pydantic domain schemas for Mini SIEM events, queries, rules, and alerts."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mini_siem.models.enums import AlertUrgency, EventSeverity, IOCType, RuleType, SourceType


class ThreatFeedItem(BaseModel):
    """Threat intelligence indicator of compromise record."""

    model_config = ConfigDict(extra="allow", frozen=True)

    indicator: str = Field(..., description="Indicator value, e.g. IP address or domain")
    ioc_type: IOCType = Field(..., description="Type of indicator (ipv4, domain, etc.)")
    threat_actor: str | None = Field(default=None, description="Associated threat actor or group")
    description: str = Field(default="", description="Contextual description of the threat")
    confidence: int = Field(default=80, ge=0, le=100, description="Confidence score (0-100)")
    source: str = Field(default="local_feed", description="Threat intel feed name/source")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Feed entry creation timestamp",
    )


class SIEMLogEvent(BaseModel):
    """Canonical normalized SIEM log event schema."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the log event",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Event generation timestamp in UTC",
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="SIEM ingestion timestamp in UTC",
    )
    host: str = Field(default="unknown-host", description="Originating host or agent name")
    sourcetype: SourceType = Field(default=SourceType.CUSTOM, description="Log category")
    severity: EventSeverity = Field(
        default=EventSeverity.INFORMATIONAL, description="Event severity"
    )

    # Normalized security context fields
    action: str | None = Field(default=None, description="Event action (login, block, drop, allow)")
    status: str | None = Field(default=None, description="Action outcome (success, failure, error)")
    src_ip: str | None = Field(default=None, description="Source IP address")
    dst_ip: str | None = Field(default=None, description="Destination IP address")
    src_port: int | None = Field(default=None, ge=0, le=65535, description="Source transport port")
    dst_port: int | None = Field(
        default=None, ge=0, le=65535, description="Destination transport port"
    )
    user: str | None = Field(default=None, description="Account name or user identity")
    process: str | None = Field(default=None, description="Associated process or command name")
    uri_path: str | None = Field(default=None, description="HTTP request URI path if applicable")

    # Raw payload and unstructured metadata
    raw: str = Field(default="", description="Original raw unparsed log message")
    fields: dict[str, Any] = Field(
        default_factory=dict, description="Extracted key-value attributes"
    )

    # Threat Intelligence Enrichment tags
    is_ioc_hit: bool = Field(default=False, description="Flag indicating threat feed match")
    ioc_tags: list[str] = Field(default_factory=list, description="Matched threat actor or tags")


class SearchQuery(BaseModel):
    """SIEM query search parameters for SPL/Lucene-style queries."""

    model_config = ConfigDict(extra="ignore")

    raw_query: str = Field(
        default="*",
        description="Query string, e.g. 'action=failure src_ip=192.168.1.10 | count by user'",
    )
    start_time: datetime | None = Field(
        default=None,
        description="Optional filter for earliest event timestamp",
    )
    end_time: datetime | None = Field(
        default=None,
        description="Optional filter for latest event timestamp",
    )
    limit: int = Field(default=100, ge=1, le=10000, description="Maximum event records to return")
    offset: int = Field(default=0, ge=0, description="Offset for pagination")


class QueryResult(BaseModel):
    """Result response payload for SIEM queries."""

    model_config = ConfigDict(extra="allow")

    total_hits: int = Field(..., description="Total matching log events")
    execution_time_ms: float = Field(..., description="Query execution duration in milliseconds")
    events: list[SIEMLogEvent] = Field(
        default_factory=list, description="List of matching normalized events"
    )
    aggregations: dict[str, int] = Field(
        default_factory=dict,
        description="Aggregated statistics if pipe aggregation specified (e.g. {'admin': 15})",
    )


class SIEMRule(BaseModel):
    """SIEM real-time correlation and detection rule definition."""

    model_config = ConfigDict(extra="allow")

    rule_id: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:8],
        description="Unique rule identifier",
    )
    name: str = Field(..., description="Human-readable rule title")
    description: str = Field(default="", description="Detailed detection rationale")
    rule_type: RuleType = Field(default=RuleType.MATCH, description="Rule evaluation mechanism")
    urgency: AlertUrgency = Field(default=AlertUrgency.MEDIUM, description="Alert urgency")

    # Matching criteria
    field_matches: dict[str, str] = Field(
        default_factory=dict,
        description="Required key-value pairs (e.g. {'action': 'login', 'status': 'failure'})",
    )
    regex_pattern: str | None = Field(
        default=None,
        description="Regex pattern to test against the raw message",
    )

    # Threshold settings
    threshold_count: int = Field(
        default=5,
        ge=1,
        description="Minimum event occurrences required within time window",
    )
    time_window_seconds: int = Field(
        default=60,
        ge=5,
        description="Sliding evaluation window duration in seconds",
    )
    group_by_field: str | None = Field(
        default="src_ip",
        description="Field used to partition threshold burst counters (e.g. src_ip, user)",
    )

    mitre_attack_id: str | None = Field(
        default=None,
        description="Mapped MITRE ATT&CK technique (e.g. T1110 for Brute Force)",
    )
    enabled: bool = Field(default=True, description="Rule activation toggle")


class SIEMAlert(BaseModel):
    """Incident alert triggered by correlation rule or threat feed hit."""

    model_config = ConfigDict(extra="allow")

    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique alert identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Alert creation timestamp in UTC",
    )
    rule_id: str | None = Field(default=None, description="Associated rule ID")
    rule_name: str = Field(..., description="Triggered rule name or alert summary")
    urgency: AlertUrgency = Field(default=AlertUrgency.MEDIUM, description="Alert urgency")
    description: str = Field(default="", description="Contextual incident details")

    # Entity identifiers
    target_host: str | None = Field(default=None, description="Impacted host")
    src_ip: str | None = Field(default=None, description="Originating source IP")
    dst_ip: str | None = Field(default=None, description="Target destination IP")
    user: str | None = Field(default=None, description="Compromised or acting username")

    trigger_count: int = Field(default=1, description="Number of correlated events")
    mitre_attack_id: str | None = Field(default=None, description="MITRE ATT&CK technique code")
    sample_events: list[str] = Field(
        default_factory=list,
        description="List of sample event IDs that triggered this alert",
    )
