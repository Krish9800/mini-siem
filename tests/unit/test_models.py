"""Unit tests for Mini SIEM domain models, enums, and schemas."""

from mini_siem.models.enums import AlertUrgency, EventSeverity, IOCType, RuleType, SourceType
from mini_siem.models.schemas import (
    QueryResult,
    SearchQuery,
    SIEMAlert,
    SIEMLogEvent,
    SIEMRule,
    ThreatFeedItem,
)


def test_enums_values() -> None:
    """Verify enumeration string representations."""
    assert EventSeverity.HIGH.value == "high"
    assert SourceType.FIREWALL.value == "firewall"
    assert AlertUrgency.CRITICAL.value == "critical"
    assert RuleType.THRESHOLD.value == "threshold"
    assert IOCType.IPV4.value == "ipv4"


def test_siem_log_event_creation() -> None:
    """Verify SIEMLogEvent model defaults and custom fields."""
    event = SIEMLogEvent(
        host="web-prod-01",
        sourcetype=SourceType.AUTH,
        severity=EventSeverity.HIGH,
        action="login",
        status="failure",
        src_ip="192.168.1.100",
        user="root",
        raw="Failed password for root from 192.168.1.100 port 22 ssh2",
    )

    assert event.event_id is not None
    assert event.host == "web-prod-01"
    assert event.action == "login"
    assert event.status == "failure"
    assert event.src_ip == "192.168.1.100"
    assert event.user == "root"
    assert event.is_ioc_hit is False
    assert len(event.ioc_tags) == 0


def test_threat_feed_item_frozen() -> None:
    """Verify ThreatFeedItem immutability and attributes."""
    item = ThreatFeedItem(
        indicator="198.51.100.23",
        ioc_type=IOCType.IPV4,
        threat_actor="APT29",
        description="Command and Control Node",
        confidence=95,
    )

    assert item.indicator == "198.51.100.23"
    assert item.threat_actor == "APT29"
    assert item.confidence == 95


def test_search_query_and_result() -> None:
    """Verify search query request and response model structure."""
    query = SearchQuery(
        raw_query="action=failure | count by user",
        limit=50,
        offset=10,
    )
    assert query.raw_query == "action=failure | count by user"
    assert query.limit == 50

    result = QueryResult(
        total_hits=2,
        execution_time_ms=1.45,
        events=[
            SIEMLogEvent(host="srv1", action="failure", user="admin"),
            SIEMLogEvent(host="srv2", action="failure", user="admin"),
        ],
        aggregations={"admin": 2},
    )
    assert result.total_hits == 2
    assert len(result.events) == 2
    assert result.aggregations["admin"] == 2


def test_siem_rule_and_alert_models() -> None:
    """Verify SIEMRule and SIEMAlert schemas."""
    rule = SIEMRule(
        name="SSH Brute Force",
        rule_type=RuleType.THRESHOLD,
        urgency=AlertUrgency.HIGH,
        field_matches={"action": "login", "status": "failure"},
        threshold_count=5,
        time_window_seconds=60,
        mitre_attack_id="T1110",
    )
    assert rule.name == "SSH Brute Force"
    assert rule.threshold_count == 5
    assert rule.mitre_attack_id == "T1110"

    alert = SIEMAlert(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        urgency=rule.urgency,
        description="Exceeded 5 login failures within 60 seconds",
        src_ip="192.168.1.100",
        trigger_count=6,
        mitre_attack_id="T1110",
        sample_events=["evt-1", "evt-2"],
    )
    assert alert.rule_name == "SSH Brute Force"
    assert alert.urgency == AlertUrgency.HIGH
    assert alert.trigger_count == 6
    assert len(alert.sample_events) == 2
