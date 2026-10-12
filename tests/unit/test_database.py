"""Unit tests for SQLite WAL persistence database repository."""

from pathlib import Path

from mini_siem.db.database import Database
from mini_siem.models.enums import AlertUrgency, IOCType, RuleType
from mini_siem.models.schemas import SIEMAlert, SIEMLogEvent, SIEMRule, ThreatFeedItem


def test_database_wal_initialization(temp_dir: Path) -> None:
    """Verify tables are created and journal mode is WAL."""
    db_file = temp_dir / "test.db"
    db = Database(db_file)

    with db.session() as conn:
        res = conn.execute("PRAGMA journal_mode;").fetchone()
        assert res[0].lower() == "wal"


def test_save_and_list_events(temp_dir: Path) -> None:
    """Verify persisting and querying events."""
    db_file = temp_dir / "events.db"
    db = Database(db_file)

    ev1 = SIEMLogEvent(host="host1", action="login", user="admin")
    ev2 = SIEMLogEvent(host="host2", action="query", user="analyst")

    db.save_event(ev1)
    db.save_events_batch([ev2])

    events = db.list_events()
    assert len(events) == 2
    users = {e.user for e in events}
    assert "admin" in users
    assert "analyst" in users


def test_save_and_list_rules(temp_dir: Path) -> None:
    """Verify rule persistence and retrieval."""
    db_file = temp_dir / "rules.db"
    db = Database(db_file)

    rule = SIEMRule(
        name="Brute Force Detection",
        rule_type=RuleType.THRESHOLD,
        urgency=AlertUrgency.HIGH,
        threshold_count=5,
        time_window_seconds=60,
        mitre_attack_id="T1110",
    )
    db.save_rule(rule)

    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0].name == "Brute Force Detection"
    assert rules[0].threshold_count == 5


def test_save_and_list_alerts(temp_dir: Path) -> None:
    """Verify alert persistence and retrieval."""
    db_file = temp_dir / "alerts.db"
    db = Database(db_file)

    alert = SIEMAlert(
        rule_name="Threat Intel C2 Hit",
        urgency=AlertUrgency.CRITICAL,
        src_ip="198.51.100.99",
        mitre_attack_id="T1071",
        sample_events=["evt-1"],
    )
    db.save_alert(alert)

    alerts = db.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Threat Intel C2 Hit"
    assert alerts[0].urgency == AlertUrgency.CRITICAL
    assert alerts[0].sample_events == ["evt-1"]


def test_save_and_list_threat_feeds(temp_dir: Path) -> None:
    """Verify threat intelligence feed items persistence."""
    db_file = temp_dir / "feeds.db"
    db = Database(db_file)

    item = ThreatFeedItem(
        indicator="malicious.xyz",
        ioc_type=IOCType.DOMAIN,
        threat_actor="Lazarus",
        confidence=90,
    )
    db.save_threat_feed_item(item)

    items = db.list_threat_feed_items()
    assert len(items) == 1
    assert items[0].indicator == "malicious.xyz"
    assert items[0].threat_actor == "Lazarus"
