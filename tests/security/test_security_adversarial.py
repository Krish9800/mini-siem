"""Adversarial Security Testbed for Mini SIEM.

Verifies:
1. SQL injection immunity across event queries and database persistence.
2. Resilience against heavily corrupted or malformed log inputs (fuzzing).
3. Search Query parser resistance to malicious syntax and potential ReDoS inputs.
4. Threat intelligence spoofing and malformed IP/CIDR input safety.
"""

from pathlib import Path

import pytest

from mini_siem.db.database import Database
from mini_siem.ingestion.collector import LogNormalizer
from mini_siem.intel.threat_intel import ThreatIntelEngine
from mini_siem.models.enums import IOCType
from mini_siem.models.schemas import SIEMLogEvent, ThreatFeedItem
from mini_siem.search.query_engine import QueryEngine, QuerySyntaxError


def test_adversarial_sqli_safety(temp_dir: Path) -> None:
    """Verify database repository is immune to SQL injection payloads."""
    db_file = temp_dir / "sqli_test.db"
    db = Database(db_file)

    # Ingest event with malicious SQL payload
    malicious_event = SIEMLogEvent(
        host="srv-target'); DROP TABLE siem_events; --",
        action="login' OR '1'='1",
        user="admin' UNION SELECT 1, 2, 3 --",
        raw="Malicious raw line'); DELETE FROM siem_alerts; --",
    )
    db.save_event(malicious_event)

    events = db.list_events()
    assert len(events) == 1
    assert "DROP TABLE" in events[0].host

    # Verify table integrity
    with db.session() as conn:
        cnt = conn.execute("SELECT count(*) FROM siem_events").fetchone()[0]
        assert cnt == 1


def test_adversarial_corrupted_log_lines() -> None:
    """Verify normalizer handles null bytes, control characters, and truncated lines safely."""
    normalizer = LogNormalizer()

    fuzz_inputs = [
        "\x00\x00\x00\x01\xff\xfe",
        "{'invalid': json}",
        "<99999999999999999999999>1 Truncated",
        "127.0.0.1 - - [invalid time] truncated",
        "\r\n\t\x1b[31mTerminal Escape Sequence\x1b[0m",
    ]

    for inp in fuzz_inputs:
        ev = normalizer.normalize(inp)
        assert ev.raw == inp.strip()
        assert ev.event_id is not None


def test_adversarial_query_parser_malicious_syntax() -> None:
    """Verify QueryEngine handles deep nested quotes, invalid pipes, and weird tokens safely."""
    engine = QueryEngine()

    # Empty and wildcard
    criteria, _agg = engine.parse_query("*")
    assert len(criteria) == 0

    # Malicious SQL-like search string
    criteria_sql, _ = engine.parse_query("user=' OR 1=1 -- action='drop")
    assert len(criteria_sql) >= 1

    # Malformed pipe syntax safely raises QuerySyntaxError
    with pytest.raises(QuerySyntaxError):
        engine.parse_query("action=login | evil_function(password)")


def test_adversarial_threat_intel_malformed_inputs() -> None:
    """Verify ThreatIntelEngine safely handles malformed IP/CIDR indicators."""
    engine = ThreatIntelEngine()

    # Invalid CIDR shouldn't crash
    invalid_item = ThreatFeedItem(indicator="999.999.999.999/99", ioc_type=IOCType.CIDR)
    engine.add_item(invalid_item)
    assert len(engine.cidr_networks) == 0

    # Checking completely invalid IP string returns None
    assert engine.check_indicator("not-an-ip-nor-indicator") is None
