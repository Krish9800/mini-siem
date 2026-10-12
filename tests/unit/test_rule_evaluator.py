"""Unit tests for rule evaluation engine."""

from datetime import UTC, datetime, timedelta

from mini_siem.engine.rule_evaluator import RuleEvaluator
from mini_siem.models.enums import AlertUrgency, RuleType
from mini_siem.models.schemas import SIEMLogEvent, SIEMRule


def test_rule_evaluator_match_rule() -> None:
    """Verify single-event match rule evaluation."""
    rule = SIEMRule(
        name="Unauthorized Sudo Command",
        rule_type=RuleType.MATCH,
        urgency=AlertUrgency.HIGH,
        field_matches={"action": "sudo", "status": "failure"},
        mitre_attack_id="T1548.003",
    )
    evaluator = RuleEvaluator([rule])

    # Non-matching event
    ev1 = SIEMLogEvent(action="sudo", status="success", host="srv1")
    alerts1 = evaluator.evaluate_event(ev1)
    assert len(alerts1) == 0

    # Matching event
    ev2 = SIEMLogEvent(action="sudo", status="failure", host="srv1", user="guest")
    alerts2 = evaluator.evaluate_event(ev2)
    assert len(alerts2) == 1
    assert alerts2[0].rule_name == "Unauthorized Sudo Command"
    assert alerts2[0].user == "guest"
    assert alerts2[0].mitre_attack_id == "T1548.003"


def test_rule_evaluator_threshold_burst() -> None:
    """Verify sliding-window burst threshold detection."""
    rule = SIEMRule(
        name="SSH Brute Force",
        rule_type=RuleType.THRESHOLD,
        urgency=AlertUrgency.CRITICAL,
        field_matches={"action": "login", "status": "failure"},
        threshold_count=3,
        time_window_seconds=30,
        group_by_field="src_ip",
        mitre_attack_id="T1110",
    )
    evaluator = RuleEvaluator([rule])

    now = datetime.now(UTC)
    events = [
        SIEMLogEvent(
            action="login",
            status="failure",
            src_ip="192.168.1.50",
            timestamp=now - timedelta(seconds=10),
        ),
        SIEMLogEvent(
            action="login",
            status="failure",
            src_ip="192.168.1.50",
            timestamp=now - timedelta(seconds=5),
        ),
        SIEMLogEvent(
            action="login",
            status="failure",
            src_ip="192.168.1.50",
            timestamp=now,
        ),
    ]

    alerts = evaluator.evaluate_batch(events)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "SSH Brute Force"
    assert alerts[0].trigger_count == 3
    assert alerts[0].src_ip == "192.168.1.50"


def test_rule_evaluator_regex_matching() -> None:
    """Verify regex pattern matching on raw messages."""
    rule = SIEMRule(
        name="SQL Injection Ingress",
        rule_type=RuleType.MATCH,
        urgency=AlertUrgency.HIGH,
        regex_pattern=r"UNION\s+SELECT|OR\s+'1'='1'",
        mitre_attack_id="T1190",
    )
    evaluator = RuleEvaluator([rule])

    ev_clean = SIEMLogEvent(raw="GET /products?id=42 HTTP/1.1")
    assert len(evaluator.evaluate_event(ev_clean)) == 0

    ev_attack = SIEMLogEvent(
        raw="GET /products?id=1' UNION SELECT username, password FROM users --"
    )
    alerts = evaluator.evaluate_event(ev_attack)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "SQL Injection Ingress"


def test_rule_evaluator_remove_and_disable() -> None:
    """Verify removing and disabling rules."""
    rule = SIEMRule(
        rule_id="rule-test-1",
        name="Test Rule",
        rule_type=RuleType.MATCH,
        field_matches={"action": "test"},
    )
    evaluator = RuleEvaluator([rule])

    ev = SIEMLogEvent(action="test")
    assert len(evaluator.evaluate_event(ev)) == 1

    # Disable rule
    rule.enabled = False
    assert len(evaluator.evaluate_event(ev)) == 0

    # Remove rule
    evaluator.remove_rule("rule-test-1")
    assert "rule-test-1" not in evaluator.rules
