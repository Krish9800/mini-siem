"""Unit tests for AlertSuppressionEngine and deduplication."""

from datetime import UTC, datetime, timedelta

from mini_siem.engine.rule_evaluator import RuleEvaluator
from mini_siem.engine.suppression import AlertSuppressionEngine
from mini_siem.models.enums import AlertUrgency, RuleType
from mini_siem.models.schemas import SIEMAlert, SIEMLogEvent, SIEMRule


def test_suppression_engine_initial_and_duplicate() -> None:
    """Verify first alert is emitted and immediate duplicates are suppressed."""
    engine = AlertSuppressionEngine(cooldown_seconds=60)
    now = datetime.now(UTC)

    alert = SIEMAlert(
        rule_id="RULE-001",
        rule_name="Brute Force",
        urgency=AlertUrgency.HIGH,
        src_ip="192.168.1.100",
        target_host="web01",
        user="admin",
        timestamp=now,
    )

    # First occurrence -> not suppressed
    suppressed, record = engine.process(alert)
    assert not suppressed
    assert record.alert_count == 1
    assert record.suppressed_count == 0
    assert engine.active_suppression_count == 1

    # Second occurrence at now + 10s -> suppressed
    suppressed2, record2 = engine.process(alert, current_time=now + timedelta(seconds=10))
    assert suppressed2
    assert record2.alert_count == 2
    assert record2.suppressed_count == 1

    # Third occurrence at now + 30s -> suppressed
    suppressed3, record3 = engine.process(alert, current_time=now + timedelta(seconds=30))
    assert suppressed3
    assert record3.alert_count == 3
    assert record3.suppressed_count == 2


def test_suppression_engine_cooldown_expiration() -> None:
    """Verify alert is permitted again after cooldown period elapses."""
    engine = AlertSuppressionEngine(cooldown_seconds=60)
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    alert = SIEMAlert(
        rule_id="RULE-002",
        rule_name="Port Scan",
        urgency=AlertUrgency.MEDIUM,
        src_ip="10.0.0.5",
        timestamp=t0,
    )

    # t0: permitted
    suppressed, _ = engine.process(alert, current_time=t0)
    assert not suppressed

    # t0 + 70s (> 60s cooldown): window resets, alert permitted again
    t_after = t0 + timedelta(seconds=70)
    suppressed_after, record_after = engine.process(alert, current_time=t_after)
    assert not suppressed_after
    assert record_after.alert_count == 1
    assert record_after.suppressed_count == 0


def test_suppression_engine_cleanup_and_clear() -> None:
    """Verify expired records cleanup and full clear."""
    engine = AlertSuppressionEngine(cooldown_seconds=30)
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    alert1 = SIEMAlert(rule_id="R1", rule_name="Test 1", urgency=AlertUrgency.LOW, src_ip="1.1.1.1")
    alert2 = SIEMAlert(rule_id="R2", rule_name="Test 2", urgency=AlertUrgency.LOW, src_ip="2.2.2.2")

    engine.process(alert1, current_time=t0)
    engine.process(alert2, current_time=t0 + timedelta(seconds=20))
    assert engine.active_suppression_count == 2

    # Cleanup at t0 + 35s -> alert1 expired (35 > 30), alert2 still active (15 <= 30)
    purged = engine.cleanup_expired(current_time=t0 + timedelta(seconds=35))
    assert purged == 1
    assert engine.active_suppression_count == 1

    engine.clear()
    assert engine.active_suppression_count == 0


def test_rule_evaluator_with_suppression() -> None:
    """Verify RuleEvaluator integrates with AlertSuppressionEngine to throttle repeat alerts."""
    rule = SIEMRule(
        name="Repeated Auth Failure",
        rule_type=RuleType.MATCH,
        urgency=AlertUrgency.HIGH,
        field_matches={"action": "auth", "status": "failure"},
    )
    suppression = AlertSuppressionEngine(cooldown_seconds=120)
    evaluator = RuleEvaluator([rule], suppression_engine=suppression)

    ev1 = SIEMLogEvent(action="auth", status="failure", host="app1", src_ip="10.10.10.1")
    ev2 = SIEMLogEvent(action="auth", status="failure", host="app1", src_ip="10.10.10.1")

    # First match generates an alert
    alerts1 = evaluator.evaluate_event(ev1)
    assert len(alerts1) == 1

    # Second identical event produces alert that gets suppressed
    alerts2 = evaluator.evaluate_event(ev2)
    assert len(alerts2) == 0
