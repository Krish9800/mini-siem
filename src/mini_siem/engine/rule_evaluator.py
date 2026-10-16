"""Real-Time Correlation & Detection Rule Engine for Mini SIEM.

Evaluates streaming or batched events against:
1. Match Rules: Single-event field matching or regex pattern matches
2. Threshold Rules: Burst event detection within sliding time windows (e.g. >5 failures in 60s)
3. Generates structured `SIEMAlert` instances mapped to MITRE ATT&CK techniques
"""

import re
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from mini_siem.engine.suppression import AlertSuppressionEngine
from mini_siem.models.enums import RuleType
from mini_siem.models.schemas import SIEMAlert, SIEMLogEvent, SIEMRule


class RuleEvaluator:
    """Evaluates SIEMLogEvents against a registered collection of SIEMRules."""

    def __init__(
        self,
        rules: list[SIEMRule] | None = None,
        suppression_engine: AlertSuppressionEngine | None = None,
    ) -> None:
        self.rules: dict[str, SIEMRule] = {}
        self.suppression_engine = suppression_engine
        # Precompiled regexes: rule_id -> Pattern
        self._compiled_regexes: dict[str, re.Pattern[str]] = {}

        # Sliding window state for threshold rules:
        # rule_id -> group_key -> deque[(event_id, timestamp)]
        self._threshold_windows: dict[str, dict[str, deque[tuple[str, datetime]]]] = {}

        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule: SIEMRule) -> None:
        """Register or update a detection rule."""
        self.rules[rule.rule_id] = rule
        if rule.regex_pattern:
            self._compiled_regexes[rule.rule_id] = re.compile(rule.regex_pattern, re.IGNORECASE)
        if rule.rule_type == RuleType.THRESHOLD:
            self._threshold_windows[rule.rule_id] = {}

    def remove_rule(self, rule_id: str) -> None:
        """Unregister a detection rule."""
        self.rules.pop(rule_id, None)
        self._compiled_regexes.pop(rule_id, None)
        self._threshold_windows.pop(rule_id, None)

    def evaluate_event(self, event: SIEMLogEvent) -> list[SIEMAlert]:
        """Evaluate a single log event against all active rules."""
        alerts: list[SIEMAlert] = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if rule.rule_type == RuleType.MATCH:
                if self._matches_criteria(rule, event):
                    alerts.append(self._create_match_alert(rule, event))

            elif rule.rule_type == RuleType.THRESHOLD:
                if self._matches_criteria(rule, event):
                    alert = self._evaluate_threshold(rule, event)
                    if alert:
                        alerts.append(alert)

        if self.suppression_engine:
            filtered: list[SIEMAlert] = []
            for a in alerts:
                suppressed, _ = self.suppression_engine.process(a)
                if not suppressed:
                    filtered.append(a)
            return filtered

        return alerts


    def evaluate_batch(self, events: list[SIEMLogEvent]) -> list[SIEMAlert]:
        """Evaluate a batch of log events sequentially."""
        all_alerts: list[SIEMAlert] = []
        for ev in events:
            all_alerts.extend(self.evaluate_event(ev))
        return all_alerts

    def _matches_criteria(self, rule: SIEMRule, event: SIEMLogEvent) -> bool:
        """Check if event satisfies rule field criteria and regex."""
        # 1. Field matching
        for field, target_val in rule.field_matches.items():
            actual: Any = getattr(event, field, None)
            if actual is None and field in event.fields:
                actual = event.fields[field]
            if actual is None:
                return False
            if str(actual).lower() != target_val.lower():
                return False

        # 2. Regex matching
        if rule.rule_id in self._compiled_regexes:
            pat = self._compiled_regexes[rule.rule_id]
            if not pat.search(event.raw):
                return False

        return True

    def _evaluate_threshold(self, rule: SIEMRule, event: SIEMLogEvent) -> SIEMAlert | None:
        """Record event in sliding window and trigger alert if threshold exceeded."""
        group_fld = rule.group_by_field or "src_ip"
        group_val: Any = getattr(event, group_fld, None)
        if group_val is None and group_fld in event.fields:
            group_val = event.fields[group_fld]

        group_key = str(group_val) if group_val is not None else "global"

        rule_windows = self._threshold_windows.setdefault(rule.rule_id, {})
        window = rule_windows.setdefault(group_key, deque())

        # Evict expired events outside the sliding window
        window_start = event.timestamp - timedelta(seconds=rule.time_window_seconds)
        while window and window[0][1] < window_start:
            window.popleft()

        # Add current event
        window.append((event.event_id, event.timestamp))

        # Check threshold trigger
        if len(window) >= rule.threshold_count:
            sample_ids = [e_id for e_id, _ in window]
            trigger_count = len(window)
            # Reset window to prevent duplicate continuous alerts for same burst
            window.clear()

            return SIEMAlert(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                urgency=rule.urgency,
                description=(
                    f"Threshold breached: {trigger_count} matching events for "
                    f"{group_fld}='{group_key}' within {rule.time_window_seconds}s"
                ),
                target_host=event.host,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                user=event.user,
                trigger_count=trigger_count,
                mitre_attack_id=rule.mitre_attack_id,
                sample_events=sample_ids,
            )

        return None

    def _create_match_alert(self, rule: SIEMRule, event: SIEMLogEvent) -> SIEMAlert:
        """Create an alert for a single match rule."""
        return SIEMAlert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            urgency=rule.urgency,
            description=f"Rule '{rule.name}' matched event on host {event.host}",
            target_host=event.host,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            user=event.user,
            trigger_count=1,
            mitre_attack_id=rule.mitre_attack_id,
            sample_events=[event.event_id],
        )
