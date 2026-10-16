"""Alert Suppression and Deduplication Engine for Mini SIEM.

Prevents alert fatigue by deduplicating and throttling repeated alerts
within sliding cooldown windows based on configurable fingerprint keys.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from mini_siem.models.schemas import SIEMAlert


@dataclass
class SuppressionRecord:
    """State for an active alert suppression window."""

    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int = 1
    suppressed_count: int = 0
    sample_alert: SIEMAlert | None = None


class AlertSuppressionEngine:
    """Manages alert deduplication, cooldown throttling, and suppression."""

    def __init__(self, cooldown_seconds: int = 300) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._active_records: dict[str, SuppressionRecord] = {}

    def compute_fingerprint(self, alert: SIEMAlert) -> str:
        """Generate a deterministic deduplication hash/fingerprint for an alert."""
        rule_part = alert.rule_id or alert.rule_name
        entity_parts = [
            f"host:{alert.target_host or '*'}",
            f"src:{alert.src_ip or '*'}",
            f"user:{alert.user or '*'}",
        ]
        return f"{rule_part}::" + "::".join(entity_parts)

    def process(
        self, alert: SIEMAlert, current_time: datetime | None = None
    ) -> tuple[bool, SuppressionRecord]:
        """Process an alert through suppression engine.

        Returns:
            tuple[bool, SuppressionRecord]:
                - bool: True if the alert is SUPPRESSED (should NOT be emitted again)
                - SuppressionRecord: Active suppression state for this alert
        """
        now = current_time or alert.timestamp
        fp = self.compute_fingerprint(alert)

        record = self._active_records.get(fp)
        if record is None:
            # First time seeing this alert
            new_record = SuppressionRecord(
                fingerprint=fp,
                first_seen=now,
                last_seen=now,
                alert_count=1,
                suppressed_count=0,
                sample_alert=alert,
            )
            self._active_records[fp] = new_record
            return False, new_record

        # Check if cooldown has expired
        elapsed = (now - record.last_seen).total_seconds()
        if elapsed > self.cooldown_seconds:
            # Window expired, reset window and allow alert through
            record.first_seen = now
            record.last_seen = now
            record.alert_count = 1
            record.suppressed_count = 0
            record.sample_alert = alert
            return False, record

        # Within cooldown window -> suppress duplicate alert
        record.last_seen = now
        record.alert_count += 1
        record.suppressed_count += 1
        return True, record

    def cleanup_expired(self, current_time: datetime | None = None) -> int:
        """Purge records whose cooldown has elapsed."""
        now = current_time or datetime.now(UTC)
        to_delete: list[str] = []
        for fp, rec in self._active_records.items():
            if (now - rec.last_seen).total_seconds() > self.cooldown_seconds:
                to_delete.append(fp)
        for fp in to_delete:
            del self._active_records[fp]
        return len(to_delete)

    def clear(self) -> None:
        """Clear all active suppression state."""
        self._active_records.clear()

    @property
    def active_suppression_count(self) -> int:
        """Number of active tracked suppression keys."""
        return len(self._active_records)
