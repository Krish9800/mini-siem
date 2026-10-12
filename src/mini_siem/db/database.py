"""SQLite WAL Persistence Repository for Mini SIEM.

Manages relational storage with:
- `PRAGMA journal_mode=WAL;`
- Parameterized SQL execution
- Transactional context management
- CRUD operations for events, rules, alerts, and threat feeds
"""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from mini_siem.models.enums import AlertUrgency, EventSeverity, IOCType, RuleType, SourceType
from mini_siem.models.schemas import SIEMAlert, SIEMLogEvent, SIEMRule, ThreatFeedItem


class Database:
    """Thread-safe SQLite WAL repository."""

    def __init__(self, db_path: Path | str, schema_file: Path | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._schema_file = schema_file or (Path(__file__).parent / "schema.sql")
        self._init_db()

    @contextmanager
    def session(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a transactional database connection with row factory."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize tables, pragmas, and indices from schema.sql."""
        schema_sql = self._schema_file.read_text(encoding="utf-8")
        with self.session() as conn:
            conn.executescript(schema_sql)

    # -------------------------------------------------------------
    # SIEM Events Operations
    # -------------------------------------------------------------
    def save_event(self, event: SIEMLogEvent) -> None:
        """Persist a single normalized SIEM event."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO siem_events (
                    event_id, timestamp, ingested_at, host, sourcetype, severity,
                    action, status, src_ip, dst_ip, src_port, dst_port, user,
                    process, uri_path, raw, fields_json, is_ioc_hit, ioc_tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.ingested_at.isoformat(),
                    event.host,
                    event.sourcetype.value,
                    event.severity.value,
                    event.action,
                    event.status,
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.user,
                    event.process,
                    event.uri_path,
                    event.raw,
                    json.dumps(event.fields),
                    1 if event.is_ioc_hit else 0,
                    json.dumps(event.ioc_tags),
                ),
            )

    def save_events_batch(self, events: list[SIEMLogEvent]) -> None:
        """Persist a batch of events in a single transaction."""
        with self.session() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO siem_events (
                    event_id, timestamp, ingested_at, host, sourcetype, severity,
                    action, status, src_ip, dst_ip, src_port, dst_port, user,
                    process, uri_path, raw, fields_json, is_ioc_hit, ioc_tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e.event_id,
                        e.timestamp.isoformat(),
                        e.ingested_at.isoformat(),
                        e.host,
                        e.sourcetype.value,
                        e.severity.value,
                        e.action,
                        e.status,
                        e.src_ip,
                        e.dst_ip,
                        e.src_port,
                        e.dst_port,
                        e.user,
                        e.process,
                        e.uri_path,
                        e.raw,
                        json.dumps(e.fields),
                        1 if e.is_ioc_hit else 0,
                        json.dumps(e.ioc_tags),
                    )
                    for e in events
                ],
            )

    def list_events(self, limit: int = 100, offset: int = 0) -> list[SIEMLogEvent]:
        """Retrieve recent events sorted by timestamp descending."""
        events: list[SIEMLogEvent] = []
        with self.session() as conn:
            rows = conn.execute(
                "SELECT * FROM siem_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            for r in rows:
                events.append(self._row_to_event(r))
        return events

    # -------------------------------------------------------------
    # SIEM Rules Operations
    # -------------------------------------------------------------
    def save_rule(self, rule: SIEMRule) -> None:
        """Persist a detection rule."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO siem_rules (
                    rule_id, name, description, rule_type, urgency,
                    field_matches_json, regex_pattern, threshold_count,
                    time_window_seconds, group_by_field, mitre_attack_id, enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.rule_id,
                    rule.name,
                    rule.description,
                    rule.rule_type.value,
                    rule.urgency.value,
                    json.dumps(rule.field_matches),
                    rule.regex_pattern,
                    rule.threshold_count,
                    rule.time_window_seconds,
                    rule.group_by_field,
                    rule.mitre_attack_id,
                    1 if rule.enabled else 0,
                ),
            )

    def list_rules(self) -> list[SIEMRule]:
        """List all registered detection rules."""
        rules: list[SIEMRule] = []
        with self.session() as conn:
            rows = conn.execute("SELECT * FROM siem_rules ORDER BY rule_id ASC").fetchall()
            for r in rows:
                rules.append(
                    SIEMRule(
                        rule_id=r["rule_id"],
                        name=r["name"],
                        description=r["description"] or "",
                        rule_type=RuleType(r["rule_type"]),
                        urgency=AlertUrgency(r["urgency"]),
                        field_matches=json.loads(r["field_matches_json"]),
                        regex_pattern=r["regex_pattern"],
                        threshold_count=r["threshold_count"],
                        time_window_seconds=r["time_window_seconds"],
                        group_by_field=r["group_by_field"],
                        mitre_attack_id=r["mitre_attack_id"],
                        enabled=bool(r["enabled"]),
                    )
                )
        return rules

    # -------------------------------------------------------------
    # SIEM Alerts Operations
    # -------------------------------------------------------------
    def save_alert(self, alert: SIEMAlert) -> None:
        """Persist a security alert."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO siem_alerts (
                    alert_id, timestamp, rule_id, rule_name, urgency,
                    description, target_host, src_ip, dst_ip, user,
                    trigger_count, mitre_attack_id, sample_events_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.rule_id,
                    alert.rule_name,
                    alert.urgency.value,
                    alert.description,
                    alert.target_host,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.user,
                    alert.trigger_count,
                    alert.mitre_attack_id,
                    json.dumps(alert.sample_events),
                ),
            )

    def list_alerts(self, limit: int = 100) -> list[SIEMAlert]:
        """List alerts sorted by timestamp descending."""
        alerts: list[SIEMAlert] = []
        with self.session() as conn:
            rows = conn.execute(
                "SELECT * FROM siem_alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            for r in rows:
                alerts.append(
                    SIEMAlert(
                        alert_id=r["alert_id"],
                        timestamp=datetime.fromisoformat(r["timestamp"]),
                        rule_id=r["rule_id"],
                        rule_name=r["rule_name"],
                        urgency=AlertUrgency(r["urgency"]),
                        description=r["description"] or "",
                        target_host=r["target_host"],
                        src_ip=r["src_ip"],
                        dst_ip=r["dst_ip"],
                        user=r["user"],
                        trigger_count=r["trigger_count"],
                        mitre_attack_id=r["mitre_attack_id"],
                        sample_events=json.loads(r["sample_events_json"]),
                    )
                )
        return alerts

    # -------------------------------------------------------------
    # Threat Feeds Operations
    # -------------------------------------------------------------
    def save_threat_feed_item(self, item: ThreatFeedItem) -> None:
        """Persist an IOC threat feed item."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_feed_items (
                    indicator, ioc_type, threat_actor, description,
                    confidence, source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.indicator,
                    item.ioc_type.value,
                    item.threat_actor,
                    item.description,
                    item.confidence,
                    item.source,
                    item.created_at.isoformat(),
                ),
            )

    def list_threat_feed_items(self) -> list[ThreatFeedItem]:
        """List all persisted threat intelligence items."""
        items: list[ThreatFeedItem] = []
        with self.session() as conn:
            rows = conn.execute("SELECT * FROM threat_feed_items ORDER BY indicator ASC").fetchall()
            for r in rows:
                items.append(
                    ThreatFeedItem(
                        indicator=r["indicator"],
                        ioc_type=IOCType(r["ioc_type"]),
                        threat_actor=r["threat_actor"],
                        description=r["description"] or "",
                        confidence=r["confidence"],
                        source=r["source"],
                        created_at=datetime.fromisoformat(r["created_at"]),
                    )
                )
        return items

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SIEMLogEvent:
        """Convert a database row into a SIEMLogEvent."""
        return SIEMLogEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
            host=row["host"],
            sourcetype=SourceType(row["sourcetype"]),
            severity=EventSeverity(row["severity"]),
            action=row["action"],
            status=row["status"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            user=row["user"],
            process=row["process"],
            uri_path=row["uri_path"],
            raw=row["raw"],
            fields=json.loads(row["fields_json"]),
            is_ioc_hit=bool(row["is_ioc_hit"]),
            ioc_tags=json.loads(row["ioc_tags_json"]),
        )
