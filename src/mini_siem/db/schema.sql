-- Mini SIEM SQLite WAL Schema

PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

-- 1. Ingested SIEM Events
CREATE TABLE IF NOT EXISTS siem_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    host TEXT NOT NULL,
    sourcetype TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT,
    status TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    user TEXT,
    process TEXT,
    uri_path TEXT,
    raw TEXT NOT NULL,
    fields_json TEXT NOT NULL DEFAULT '{}',
    is_ioc_hit INTEGER NOT NULL DEFAULT 0,
    ioc_tags_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON siem_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_host ON siem_events (host);
CREATE INDEX IF NOT EXISTS idx_events_sourcetype ON siem_events (sourcetype);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON siem_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON siem_events (user);
CREATE INDEX IF NOT EXISTS idx_events_ioc_hit ON siem_events (is_ioc_hit);

-- 2. Detection Rules
CREATE TABLE IF NOT EXISTS siem_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    rule_type TEXT NOT NULL,
    urgency TEXT NOT NULL,
    field_matches_json TEXT NOT NULL DEFAULT '{}',
    regex_pattern TEXT,
    threshold_count INTEGER NOT NULL DEFAULT 5,
    time_window_seconds INTEGER NOT NULL DEFAULT 60,
    group_by_field TEXT DEFAULT 'src_ip',
    mitre_attack_id TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- 3. Security Alerts
CREATE TABLE IF NOT EXISTS siem_alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT NOT NULL,
    urgency TEXT NOT NULL,
    description TEXT,
    target_host TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    user TEXT,
    trigger_count INTEGER NOT NULL DEFAULT 1,
    mitre_attack_id TEXT,
    sample_events_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON siem_alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_urgency ON siem_alerts (urgency);

-- 4. Threat Intel IOC Feeds
CREATE TABLE IF NOT EXISTS threat_feed_items (
    indicator TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    threat_actor TEXT,
    description TEXT,
    confidence INTEGER NOT NULL DEFAULT 80,
    source TEXT NOT NULL DEFAULT 'local_feed',
    created_at TEXT NOT NULL
);
