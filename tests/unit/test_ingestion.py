"""Unit tests for multi-protocol log collector and normalization engine."""

import pytest

from mini_siem.ingestion.collector import HECCollector, IngestionError, LogNormalizer
from mini_siem.models.enums import EventSeverity, SourceType


def test_normalizer_json_logs() -> None:
    """Verify parsing of structured JSON events."""
    normalizer = LogNormalizer()
    raw = (
        '{"host": "srv-db", "action": "login", "status": "failure", '
        '"src_ip": "10.0.0.99", "user": "postgres", "severity": "high"}'
    )
    event = normalizer.normalize(raw)

    assert event.host == "srv-db"
    assert event.action == "login"
    assert event.status == "failure"
    assert event.src_ip == "10.0.0.99"
    assert event.user == "postgres"
    assert event.severity == EventSeverity.HIGH


def test_normalizer_apache_combined_log() -> None:
    """Verify parsing of Apache/Nginx web server combined logs."""
    normalizer = LogNormalizer()
    raw = (
        "192.168.1.50 - admin [10/Oct/2026:13:55:36 +0000] "
        '"POST /api/v1/auth/login HTTP/1.1" 401 532'
    )
    event = normalizer.normalize(raw, host="web-gw")

    assert event.host == "web-gw"
    assert event.sourcetype == SourceType.WEB_ACCESS
    assert event.src_ip == "192.168.1.50"
    assert event.user == "admin"
    assert event.action == "POST"
    assert event.status == "failure"
    assert event.uri_path == "/api/v1/auth/login"
    assert event.fields["status_code"] == 401


def test_normalizer_rfc3164_ssh_auth_log() -> None:
    """Verify parsing of Linux Syslog with SSH authentication deep extraction."""
    normalizer = LogNormalizer()
    raw = (
        "Oct 12 14:00:00 bastion sshd[1234]: "
        "Failed password for invalid user admin from 203.0.113.15 port 44321 ssh2"
    )
    event = normalizer.normalize(raw)

    assert event.host == "bastion"
    assert event.process == "sshd"
    assert event.sourcetype == SourceType.AUTH
    assert event.action == "login"
    assert event.status == "failure"
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.15"
    assert event.src_port == 44321
    assert event.severity == EventSeverity.HIGH


def test_normalizer_rfc5424_syslog() -> None:
    """Verify parsing of RFC 5424 structured syslog."""
    normalizer = LogNormalizer()
    raw = "<165>1 2026-10-12T14:15:00Z router.edge fw - ID42 - Packet dropped on interface eth0"
    event = normalizer.normalize(raw)

    assert event.host == "router.edge"
    assert event.process == "fw"
    assert event.sourcetype == SourceType.SYSLOG


def test_normalizer_empty_string_error() -> None:
    """Verify IngestionError raised for empty logs."""
    normalizer = LogNormalizer()
    with pytest.raises(IngestionError, match="Empty log"):
        normalizer.normalize("   ")


def test_hec_collector_single_and_batch() -> None:
    """Verify HTTP Event Collector processing single and batch event lists."""
    hec = HECCollector(token="secret-hec-token")

    # Unauthorized attempt
    with pytest.raises(IngestionError, match="Unauthorized"):
        hec.process_payload({"event": "test"}, provided_token="wrong-token")

    # Authorized single event dict
    events = hec.process_payload(
        {"event": {"action": "sudo", "user": "ubuntu", "status": "success"}, "host": "srv-jump"},
        provided_token="secret-hec-token",
    )
    assert len(events) == 1
    assert events[0].host == "srv-jump"
    assert events[0].action == "sudo"
    assert events[0].user == "ubuntu"

    # Authorized batch events
    batch = [
        {"event": "Oct 12 14:00:00 h1 sshd[1]: Accepted publickey for user1 from 10.1.1.1 port 22"},
        {"event": "Oct 12 14:00:01 h2 sshd[2]: Accepted publickey for user2 from 10.1.1.2 port 22"},
    ]
    batch_res = hec.process_payload(batch, provided_token="secret-hec-token")
    assert len(batch_res) == 2
    assert batch_res[0].user == "user1"
    assert batch_res[1].user == "user2"

    # String line-delimited payload
    str_payload = "Line 1 unparsed event\nLine 2 unparsed event\n"
    res_str = hec.process_payload(str_payload, provided_token="secret-hec-token")
    assert len(res_str) == 2

    # Unsupported payload type
    with pytest.raises(IngestionError, match="Unsupported HEC payload"):
        hec.process_payload(12345, provided_token="secret-hec-token")  # type: ignore[arg-type]


def test_normalizer_timestamps_and_severities() -> None:
    """Verify integer epoch timestamps, ISO timestamps, and severity mappings."""
    normalizer = LogNormalizer()

    # Epoch timestamp and warning severity
    data1 = {"host": "h1", "time": 1728741600, "level": "warning", "sourcetype": "firewall"}
    ev1 = normalizer.from_json_dict(data1)
    assert ev1.sourcetype == SourceType.FIREWALL
    assert ev1.severity == EventSeverity.MEDIUM
    assert ev1.timestamp.year == 2024

    # ISO string timestamp and error level
    data2 = {"host": "h2", "@timestamp": "2026-10-12T14:00:00Z", "level": "error"}
    ev2 = normalizer.from_json_dict(data2)
    assert ev2.severity == EventSeverity.HIGH
    assert ev2.timestamp.year == 2026

    # Generic unparsed fallback log
    ev_fallback = normalizer.normalize("Plain text unstructured log line without special syntax")
    assert ev_fallback.sourcetype == SourceType.CUSTOM
    assert ev_fallback.raw == "Plain text unstructured log line without special syntax"
