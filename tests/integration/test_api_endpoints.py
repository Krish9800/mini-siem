"""Integration tests for FastAPI Control Plane REST API endpoints."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mini_siem.api.app import app
from mini_siem.config.settings import get_settings


@pytest.fixture
def client(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Create test client with isolated database path."""
    db_file = temp_dir / "api_test.db"
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("SIEM_DATABASE_URL", str(db_file))
    monkeypatch.setenv("SIEM_HEC_TOKEN", "test-hec-key")
    get_settings.cache_clear()
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    """Verify GET /api/v1/health returns 200 OK and metric counters."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "indexed_events" in data


def test_hec_ingest_and_search_flow(client: TestClient) -> None:
    """Verify ingestion of logs via HEC followed by SPL search and alerts check."""
    # Register a detection rule
    rule_payload = {
        "name": "Failed Sudo Attempts",
        "rule_type": "match",
        "urgency": "high",
        "field_matches": {"action": "sudo", "status": "failure"},
        "mitre_attack_id": "T1548.003",
    }
    res_rule = client.post("/api/v1/rules", json=rule_payload)
    assert res_rule.status_code == 201

    # Ingest events via HEC
    hec_events = [
        {
            "event": {
                "host": "srv-app-01",
                "action": "sudo",
                "status": "failure",
                "user": "malicious_user",
                "src_ip": "10.0.0.99",
            }
        },
        {
            "event": {
                "host": "srv-app-01",
                "action": "login",
                "status": "success",
                "user": "legit_user",
                "src_ip": "10.0.0.10",
            }
        },
    ]

    res_ingest = client.post(
        "/api/v1/hec/event",
        json=hec_events,
        headers={"Authorization": "Bearer test-hec-key"},
    )
    assert res_ingest.status_code == 202
    assert res_ingest.json()["ingested_count"] == 2
    assert res_ingest.json()["alerts_triggered"] == 1

    # Search query
    res_search = client.post(
        "/api/v1/search",
        json={"raw_query": "action=sudo | count by user"},
    )
    assert res_search.status_code == 200
    search_data = res_search.json()
    assert search_data["total_hits"] == 1
    assert search_data["aggregations"]["malicious_user"] == 1

    # Check alerts
    res_alerts = client.get("/api/v1/alerts")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "Failed Sudo Attempts"


def test_threat_intel_endpoints(client: TestClient) -> None:
    """Verify threat intelligence IOC registration and listing."""
    ioc_payload = {
        "indicator": "malicious-c2.net",
        "ioc_type": "domain",
        "threat_actor": "APT29",
        "confidence": 90,
    }
    res_create = client.post("/api/v1/threat-intel", json=ioc_payload)
    assert res_create.status_code == 201

    res_list = client.get("/api/v1/threat-intel")
    assert res_list.status_code == 200
    items = res_list.json()
    assert len(items) == 1
    assert items[0]["indicator"] == "malicious-c2.net"
