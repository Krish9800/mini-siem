"""Integration tests for Typer CLI commands."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mini_siem.cli.main import app
from mini_siem.config.settings import get_settings
from mini_siem.db.database import Database
from mini_siem.models.enums import AlertUrgency, IOCType, RuleType
from mini_siem.models.schemas import SIEMRule, ThreatFeedItem

runner = CliRunner()


def test_cli_rules_and_intel_list(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `mini-siem rules list` and `mini-siem intel list` commands."""
    db_file = temp_dir / "cli_test.db"
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("SIEM_DATABASE_URL", str(db_file))
    get_settings.cache_clear()

    # Empty states
    res_empty_rules = runner.invoke(app, ["rules", "list"])
    assert res_empty_rules.exit_code == 0
    assert "No detection rules" in res_empty_rules.stdout

    res_empty_intel = runner.invoke(app, ["intel", "list"])
    assert res_empty_intel.exit_code == 0
    assert "No threat intel indicators" in res_empty_intel.stdout

    db = Database(db_file)
    db.save_rule(
        SIEMRule(
            rule_id="rule-cli-1",
            name="SSH Scan",
            rule_type=RuleType.MATCH,
            urgency=AlertUrgency.MEDIUM,
        )
    )
    db.save_threat_feed_item(
        ThreatFeedItem(
            indicator="198.51.100.5",
            ioc_type=IOCType.IPV4,
            threat_actor="APT28",
            description="C2 Node",
        )
    )

    res_rules = runner.invoke(app, ["rules", "list"])
    assert res_rules.exit_code == 0
    assert "rule-cli-1" in res_rules.stdout

    res_intel = runner.invoke(app, ["intel", "list"])
    assert res_intel.exit_code == 0
    assert "198.51.100.5" in res_intel.stdout


def test_cli_ingest_and_search_and_alerts(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `mini-siem ingest` file and `mini-siem search` / `mini-siem alerts list`."""
    db_file = temp_dir / "cli_workflow.db"
    monkeypatch.setenv("SIEM_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("SIEM_DATABASE_URL", str(db_file))
    get_settings.cache_clear()

    # Write synthetic log file
    log_file = temp_dir / "auth.log"
    log_file.write_text(
        "Oct 12 14:00:00 server1 sshd[100]: "
        "Failed password for invalid user hacker from 10.0.0.99 port 22\n"
        "Oct 12 14:00:01 server1 sshd[101]: "
        "Accepted publickey for ubuntu from 10.0.0.1 port 22\n",
        encoding="utf-8",
    )

    # Ingest file
    res_ingest = runner.invoke(app, ["ingest", str(log_file)])
    assert res_ingest.exit_code == 0
    assert "Successfully ingested 2 events" in res_ingest.stdout

    # Search with aggregation pipe
    res_search = runner.invoke(app, ["search", "action=login | count by user"])
    assert res_search.exit_code == 0
    assert "Search Completed" in res_search.stdout
    assert "hacker" in res_search.stdout
    assert "ubuntu" in res_search.stdout

    # Search without pipe
    res_search_events = runner.invoke(app, ["search", "user=hacker"])
    assert res_search_events.exit_code == 0
    assert "server1" in res_search_events.stdout

    # Ingest missing file
    res_missing = runner.invoke(app, ["ingest", "non_existent_file.log"])
    assert res_missing.exit_code == 1
    assert "File not found" in res_missing.stdout
