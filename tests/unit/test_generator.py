"""Unit tests for synthetic log generator and CLI simulate commands."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mini_siem.cli.main import app
from mini_siem.ingestion.collector import LogNormalizer
from mini_siem.ingestion.generator import LogGenerator
from mini_siem.models.enums import SourceType


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_log_generator_ssh_brute_force() -> None:
    """Verify SSH brute force log generation and normalization."""
    generator = LogGenerator(seed=123)
    normalizer = LogNormalizer()

    logs = generator.generate_ssh_brute_force(
        count=5, attacker_ip="192.168.10.55", target_user="root", success_at_end=True
    )
    assert len(logs) == 5
    assert "Failed password" in logs[0]
    assert "Accepted password" in logs[-1]

    # Verify normalizer can parse all generated entries
    events = [normalizer.normalize(line, sourcetype=SourceType.AUTH) for line in logs]
    assert len(events) == 5
    assert events[0].src_ip == "192.168.10.55"
    assert events[0].user == "root"
    assert events[0].action == "login"
    assert events[0].status == "failure"
    assert events[-1].status == "success"


def test_log_generator_web_attacks() -> None:
    """Verify web attack log generation and normalization."""
    generator = LogGenerator(seed=456)
    normalizer = LogNormalizer()

    logs = generator.generate_web_attacks(count=7, attacker_ip="172.16.0.4")
    assert len(logs) == 7

    events = [normalizer.normalize(line, sourcetype=SourceType.WEB_ACCESS) for line in logs]
    assert len(events) == 7
    assert events[0].src_ip == "172.16.0.4"
    assert events[0].sourcetype == SourceType.WEB_ACCESS


def test_log_generator_syslog_stream() -> None:
    """Verify RFC syslog generation and normalization."""
    generator = LogGenerator(seed=789)
    normalizer = LogNormalizer()

    logs = generator.generate_syslog_stream(count=5, host="firewall-core")
    assert len(logs) == 5

    events = [normalizer.normalize(line, sourcetype=SourceType.SYSLOG) for line in logs]
    assert len(events) == 5
    assert events[0].host == "firewall-core"


def test_log_generator_scenario_dispatch() -> None:
    """Verify scenario dispatcher and error handling."""
    generator = LogGenerator()

    ssh_logs = generator.generate_scenario("brute-force", count=3)
    assert len(ssh_logs) == 3

    web_logs = generator.generate_scenario("web-attacks", count=4)
    assert len(web_logs) == 4

    syslog_logs = generator.generate_scenario("syslog", count=2)
    assert len(syslog_logs) == 2

    with pytest.raises(ValueError, match="Unknown scenario"):
        generator.generate_scenario("non-existent-scenario")


def test_cli_generate_command(runner: CliRunner, tmp_path: Path) -> None:
    """Verify CLI generate command to stdout and file output."""
    out_file = tmp_path / "test_attack.log"

    # Generate to file
    res = runner.invoke(
        app,
        ["generate", "--scenario", "brute-force", "--count", "5", "--output", str(out_file)],
    )
    assert res.exit_code == 0
    assert out_file.is_file()
    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5

    # Generate invalid scenario
    err_res = runner.invoke(app, ["generate", "--scenario", "invalid-xyz"])
    assert err_res.exit_code == 1


def test_cli_ingest_with_suppression(runner: CliRunner, tmp_path: Path) -> None:
    """Verify CLI ingest command with suppression cooldown option."""
    log_file = tmp_path / "ingest_sample.log"
    log_file.write_text(
        "Failed password for invalid user root from 192.168.1.100 port 44001 ssh2\n"
        "Failed password for invalid user root from 192.168.1.100 port 44002 ssh2\n",
        encoding="utf-8",
    )

    res = runner.invoke(
        app,
        ["ingest", str(log_file), "--sourcetype", "auth", "--suppress-cooldown", "60"],
    )
    assert res.exit_code == 0
    assert "Successfully ingested 2 events" in res.output
