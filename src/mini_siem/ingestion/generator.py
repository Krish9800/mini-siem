"""Synthetic and Attack Log Generator for Mini SIEM.

Simulates heterogeneous log streams:
1. SSH Brute Force attacks (multiple failures followed by potential breach)
2. Web application attack payloads (SQLi, XSS, Path Traversal)
3. Standard RFC Syslog operational telemetry
"""

import random
from datetime import UTC, datetime


class LogGenerator:
    """Generates synthetic log streams and attack scenarios for SIEM evaluation."""

    def __init__(self, seed: int | None = 42) -> None:
        if seed is not None:
            random.seed(seed)

    def generate_ssh_brute_force(
        self,
        count: int = 10,
        attacker_ip: str = "192.168.1.250",
        target_user: str = "admin",
        success_at_end: bool = False,
    ) -> list[str]:
        """Generate Linux auth log entries simulating an SSH brute force attempt."""
        logs: list[str] = []
        for i in range(count):
            port = 40000 + i
            is_last = i == count - 1
            if is_last and success_at_end:
                logs.append(
                    f"Accepted password for {target_user} from {attacker_ip} port {port} ssh2"
                )
            else:
                msg = (
                    f"Failed password for invalid user {target_user} from "
                    f"{attacker_ip} port {port} ssh2"
                )
                logs.append(msg)
        return logs

    def generate_web_attacks(
        self,
        count: int = 10,
        attacker_ip: str = "10.0.0.99",
    ) -> list[str]:
        """Generate Apache/Nginx Combined Log Format web attack requests."""
        payloads = [
            ("GET", "/login.php?user=admin' OR '1'='1", 401),
            ("GET", "/search?q=<script>alert(1)</script>", 200),
            ("GET", "/../../etc/passwd", 403),
            ("POST", "/api/v1/auth?token=' UNION SELECT null,password FROM users--", 500),
            ("GET", "/cgi-bin/test.cgi?cmd=cat+/etc/shadow", 403),
            ("GET", "/wp-login.php", 404),
            ("GET", "/phpmyadmin/index.php", 404),
        ]
        logs: list[str] = []
        now_str = datetime.now(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")

        for i in range(count):
            method, path, status = payloads[i % len(payloads)]
            logs.append(
                f'{attacker_ip} - - [{now_str}] "{method} {path} HTTP/1.1" {status} 1234'
            )
        return logs

    def generate_syslog_stream(
        self,
        count: int = 10,
        host: str = "firewall-gw01",
    ) -> list[str]:
        """Generate RFC 3164 Syslog entries."""
        logs: list[str] = []
        timestamp = datetime.now(UTC).strftime("%b %d %H:%M:%S")
        services = ["kernel", "sshd", "systemd", "iptables", "cron"]

        for i in range(count):
            svc = services[i % len(services)]
            logs.append(
                f"<34>{timestamp} {host} {svc}[{1000 + i}]: Event {i} state updated to active"
            )
        return logs

    def generate_scenario(self, scenario: str, count: int = 10) -> list[str]:
        """Generate logs based on high-level scenario name."""
        scenario_clean = scenario.lower().strip()
        if scenario_clean in ("brute-force", "ssh"):
            return self.generate_ssh_brute_force(count=count)
        if scenario_clean in ("web", "web-attacks", "sqli", "xss"):
            return self.generate_web_attacks(count=count)
        if scenario_clean in ("syslog", "system"):
            return self.generate_syslog_stream(count=count)
        raise ValueError(
            f"Unknown scenario '{scenario}'. Supported: brute-force, web-attacks, syslog"
        )
