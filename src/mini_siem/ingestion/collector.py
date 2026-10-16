"""Multi-Protocol Log Ingestion & Normalization Engine for Mini SIEM.

Parses heterogeneous logs from multiple protocols and formats:
1. HTTP Event Collector (HEC) JSON payloads
2. Syslog RFC 5424 and RFC 3164 lines
3. Apache / Nginx Combined Log Format
4. Generic JSON logs
5. Linux authentication logs (sshd/sudo)

Maps all parsed inputs into canonical `SIEMLogEvent` records.
"""

import json
import re
from datetime import UTC, datetime
from typing import Any

from mini_siem.models.enums import EventSeverity, SourceType
from mini_siem.models.schemas import SIEMLogEvent


class IngestionError(Exception):
    """Base exception for log ingestion and parsing errors."""


class LogNormalizer:
    """Normalizes heterogeneous raw log formats into canonical SIEMLogEvents."""

    # Regex for Apache/Nginx Combined Log Format:
    # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    COMBINED_LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"'
        r'(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
        r"(?P<status>\d{3})\s+(?P<bytes>\S+)"
    )

    # Regex for RFC 3164 Syslog:
    # <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
    RFC3164_REGEX = re.compile(
        r"^(?:<(?P<pri>\d+)>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )

    # Regex for RFC 5424 Syslog:
    # <165>1 2003-10-11T22:14:15.003Z host.com evntslog - ID47 [SDID iut="3"] App log entry
    RFC5424_REGEX = re.compile(
        r"^<(?P<pri>\d+)>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
        r"(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured>(?:\[.*?\]|-))\s*(?P<message>.*)$"
    )

    # Regex for SSH Authentication logs:
    # Failed password for invalid user root from 192.168.1.100 port 22 ssh2
    # Accepted publickey for ubuntu from 10.0.0.5 port 54321 ssh2
    SSH_AUTH_REGEX = re.compile(
        r"^(?P<action>Failed|Accepted)\s+(?:password|publickey)\s+for\s+"
        r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+"
        r"(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    )

    def normalize(
        self,
        raw: str,
        sourcetype: SourceType = SourceType.CUSTOM,
        host: str = "unknown-host",
    ) -> SIEMLogEvent:
        """Attempt best-effort normalization from string input."""
        trimmed = raw.strip()
        if not trimmed:
            raise IngestionError("Empty log string provided.")

        # 1. Attempt JSON parsing
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                data = json.loads(trimmed)
                if isinstance(data, dict):
                    return self.from_json_dict(data, raw=trimmed, sourcetype=sourcetype, host=host)
            except json.JSONDecodeError:
                pass

        # 2. Attempt Web Access Log regex
        match_web = self.COMBINED_LOG_REGEX.match(trimmed)
        if match_web:
            return self._parse_web_log(match_web, raw=trimmed, host=host)

        # 3. Attempt Syslog RFC 5424
        match_5424 = self.RFC5424_REGEX.match(trimmed)
        if match_5424:
            return self._parse_rfc5424(match_5424, raw=trimmed)

        # 4. Attempt Syslog RFC 3164
        match_3164 = self.RFC3164_REGEX.match(trimmed)
        if match_3164:
            return self._parse_rfc3164(match_3164, raw=trimmed)

        # 5. Attempt direct SSH authentication line
        match_ssh = self.SSH_AUTH_REGEX.search(trimmed)
        if match_ssh:
            is_success = match_ssh.group("action") == "Accepted"
            return SIEMLogEvent(
                host=host,
                sourcetype=SourceType.AUTH,
                severity=EventSeverity.INFORMATIONAL if is_success else EventSeverity.HIGH,
                process="sshd",
                action="login",
                status="success" if is_success else "failure",
                user=match_ssh.group("user"),
                src_ip=match_ssh.group("src_ip"),
                src_port=int(match_ssh.group("src_port")),
                raw=trimmed,
            )

        # 6. Fallback generic log
        return SIEMLogEvent(
            host=host,
            sourcetype=sourcetype,
            severity=EventSeverity.INFORMATIONAL,
            raw=trimmed,
        )

    def from_json_dict(
        self,
        data: dict[str, Any],
        raw: str | None = None,
        sourcetype: SourceType = SourceType.CUSTOM,
        host: str = "unknown-host",
    ) -> SIEMLogEvent:
        """Parse structured dictionary into canonical SIEMLogEvent."""
        raw_str = raw or json.dumps(data)
        event_host = str(data.get("host") or data.get("hostname") or host)

        # Extract timestamp
        ts = datetime.now(UTC)
        raw_ts = data.get("timestamp") or data.get("time") or data.get("@timestamp")
        if raw_ts:
            if isinstance(raw_ts, (int, float)):
                ts = datetime.fromtimestamp(raw_ts, tz=UTC)
            elif isinstance(raw_ts, str):
                try:
                    ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except ValueError:
                    pass

        # Map severity
        sev = EventSeverity.INFORMATIONAL
        raw_sev = str(data.get("severity") or data.get("level") or "").lower()
        if raw_sev in {e.value for e in EventSeverity}:
            sev = EventSeverity(raw_sev)
        elif raw_sev in ("warn", "warning"):
            sev = EventSeverity.MEDIUM
        elif raw_sev in ("err", "error"):
            sev = EventSeverity.HIGH

        # Map sourcetype
        st = sourcetype
        raw_st = str(data.get("sourcetype") or "").lower()
        if raw_st in {e.value for e in SourceType}:
            st = SourceType(raw_st)

        # Source / destination network fields
        src_ip = data.get("src_ip") or data.get("source_ip") or data.get("src")
        dst_ip = data.get("dst_ip") or data.get("destination_ip") or data.get("dst")
        src_port = data.get("src_port") or data.get("source_port")
        dst_port = data.get("dst_port") or data.get("destination_port")

        user = data.get("user") or data.get("username") or data.get("account")
        action = data.get("action") or data.get("event_action")
        status = data.get("status") or data.get("result") or data.get("outcome")
        process = data.get("process") or data.get("app") or data.get("program")
        uri_path = data.get("uri_path") or data.get("path") or data.get("uri")

        return SIEMLogEvent(
            host=event_host,
            timestamp=ts,
            sourcetype=st,
            severity=sev,
            action=str(action) if action is not None else None,
            status=str(status) if status is not None else None,
            src_ip=str(src_ip) if src_ip is not None else None,
            dst_ip=str(dst_ip) if dst_ip is not None else None,
            src_port=int(src_port) if src_port is not None else None,
            dst_port=int(dst_port) if dst_port is not None else None,
            user=str(user) if user is not None else None,
            process=str(process) if process is not None else None,
            uri_path=str(uri_path) if uri_path is not None else None,
            raw=raw_str,
            fields=data,
        )

    def _parse_web_log(self, match: re.Match[str], raw: str, host: str) -> SIEMLogEvent:
        """Map web access log match groups to canonical event."""
        client_ip = match.group("ip")
        user = match.group("user")
        if user == "-":
            user = None
        method = match.group("method")
        path = match.group("path")
        status_code = int(match.group("status"))

        status = "success" if status_code < 400 else "failure"
        sev = EventSeverity.LOW if status_code < 400 else EventSeverity.MEDIUM
        if status_code >= 500:
            sev = EventSeverity.HIGH

        return SIEMLogEvent(
            host=host,
            sourcetype=SourceType.WEB_ACCESS,
            severity=sev,
            action=method,
            status=status,
            src_ip=client_ip,
            user=user,
            uri_path=path,
            raw=raw,
            fields={
                "status_code": status_code,
                "bytes": match.group("bytes"),
                "protocol": match.group("proto"),
            },
        )

    def _parse_rfc3164(self, match: re.Match[str], raw: str) -> SIEMLogEvent:
        """Map RFC 3164 Syslog match to canonical event with SSH auth extraction."""
        host = match.group("host")
        process = match.group("process")
        message = match.group("message")

        action: str | None = None
        status: str | None = None
        src_ip: str | None = None
        src_port: int | None = None
        user: str | None = None
        sourcetype = SourceType.SYSLOG
        sev = EventSeverity.INFORMATIONAL

        # Deep inspect message for SSH auth events
        ssh_match = self.SSH_AUTH_REGEX.search(message)
        if ssh_match:
            sourcetype = SourceType.AUTH
            is_success = ssh_match.group("action") == "Accepted"
            action = "login"
            status = "success" if is_success else "failure"
            sev = EventSeverity.INFORMATIONAL if is_success else EventSeverity.HIGH
            user = ssh_match.group("user")
            src_ip = ssh_match.group("src_ip")
            src_port = int(ssh_match.group("src_port"))

        return SIEMLogEvent(
            host=host,
            sourcetype=sourcetype,
            severity=sev,
            process=process,
            action=action,
            status=status,
            src_ip=src_ip,
            src_port=src_port,
            user=user,
            raw=raw,
            fields={"syslog_message": message},
        )

    def _parse_rfc5424(self, match: re.Match[str], raw: str) -> SIEMLogEvent:
        """Map RFC 5424 Syslog match to canonical event."""
        host = match.group("host")
        app = match.group("app")
        message = match.group("message")

        return SIEMLogEvent(
            host=host,
            sourcetype=SourceType.SYSLOG,
            severity=EventSeverity.INFORMATIONAL,
            process=app if app != "-" else None,
            raw=raw,
            fields={
                "msgid": match.group("msgid"),
                "structured_data": match.group("structured"),
                "message": message,
            },
        )


class HECCollector:
    """HTTP Event Collector (HEC) receiver with batch buffering."""

    def __init__(self, token: str | None = None, normalizer: LogNormalizer | None = None) -> None:
        self.token = token
        self.normalizer = normalizer or LogNormalizer()

    def process_payload(
        self,
        payload: dict[str, Any] | list[dict[str, Any]] | str,
        provided_token: str | None = None,
    ) -> list[SIEMLogEvent]:
        """Validate HEC payload and ingest single or batch events."""
        if self.token and provided_token != self.token:
            raise IngestionError("Unauthorized HEC token.")

        events: list[SIEMLogEvent] = []

        if isinstance(payload, str):
            # Line-delimited JSON or raw string
            for line in payload.splitlines():
                if line.strip():
                    events.append(self.normalizer.normalize(line, sourcetype=SourceType.HEC))
            return events

        if isinstance(payload, list):
            for item in payload:
                events.append(self._ingest_hec_dict(item))
            return events

        if isinstance(payload, dict):
            events.append(self._ingest_hec_dict(payload))
            return events

        raise IngestionError(f"Unsupported HEC payload format: {type(payload)}")

    def _ingest_hec_dict(self, item: dict[str, Any]) -> SIEMLogEvent:
        """Process Splunk-style HEC event dict {'event': ..., 'host': ..., 'sourcetype': ...}."""
        event_body = item.get("event")
        host = item.get("host", "hec-client")

        if isinstance(event_body, dict):
            return self.normalizer.from_json_dict(event_body, sourcetype=SourceType.HEC, host=host)
        if isinstance(event_body, str):
            return self.normalizer.normalize(event_body, sourcetype=SourceType.HEC, host=host)

        # Flat dictionary
        return self.normalizer.from_json_dict(item, sourcetype=SourceType.HEC, host=host)
