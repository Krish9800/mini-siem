# Mini SIEM (Security Information & Event Management)

High-performance, pure-Python Security Information and Event Management (SIEM) system featuring multi-protocol log ingestion, canonical normalization, SPL-style search engine, real-time correlation and detection rules, threat intelligence feed enrichment, SQLite WAL persistence, FastAPI REST control plane, and Typer CLI.

---

## Architecture Overview

```
                                      ┌────────────────────────────────────────────────┐
                                      │             Heterogeneous Log Streams          │
                                      │        (HEC JSON, Syslog, Web, Auth)           │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                                              ▼
                                      ┌────────────────────────────────────────────────┐
                                      │         Ingestion & Normalizer Pipeline        │
                                      │    (LogNormalizer -> Canonical SIEMLogEvent)   │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                      ┌───────────────────────┴────────────────────────┐
                                      ▼                                                ▼
         ┌──────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
         │         Threat Intelligence Engine           │    │       Real-Time Rule Evaluator Engine        │
         │  • IP / Domain / CIDR IOC matching           │    │  • Single-event match rules & regexes        │
         │  • Threat actor tags & confidence scoring    │    │  • Sliding-window threshold bursts           │
         │  • MITRE ATT&CK technique mapping            │    │  • Alert generation (SIEMAlert)              │
         └──────────────────────┬───────────────────────┘    └──────────────────────┬───────────────────────┘
                                │                                                   │
                                └───────────────────────┬───────────────────────────┘
                                                        │
                                                        ▼
                                      ┌────────────────────────────────────────────────┐
                                      │              SQLite WAL Storage                │
                                      │    (siem_events, siem_alerts, rules, feeds)    │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                      ┌───────────────────────┴────────────────────────┐
                                      ▼                                                ▼
         ┌──────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
         │             FastAPI Control Plane            │    │                  Typer CLI                   │
         │   • /api/v1/hec/event                        │    │   • mini-siem search "<query>"               │
         │   • /api/v1/search                           │    │   • mini-siem ingest <file>                  │
         │   • /api/v1/alerts & /api/v1/rules           │    │   • mini-siem alerts list                    │
         │   • /api/v1/threat-intel                     │    │   • mini-siem rules list & intel list        │
         └──────────────────────────────────────────────┘    └──────────────────────────────────────────────┘
```

---

## Features

- **Multi-Protocol Ingestion**: Ingests Splunk-compatible HEC payloads, Syslog RFC 5424 and RFC 3164 lines, Apache/Nginx combined access logs, and Linux auth logs (`sshd`/`sudo`).
- **Canonical Schema Normalization**: Maps raw logs to `SIEMLogEvent` with normalized endpoints (`src_ip`, `dst_ip`, `user`, `action`, `status`, `severity`).
- **SPL-Style Search & Analytics**: Supports key-value filtering, wildcards (`*`), negation (`NOT`, `!=`), full-text search, and pipe aggregations (`| count by user`).
- **Real-Time Correlation & Detection**: Evaluates events against Sigma-style rules, regexes, and sliding-window burst thresholds (e.g. $>5$ login failures in 60s).
- **Threat Intelligence Feed Enrichment**: Matches IPs, CIDRs, and domains against local threat feeds to flag malicious actors and tag events.
- **Relational WAL Storage**: SQLite storage engine running in `PRAGMA journal_mode=WAL;` with parameterized query safety.
- **Rootless Container Runtime**: Multi-stage Docker container (`UID 10001:10001`) with dropped privileges and read-only filesystem.

---

## Getting Started

### Local Setup

```bash
# Clone and enter directory
cd mini-siem

# Create virtual environment and install in editable mode
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Quality Gates

```bash
# Code formatting & linting
ruff format .
ruff check . --fix

# Strict static type checking
mypy --strict src tests

# SAST security vulnerability scan
bandit -r src/

# Run pytest suite with coverage (>= 90%)
pytest --cov=mini_siem --cov-report=term-missing --cov-fail-under=90
```

---

## CLI Usage

```bash
# Ingest local auth log file
mini-siem ingest /var/log/auth.log --sourcetype auth

# Search events with SPL aggregation
mini-siem search "action=login status=failure | count by user"

# Inspect generated alerts
mini-siem alerts list

# View detection rules
mini-siem rules list

# Inspect threat intel IOC feeds
mini-siem intel list

# Start the REST control plane daemon
mini-siem serve --host 127.0.0.1 --port 8000
```

---

## Docker Deployment

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8000/api/v1/health
```

---

## Threat Model

Detailed STRIDE threat modeling and mitigations are documented in [`docs/threat_model.md`](docs/threat_model.md).
