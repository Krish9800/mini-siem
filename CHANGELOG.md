# Changelog

All notable changes to the Mini SIEM system are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- **Phase 1 (Foundation)**: Project structure, settings (`SIEMSettings`), Pytest fixtures.
- **Phase 2 (Models & Enums)**: Canonical `SIEMLogEvent`, `SearchQuery`, `QueryResult`, `SIEMRule`, `SIEMAlert`, `ThreatFeedItem`, and `StrEnum` enums.
- **Phase 3 (Multi-Protocol Ingestion & Normalizer)**: `HECCollector` and `LogNormalizer` supporting JSON, Syslog RFC 5424/3164, Apache/Nginx web access logs, and Linux auth logs.
- **Phase 4 (SPL Search Engine)**: `QueryEngine` with field filtering, boolean logic, wildcards, and aggregation pipes (`| count by <field>`).
- **Phase 5 (Correlation Rule Engine)**: `RuleEvaluator` evaluating match rules, regex patterns, and sliding-window burst thresholds.
- **Phase 6 (Threat Intelligence Enrichment)**: `ThreatIntelEngine` matching IPs, CIDR subnets, and domains against IOC feeds with MITRE ATT&CK mapping.
- **Phase 7 (SQLite WAL Persistence)**: `Database` repository running in WAL mode with parameterized tables for events, rules, alerts, and threat feeds.
- **Phase 8 (FastAPI Control Plane)**: REST API with `/api/v1/health`, `/api/v1/hec/event`, `/api/v1/search`, `/api/v1/alerts`, `/api/v1/rules`, and `/api/v1/threat-intel`.
- **Phase 9 (Typer CLI Tool)**: CLI tool supporting `mini-siem search`, `mini-siem ingest`, `mini-siem alerts list`, `mini-siem rules list`, `mini-siem intel list`, and `mini-siem serve`.
- **Phase 10 (Deployment, Security & CI)**: Multi-stage rootless Dockerfile (`UID 10001:10001`), `docker-compose.yml`, GitHub Actions CI workflow, STRIDE threat model, and adversarial security testbed.
