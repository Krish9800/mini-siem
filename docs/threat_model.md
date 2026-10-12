# STRIDE Threat Model: Mini SIEM

## 1. System Overview & Boundaries
Mini SIEM is a high-throughput log ingestion, normalization, query, and correlation platform.

### Trust Boundaries
1. **Network Ingestion Boundary**: Unauthenticated/authenticated HEC and Syslog log streams from external clients or endpoints.
2. **Search / Control Plane Boundary**: REST API `/api/v1/search` and Typer CLI executing user-supplied query strings.
3. **Database Boundary**: SQLite WAL storage storing events, rules, alerts, and threat feed indicators.

---

## 2. STRIDE Analysis & Mitigations

| Threat | Description | Attack Vector | Severity | Implemented Mitigations | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Forged log origins or spoofed threat feeds. | Sending fake events pretending to originate from legitimate domain controllers or firewalls. | High | Ingestion tracks transport metadata; threat feeds verified against strict CIDR network parsing and canonical indicators. | `tests/unit/test_threat_intel.py` |
| **Tampering** | SQL Injection or Search Parser Manipulation. | Attacker attempts SQL injection via search queries or log event fields (`DROP TABLE`). | Critical | 100% Parameterized queries (`?`) in all SQLite operations; SPL search queries parsed via tokenizer and evaluated safely without raw SQL injection surfaces. | `tests/security/test_security_adversarial.py` |
| **Repudiation** | Denying an attack occurred or deleting event history. | High-frequency log floods or malicious resets. | Medium | SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) with synchronous `NORMAL` and immutable UTC ISO-8601 monotonic timestamps. | `tests/unit/test_database.py` |
| **Information Disclosure** | PII or Credential Leaks in Raw Logs. | Log streams containing unencrypted passwords or secrets. | High | Deep inspection parsers extract structured security fields; CLI and API control planes protect sensitive tokens. | `tests/integration/test_api_endpoints.py` |
| **Denial of Service** | Log flooding or Regular Expression DoS (ReDoS). | Ingesting malicious regex patterns or corrupted high-volume lines to stall search workers. | Critical | Bounded batch buffering, linear-time token matching in QueryEngine, precompiled regex caching in RuleEvaluator. | `tests/security/test_security_adversarial.py` |
| **Elevation of Privilege** | Container Breakout or Host Takeover. | Exploiting vulnerabilities to execute code as host root. | Critical | Rootless container execution (`UID 10001:10001`), `cap_drop: ALL`, read-only container filesystem root. | Dockerfile & CI checks |
