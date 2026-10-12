"""FastAPI Control Plane REST API for Mini SIEM.

Endpoints:
- GET  /api/v1/health: System health and telemetry metrics
- POST /api/v1/hec/event: HTTP Event Collector log ingestion
- POST /api/v1/search: SPL-style query execution over indexed events
- GET  /api/v1/alerts: Retrieve security alerts
- GET  /api/v1/rules: List registered detection rules
- POST /api/v1/rules: Create or update detection rule
- GET  /api/v1/threat-intel: Query threat intelligence IOC items
- POST /api/v1/threat-intel: Ingest new threat intelligence IOC item
"""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from mini_siem import __version__
from mini_siem.config.settings import SIEMSettings, get_settings
from mini_siem.db.database import Database
from mini_siem.engine.rule_evaluator import RuleEvaluator
from mini_siem.ingestion.collector import HECCollector, IngestionError
from mini_siem.intel.threat_intel import ThreatIntelEngine
from mini_siem.models.schemas import (
    QueryResult,
    SearchQuery,
    SIEMAlert,
    SIEMRule,
    ThreatFeedItem,
)
from mini_siem.search.query_engine import QueryEngine, QuerySyntaxError

app = FastAPI(
    title="Mini SIEM Control Plane",
    description="High-performance autonomous SIEM ingestion, search, and alert control plane.",
    version=__version__,
)


def get_database(settings: Annotated[SIEMSettings, Depends(get_settings)]) -> Database:
    """Dependency provider for database repository."""
    return Database(settings.effective_db_path)


def get_rule_evaluator(db: Annotated[Database, Depends(get_database)]) -> RuleEvaluator:
    """Dependency provider for initialized RuleEvaluator."""
    rules = db.list_rules()
    return RuleEvaluator(rules)


def get_threat_intel(db: Annotated[Database, Depends(get_database)]) -> ThreatIntelEngine:
    """Dependency provider for initialized ThreatIntelEngine."""
    items = db.list_threat_feed_items()
    return ThreatIntelEngine(items)


@app.get("/api/v1/health", tags=["System"])
def health_endpoint(
    db: Annotated[Database, Depends(get_database)],
) -> dict[str, Any]:
    """Health status and storage metrics."""
    with db.session() as conn:
        events_cnt = conn.execute("SELECT count(*) FROM siem_events").fetchone()[0]
        alerts_cnt = conn.execute("SELECT count(*) FROM siem_alerts").fetchone()[0]
        rules_cnt = conn.execute("SELECT count(*) FROM siem_rules").fetchone()[0]

    return {
        "status": "healthy",
        "version": __version__,
        "indexed_events": events_cnt,
        "active_alerts": alerts_cnt,
        "registered_rules": rules_cnt,
    }


@app.post(
    "/api/v1/hec/event",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Ingestion"],
)
def hec_ingest_endpoint(
    payload: dict[str, Any] | list[dict[str, Any]] | str,
    db: Annotated[Database, Depends(get_database)],
    evaluator: Annotated[RuleEvaluator, Depends(get_rule_evaluator)],
    threat_intel: Annotated[ThreatIntelEngine, Depends(get_threat_intel)],
    settings: Annotated[SIEMSettings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Ingest heterogeneous logs via Splunk-compatible HEC format."""
    provided_token: str | None = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() in ("splunk", "bearer"):
            provided_token = parts[1]

    collector = HECCollector(token=settings.hec_token)
    try:
        events = collector.process_payload(payload, provided_token=provided_token)
    except IngestionError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
            if "Unauthorized" in str(err)
            else status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    all_alerts: list[SIEMAlert] = []

    # Enrich against threat intel and evaluate detection rules
    for ev in events:
        if settings.enable_threat_intel:
            intel_alerts = threat_intel.enrich_event(ev)
            all_alerts.extend(intel_alerts)

        rule_alerts = evaluator.evaluate_event(ev)
        all_alerts.extend(rule_alerts)

    # Persist events and triggered alerts
    db.save_events_batch(events)
    for a in all_alerts:
        db.save_alert(a)

    return {
        "status": "success",
        "ingested_count": len(events),
        "alerts_triggered": len(all_alerts),
    }


@app.post("/api/v1/search", response_model=QueryResult, tags=["Search"])
def search_endpoint(
    query: SearchQuery,
    db: Annotated[Database, Depends(get_database)],
) -> QueryResult:
    """Execute SPL / Lucene style search queries over ingested events."""
    engine = QueryEngine()
    # Fetch event corpus
    events = db.list_events(limit=10000)
    try:
        return engine.execute(query, events)
    except QuerySyntaxError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err


@app.get("/api/v1/alerts", response_model=list[SIEMAlert], tags=["Alerts"])
def list_alerts_endpoint(
    db: Annotated[Database, Depends(get_database)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[SIEMAlert]:
    """Retrieve list of generated security alerts."""
    return db.list_alerts(limit=limit)


@app.get("/api/v1/rules", response_model=list[SIEMRule], tags=["Rules"])
def list_rules_endpoint(
    db: Annotated[Database, Depends(get_database)],
) -> list[SIEMRule]:
    """List registered detection rules."""
    return db.list_rules()


@app.post("/api/v1/rules", status_code=status.HTTP_201_CREATED, tags=["Rules"])
def create_rule_endpoint(
    rule: SIEMRule,
    db: Annotated[Database, Depends(get_database)],
) -> dict[str, str]:
    """Create or update a detection rule."""
    db.save_rule(rule)
    return {"status": "created", "rule_id": rule.rule_id}


@app.get("/api/v1/threat-intel", response_model=list[ThreatFeedItem], tags=["Threat Intel"])
def list_threat_intel_endpoint(
    db: Annotated[Database, Depends(get_database)],
) -> list[ThreatFeedItem]:
    """List threat intelligence indicators of compromise."""
    return db.list_threat_feed_items()


@app.post("/api/v1/threat-intel", status_code=status.HTTP_201_CREATED, tags=["Threat Intel"])
def create_threat_intel_endpoint(
    item: ThreatFeedItem,
    db: Annotated[Database, Depends(get_database)],
) -> dict[str, str]:
    """Register a new threat intelligence IOC item."""
    db.save_threat_feed_item(item)
    return {"status": "created", "indicator": item.indicator}
