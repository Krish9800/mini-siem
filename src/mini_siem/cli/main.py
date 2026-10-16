"""Typer CLI Tool for Mini SIEM.

Commands:
- search: Run SPL-style queries and aggregate analytics across events.
- ingest: Parse and ingest raw log files or streams into the database.
- alerts: List and triage triggered security alerts.
- rules: List, inspect, and add detection rules.
- intel: Manage and view threat intelligence IOC feeds.
- serve: Start the FastAPI control plane daemon.
"""

from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from mini_siem.config.settings import get_settings
from mini_siem.db.database import Database
from mini_siem.engine.rule_evaluator import RuleEvaluator
from mini_siem.engine.suppression import AlertSuppressionEngine
from mini_siem.ingestion.collector import LogNormalizer
from mini_siem.ingestion.generator import LogGenerator
from mini_siem.intel.threat_intel import ThreatIntelEngine
from mini_siem.models.enums import RuleType, SourceType
from mini_siem.models.schemas import SearchQuery
from mini_siem.search.query_engine import QueryEngine

app = typer.Typer(
    name="mini-siem",
    help="Autonomous Security Information and Event Management (SIEM) CLI.",
    add_completion=False,
)
alerts_app = typer.Typer(name="alerts", help="Triage and query security alerts.")
rules_app = typer.Typer(name="rules", help="Manage and inspect detection rules.")
intel_app = typer.Typer(name="intel", help="Manage threat intelligence IOC feeds.")

app.add_typer(alerts_app)
app.add_typer(rules_app)
app.add_typer(intel_app)

console = Console()


# -------------------------------------------------------------
# Search Command
# -------------------------------------------------------------
@app.command(name="search")
def search_cmd(
    query_str: Annotated[
        str, typer.Argument(help="SPL search query, e.g. 'action=failure | count by user'")
    ],
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max events to return")] = 50,
) -> None:
    """Execute SPL search query and render results or aggregation tables."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    engine = QueryEngine()

    events = db.list_events(limit=5000)
    query = SearchQuery(raw_query=query_str, limit=limit)
    res = engine.execute(query, events)

    console.print(
        f"[bold green]Search Completed:[/] [white]{res.total_hits} total hits in "
        f"{res.execution_time_ms}ms[/]\n"
    )

    # If aggregation pipe used
    if res.aggregations:
        table = Table(title="Aggregation Statistics")
        table.add_column("Value / Key", style="cyan")
        table.add_column("Event Count", style="magenta")
        for key, count in res.aggregations.items():
            table.add_row(key, str(count))
        console.print(table)
        return

    # Render tabular event hits
    if not res.events:
        console.print("[yellow]No events matched query.[/]")
        return

    table = Table(title="Matching SIEM Events")
    table.add_column("Timestamp (UTC)", style="dim")
    table.add_column("Host", style="cyan")
    table.add_column("Action", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("User", style="blue")
    table.add_column("Src IP", style="green")
    for ev in res.events:
        table.add_row(
            ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            ev.host,
            ev.action or "-",
            ev.status or "-",
            ev.user or "-",
            ev.src_ip or "-",
        )
    console.print(table)


# -------------------------------------------------------------
# Ingest Command
# -------------------------------------------------------------
@app.command(name="ingest")
def ingest_cmd(
    file_path: Annotated[Path, typer.Argument(help="Path to raw log file")],
    sourcetype: Annotated[SourceType, typer.Option("--sourcetype", "-s")] = SourceType.CUSTOM,
    host: Annotated[str, typer.Option("--host", "-h")] = "cli-ingest",
    suppress_cooldown: Annotated[
        int,
        typer.Option(
            "--suppress-cooldown",
            "-c",
            help="Alert suppression cooldown in seconds (0 to disable)",
        ),
    ] = 0,
) -> None:
    """Ingest a local log file, evaluate rules & IOCs, and store events."""
    if not file_path.is_file():
        console.print(f"[red]File not found:[/] {file_path}")
        raise typer.Exit(code=1)

    settings = get_settings()
    db = Database(settings.effective_db_path)
    suppression = (
        AlertSuppressionEngine(cooldown_seconds=suppress_cooldown)
        if suppress_cooldown > 0
        else None
    )
    evaluator = RuleEvaluator(db.list_rules(), suppression_engine=suppression)
    threat_intel = ThreatIntelEngine(db.list_threat_feed_items())
    normalizer = LogNormalizer()

    lines = file_path.read_text(encoding="utf-8").splitlines()
    events = []
    alerts = []

    for line in lines:
        if not line.strip():
            continue
        ev = normalizer.normalize(line, sourcetype=sourcetype, host=host)
        if settings.enable_threat_intel:
            alerts.extend(threat_intel.enrich_event(ev))
        alerts.extend(evaluator.evaluate_event(ev))
        events.append(ev)

    db.save_events_batch(events)
    for a in alerts:
        db.save_alert(a)

    console.print(
        f"[green]Successfully ingested {len(events)} events. Triggered {len(alerts)} alerts.[/]"
    )


# -------------------------------------------------------------
# Generate / Simulate Command
# -------------------------------------------------------------
@app.command(name="generate")
def generate_cmd(
    scenario: Annotated[
        str,
        typer.Option(
            "--scenario",
            "-s",
            help="Attack scenario: brute-force, web-attacks, syslog",
        ),
    ] = "brute-force",
    count: Annotated[
        int,
        typer.Option("--count", "-n", help="Number of log lines to generate"),
    ] = 10,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional output file path")
    ] = None,
) -> None:
    """Generate synthetic log streams for testing SIEM rules and pipelines."""
    generator = LogGenerator()
    try:
        logs = generator.generate_scenario(scenario=scenario, count=count)
    except ValueError as err:
        console.print(f"[red]Error:[/] {err}")
        raise typer.Exit(code=1) from err

    if output:
        output.write_text("\n".join(logs) + "\n", encoding="utf-8")
        console.print(f"[green]Successfully generated {len(logs)} logs to[/] {output}")
    else:
        for log in logs:
            console.print(log)



# -------------------------------------------------------------
# Alerts Subcommands
# -------------------------------------------------------------
@alerts_app.command(name="list")
def list_alerts_cmd(
    limit: Annotated[int, typer.Option("--limit", "-l")] = 50,
) -> None:
    """List recent security alerts."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    alerts = db.list_alerts(limit=limit)

    if not alerts:
        console.print("[yellow]No security alerts recorded.[/]")
        return

    table = Table(title="Triggered SIEM Alerts")
    table.add_column("Alert ID", style="dim")
    table.add_column("Timestamp (UTC)", style="cyan")
    table.add_column("Urgency", style="magenta")
    table.add_column("Rule Name", style="white")
    table.add_column("Source IP", style="green")
    table.add_column("User", style="blue")
    table.add_column("MITRE", style="yellow")
    for a in alerts:
        table.add_row(
            a.alert_id[:8],
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.urgency.value,
            a.rule_name,
            a.src_ip or "-",
            a.user or "-",
            a.mitre_attack_id or "-",
        )
    console.print(table)


# -------------------------------------------------------------
# Rules Subcommands
# -------------------------------------------------------------
@rules_app.command(name="list")
def list_rules_cmd() -> None:
    """List registered correlation and detection rules."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    rules = db.list_rules()

    if not rules:
        console.print("[yellow]No detection rules registered.[/]")
        return

    table = Table(title="SIEM Detection Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Type", style="blue")
    table.add_column("Urgency", style="magenta")
    table.add_column("Threshold", style="yellow")
    table.add_column("MITRE", style="green")
    for r in rules:
        table.add_row(
            r.rule_id,
            r.name,
            r.rule_type.value,
            r.urgency.value,
            f"{r.threshold_count} in {r.time_window_seconds}s"
            if r.rule_type == RuleType.THRESHOLD
            else "-",
            r.mitre_attack_id or "-",
        )
    console.print(table)


# -------------------------------------------------------------
# Threat Intel Subcommands
# -------------------------------------------------------------
@intel_app.command(name="list")
def list_intel_cmd() -> None:
    """List registered IOC indicators."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    items = db.list_threat_feed_items()

    if not items:
        console.print("[yellow]No threat intel indicators loaded.[/]")
        return

    table = Table(title="Threat Intelligence Feed Items")
    table.add_column("Indicator", style="cyan")
    table.add_column("Type", style="blue")
    table.add_column("Threat Actor", style="magenta")
    table.add_column("Confidence", style="yellow")
    table.add_column("Description", style="white")
    for i in items:
        table.add_row(
            i.indicator,
            i.ioc_type.value,
            i.threat_actor or "-",
            f"{i.confidence}%",
            i.description,
        )
    console.print(table)


# -------------------------------------------------------------
# Daemon Server Command
# -------------------------------------------------------------
@app.command(name="serve")
def serve_cmd(
    host: Annotated[str, typer.Option(help="Host address to bind")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port number to bind")] = 8000,
    reload: Annotated[bool, typer.Option(help="Enable hot reloading")] = False,
) -> None:
    """Start the FastAPI control plane daemon."""
    console.print(f"[green]Starting Mini SIEM API Daemon on http://{host}:{port}[/]")
    uvicorn.run("mini_siem.api.app:app", host=host, port=port, reload=reload)
