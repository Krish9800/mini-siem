"""Unit tests for SPL-style query engine and aggregation filters."""

from datetime import UTC, datetime, timedelta

import pytest

from mini_siem.models.schemas import SearchQuery, SIEMLogEvent
from mini_siem.search.query_engine import QueryEngine, QuerySyntaxError


@pytest.fixture
def sample_events() -> list[SIEMLogEvent]:
    """Sample corpus of SIEM log events for search tests."""
    now = datetime.now(UTC)
    return [
        SIEMLogEvent(
            host="app-01",
            user="alice",
            action="login",
            status="success",
            src_ip="192.168.1.10",
            raw="Successful login for alice from 192.168.1.10",
            timestamp=now - timedelta(seconds=50),
        ),
        SIEMLogEvent(
            host="app-01",
            user="bob",
            action="login",
            status="failure",
            src_ip="192.168.1.20",
            raw="Failed password for bob from 192.168.1.20",
            timestamp=now - timedelta(seconds=40),
        ),
        SIEMLogEvent(
            host="db-01",
            user="bob",
            action="login",
            status="failure",
            src_ip="192.168.1.20",
            raw="Failed password for bob from 192.168.1.20",
            timestamp=now - timedelta(seconds=30),
        ),
        SIEMLogEvent(
            host="db-01",
            user="charlie",
            action="query",
            status="success",
            src_ip="10.0.0.5",
            raw="SELECT * FROM users executed by charlie",
            timestamp=now - timedelta(seconds=20),
        ),
    ]


def test_query_field_exact_match(sample_events: list[SIEMLogEvent]) -> None:
    """Verify exact key=value filtering."""
    engine = QueryEngine()
    query = SearchQuery(raw_query="action=login status=failure")
    res = engine.execute(query, sample_events)

    assert res.total_hits == 2
    assert all(e.user == "bob" for e in res.events)


def test_query_wildcard_matching(sample_events: list[SIEMLogEvent]) -> None:
    """Verify wildcard matching in field values."""
    engine = QueryEngine()
    query = SearchQuery(raw_query="host=app* user=*li*")
    res = engine.execute(query, sample_events)

    assert res.total_hits == 1
    assert res.events[0].user == "alice"


def test_query_negation(sample_events: list[SIEMLogEvent]) -> None:
    """Verify != and NOT negation in filters."""
    engine = QueryEngine()
    query = SearchQuery(raw_query="status!=failure NOT user=alice")
    res = engine.execute(query, sample_events)

    assert res.total_hits == 1
    assert res.events[0].user == "charlie"


def test_query_free_text_search(sample_events: list[SIEMLogEvent]) -> None:
    """Verify free-text search matching in raw payloads."""
    engine = QueryEngine()
    query = SearchQuery(raw_query="SELECT users")
    res = engine.execute(query, sample_events)

    assert res.total_hits == 1
    assert res.events[0].user == "charlie"


def test_query_aggregation_pipe(sample_events: list[SIEMLogEvent]) -> None:
    """Verify SPL aggregation pipe e.g. '| stats count by user'."""
    engine = QueryEngine()
    query = SearchQuery(raw_query="action=login | count by user")
    res = engine.execute(query, sample_events)

    assert res.total_hits == 3
    assert res.aggregations["bob"] == 2
    assert res.aggregations["alice"] == 1


def test_query_syntax_error_invalid_pipe() -> None:
    """Verify QuerySyntaxError on malformed pipe expressions."""
    engine = QueryEngine()
    with pytest.raises(QuerySyntaxError, match="Unsupported aggregation"):
        engine.parse_query("host=srv1 | top 10 users")
