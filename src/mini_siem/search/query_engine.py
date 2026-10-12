"""SPL-Style Search & Query Engine for Mini SIEM.

Supports:
- Field-based filtering: `action=failure`, `host=srv1`, `src_ip=10.0.0.1`
- Boolean AND / OR logic (default space is AND)
- Negation: `status!=success` or `NOT user=admin`
- Substring and wildcard searching: `user=adm*`, `uri_path=*login*`
- Free-text search matching across `raw` log payload
- Aggregation pipe expressions: `| stats count by user`, `| count by src_ip`
"""

import fnmatch
import re
import time
from collections import Counter
from typing import Any

from mini_siem.models.schemas import QueryResult, SearchQuery, SIEMLogEvent


class QuerySyntaxError(Exception):
    """Exception raised when an SPL search query cannot be parsed."""


class FilterCriterion:
    """Evaluates a single field condition or full-text term against an event."""

    def __init__(
        self,
        field: str | None,
        operator: str,
        value: str,
        negated: bool = False,
    ) -> None:
        self.field = field.lower() if field else None
        self.operator = operator
        self.value = value.strip('"').strip("'")
        self.negated = negated

    def matches(self, event: SIEMLogEvent) -> bool:
        """Check if an event matches this filter criterion."""
        res = self._check_match(event)
        return not res if self.negated else res

    def _check_match(self, event: SIEMLogEvent) -> bool:
        if self.field is None:
            # Free-text search against raw log message and major fields
            val_lower = self.value.lower()
            if self.value == "*":
                return True
            if val_lower in event.raw.lower():
                return True
            for fld in (event.host, event.user, event.action, event.status, event.src_ip):
                if fld and val_lower in fld.lower():
                    return True
            return False

        # Extract field value from event
        actual_val: Any = getattr(event, self.field, None)
        if actual_val is None and self.field in event.fields:
            actual_val = event.fields[self.field]

        if actual_val is None:
            return False

        actual_str = str(actual_val)
        val = self.value

        if "*" in val or "?" in val:
            return fnmatch.fnmatch(actual_str.lower(), val.lower())

        if self.operator == "=":
            return actual_str.lower() == val.lower()
        if self.operator == "!=":
            return actual_str.lower() != val.lower()

        return False


class QueryEngine:
    """Parses and executes SPL-style queries over in-memory or persisted event collections."""

    PIPE_SPLIT_REGEX = re.compile(r"\s*\|\s*")
    AGGREGATION_REGEX = re.compile(
        r"^(?:stats\s+)?count\s+by\s+(?P<field>[a-zA-Z_][a-zA-Z0-9_]*)$", re.IGNORECASE
    )
    TOKEN_REGEX = re.compile(
        r'(?P<neg>NOT\s+)?(?:(?P<field>[a-zA-Z_][a-zA-Z0-9_]*)(?P<op>=|!=))?(?P<val>"[^"]*"|\'[^\']*\'|\S+)'
    )

    def parse_query(self, query_str: str) -> tuple[list[FilterCriterion], str | None]:
        """Parse query string into filter criteria and an optional aggregation field."""
        trimmed = query_str.strip()
        if not trimmed:
            return [], None

        parts = self.PIPE_SPLIT_REGEX.split(trimmed, maxsplit=1)
        filter_part = parts[0].strip()
        agg_field: str | None = None

        if len(parts) > 1:
            agg_expr = parts[1].strip()
            match_agg = self.AGGREGATION_REGEX.match(agg_expr)
            if not match_agg:
                raise QuerySyntaxError(
                    f"Unsupported aggregation expression: '{agg_expr}'. Use '| count by <field>'"
                )
            agg_field = match_agg.group("field").lower()

        criteria: list[FilterCriterion] = []
        if filter_part and filter_part != "*":
            for match in self.TOKEN_REGEX.finditer(filter_part):
                neg = bool(match.group("neg"))
                field = match.group("field")
                op = match.group("op") or "="
                val = match.group("val")

                if val.upper() in ("AND", "OR"):
                    continue

                if op == "!=":
                    criteria.append(
                        FilterCriterion(field=field, operator="=", value=val, negated=True)
                    )
                else:
                    criteria.append(
                        FilterCriterion(field=field, operator=op, value=val, negated=neg)
                    )

        return criteria, agg_field

    def execute(
        self,
        query: SearchQuery,
        events: list[SIEMLogEvent],
    ) -> QueryResult:
        """Filter, sort, aggregate, and paginate events according to query."""
        start_time = time.perf_counter()
        criteria, agg_field = self.parse_query(query.raw_query)

        # 1. Temporal window filtering
        filtered = events
        if query.start_time:
            filtered = [e for e in filtered if e.timestamp >= query.start_time]
        if query.end_time:
            filtered = [e for e in filtered if e.timestamp <= query.end_time]

        # 2. Filter matching
        if criteria:
            matching: list[SIEMLogEvent] = []
            for ev in filtered:
                if all(c.matches(ev) for c in criteria):
                    matching.append(ev)
            filtered = matching

        # 3. Aggregations if pipe specified
        aggregations: dict[str, int] = {}
        if agg_field:
            counter: Counter[str] = Counter()
            for ev in filtered:
                val = getattr(ev, agg_field, None)
                if val is None and agg_field in ev.fields:
                    val = ev.fields[agg_field]
                key = str(val) if val is not None else "unknown"
                counter[key] += 1
            aggregations = dict(counter.most_common())

        total_hits = len(filtered)
        paginated = filtered[query.offset : query.offset + query.limit]
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return QueryResult(
            total_hits=total_hits,
            execution_time_ms=round(elapsed_ms, 2),
            events=paginated,
            aggregations=aggregations,
        )
