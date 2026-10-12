"""Threat Intelligence Feed Enrichment Engine for Mini SIEM.

Enriches incoming SIEMLogEvents against indicators of compromise (IOCs):
- IPv4 address exact matches
- CIDR block subnet membership (e.g. 198.51.100.0/24)
- Suspicious and malicious domain names
- Cryptographic file hashes (SHA-256)

Attaches threat scores, actor tags, and generates enrichment alerts.
"""

import ipaddress

from mini_siem.models.enums import AlertUrgency, IOCType
from mini_siem.models.schemas import SIEMAlert, SIEMLogEvent, ThreatFeedItem


class ThreatIntelEngine:
    """In-memory threat intelligence database and real-time enrichment correlator."""

    def __init__(self, feed_items: list[ThreatFeedItem] | None = None) -> None:
        self.exact_iocs: dict[str, ThreatFeedItem] = {}  # Normalized indicator -> item
        self.cidr_networks: list[
            tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatFeedItem]
        ] = []

        if feed_items:
            for item in feed_items:
                self.add_item(item)

    def add_item(self, item: ThreatFeedItem) -> None:
        """Register an IOC item into database."""
        val = item.indicator.strip().lower()
        if item.ioc_type == IOCType.CIDR:
            try:
                net = ipaddress.ip_network(val, strict=False)
                self.cidr_networks.append((net, item))
            except ValueError:
                pass
        else:
            self.exact_iocs[val] = item

    def remove_item(self, indicator: str) -> None:
        """Remove indicator from exact match and CIDR lists."""
        val = indicator.strip().lower()
        self.exact_iocs.pop(val, None)
        self.cidr_networks = [
            (net, item) for net, item in self.cidr_networks if item.indicator.lower() != val
        ]

    def check_indicator(self, indicator: str) -> ThreatFeedItem | None:
        """Query if a given indicator (IP, domain, hash) is an IOC hit."""
        val = indicator.strip().lower()

        # 1. Exact string match
        if val in self.exact_iocs:
            return self.exact_iocs[val]

        # 2. Check if valid IP falling into a known CIDR network
        try:
            ip_obj = ipaddress.ip_address(val)
            for net, item in self.cidr_networks:
                if ip_obj in net:
                    return item
        except ValueError:
            pass

        return None

    def enrich_event(self, event: SIEMLogEvent) -> list[SIEMAlert]:
        """Enrich event fields with IOC context and return alerts on hit."""
        alerts: list[SIEMAlert] = []
        hits: list[ThreatFeedItem] = []

        # Check source IP
        if event.src_ip:
            hit = self.check_indicator(event.src_ip)
            if hit:
                hits.append(hit)

        # Check destination IP
        if event.dst_ip:
            hit = self.check_indicator(event.dst_ip)
            if hit:
                hits.append(hit)

        # Check URI path / domains in event fields
        domain_fld = event.fields.get("domain") or event.fields.get("query_name")
        if domain_fld:
            hit = self.check_indicator(str(domain_fld))
            if hit:
                hits.append(hit)

        if hits:
            event.is_ioc_hit = True
            for h in hits:
                tag = f"{h.threat_actor or 'unknown'}:{h.indicator}"
                if tag not in event.ioc_tags:
                    event.ioc_tags.append(tag)

                urgency = AlertUrgency.HIGH if h.confidence >= 80 else AlertUrgency.MEDIUM
                if h.confidence >= 95:
                    urgency = AlertUrgency.CRITICAL

                alerts.append(
                    SIEMAlert(
                        rule_name=f"Threat Intel Hit: {h.indicator}",
                        urgency=urgency,
                        description=(
                            f"Event matched threat feed item '{h.indicator}' "
                            f"(Actor: {h.threat_actor or 'N/A'}, Confidence: {h.confidence}%). "
                            f"{h.description}"
                        ),
                        target_host=event.host,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        user=event.user,
                        trigger_count=1,
                        mitre_attack_id="T1071",  # Application Layer Protocol C2
                        sample_events=[event.event_id],
                    )
                )

        return alerts
