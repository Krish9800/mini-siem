"""Unit tests for threat intelligence feed enrichment."""

from mini_siem.intel.threat_intel import ThreatIntelEngine
from mini_siem.models.enums import AlertUrgency, IOCType
from mini_siem.models.schemas import SIEMLogEvent, ThreatFeedItem


def test_threat_intel_exact_ip_match() -> None:
    """Verify exact IPv4 threat intel matching and event tagging."""
    item = ThreatFeedItem(
        indicator="198.51.100.99",
        ioc_type=IOCType.IPV4,
        threat_actor="APT28",
        description="Known FancyBear C2 Node",
        confidence=95,
    )
    engine = ThreatIntelEngine([item])

    ev = SIEMLogEvent(
        host="web-gateway",
        src_ip="198.51.100.99",
        action="connect",
    )

    alerts = engine.enrich_event(ev)
    assert ev.is_ioc_hit is True
    assert "APT28:198.51.100.99" in ev.ioc_tags
    assert len(alerts) == 1
    assert alerts[0].urgency == AlertUrgency.CRITICAL
    assert "FancyBear" in alerts[0].description


def test_threat_intel_cidr_subnet_match() -> None:
    """Verify CIDR block range matching for IP addresses."""
    item = ThreatFeedItem(
        indicator="203.0.113.0/24",
        ioc_type=IOCType.CIDR,
        threat_actor="CobaltStrike-Pool",
        confidence=85,
    )
    engine = ThreatIntelEngine([item])

    # In-range IP
    ev1 = SIEMLogEvent(src_ip="203.0.113.45")
    alerts1 = engine.enrich_event(ev1)
    assert ev1.is_ioc_hit is True
    assert len(alerts1) == 1
    assert alerts1[0].urgency == AlertUrgency.HIGH

    # Out-of-range IP
    ev2 = SIEMLogEvent(src_ip="192.168.1.1")
    alerts2 = engine.enrich_event(ev2)
    assert ev2.is_ioc_hit is False
    assert len(alerts2) == 0


def test_threat_intel_domain_match() -> None:
    """Verify malicious domain query matching."""
    item = ThreatFeedItem(
        indicator="evil-phish.com",
        ioc_type=IOCType.DOMAIN,
        threat_actor="FIN7",
        confidence=90,
    )
    engine = ThreatIntelEngine([item])

    ev = SIEMLogEvent(fields={"domain": "evil-phish.com"})
    alerts = engine.enrich_event(ev)
    assert ev.is_ioc_hit is True
    assert len(alerts) == 1


def test_threat_intel_remove_item() -> None:
    """Verify IOC indicator removal."""
    item = ThreatFeedItem(indicator="1.2.3.4", ioc_type=IOCType.IPV4)
    engine = ThreatIntelEngine([item])
    assert engine.check_indicator("1.2.3.4") is not None

    engine.remove_item("1.2.3.4")
    assert engine.check_indicator("1.2.3.4") is None
