"""DNS source adapter seam — unconfigured empty state + mock summary counts."""

from __future__ import annotations

import asyncio

from app.config import Settings, SourceConfig
from app.models import DnsSourceStatus
from app.services.dns import DnsService
from app.sources.dns import AdGuardSourceAdapter


def _mock_adguard() -> AdGuardSourceAdapter:
    cfg = SourceConfig(id="agh", type="adguard", display_name="AdGuard",
                       options={"mock": True})
    return AdGuardSourceAdapter(cfg, Settings())


def test_dns_unavailable_returns_configured_disabled_state():
    svc = DnsService(Settings(dns_enabled=False))
    summary = svc.build_summary([], [], {})
    assert summary.configured is False
    assert summary.protection_status == "unconfigured"


def test_dns_mock_summary_returns_expected_counts():
    adapter = _mock_adguard()
    snap = asyncio.run(adapter.poll())
    assert snap.dns is not None and snap.dns.query_count > 0

    statuses = {"agh": DnsSourceStatus(id="agh", type="adguard", display_name="AdGuard",
                                       status="ok", protection_enabled=True)}
    svc = DnsService(Settings(dns_enabled=True))
    summary = svc.build_summary([snap], [], statuses)
    assert summary.configured is True
    assert summary.protection_status == "active"
    assert summary.query_count == snap.dns.query_count
    assert summary.blocked_count == snap.dns.blocked_count
    assert summary.top_devices  # per-device breakdown present
    assert 0 <= summary.blocked_percent <= 100


def test_dns_degraded_when_protection_off():
    cfg = SourceConfig(id="agh", type="adguard", display_name="AdGuard", options={"mock": True})
    adapter = AdGuardSourceAdapter(cfg, Settings())
    snap = asyncio.run(adapter.poll())
    snap.dns.protection_enabled = False
    statuses = {"agh": DnsSourceStatus(id="agh", type="adguard", display_name="AdGuard",
                                       status="ok", protection_enabled=False)}
    summary = DnsService(Settings(dns_enabled=True)).build_summary([snap], [], statuses)
    assert summary.protection_status == "degraded"
