"""Internet Health Monitor: debounced status, DNS, latency/loss thresholds."""

from __future__ import annotations

import asyncio

from app.config import Settings
from app.services.internet import InternetHealthMonitor


def _collect(events):
    def emit(type_, severity, title, message, metadata):
        events.append((type_, severity))
    return emit


def _noop_resolve(_key):
    pass


def _run(monitor, hints, events):
    return asyncio.run(monitor.evaluate(hints, _collect(events), _noop_resolve))


def _settings(**kw):
    return Settings(mock=True, internet_check_enabled=False, **kw)


def test_offline_only_after_threshold():
    m = InternetHealthMonitor(_settings(internet_failure_threshold=3))
    events: list = []
    # two failures: still not offline (degraded), no offline event
    _run(m, {"internet_online": False}, events)
    h = _run(m, {"internet_online": False}, events)
    assert h.status == "degraded"
    assert not any(t == "internet.offline" for t, _ in events)
    # third failure crosses the threshold
    h = _run(m, {"internet_online": False}, events)
    assert h.status == "offline"
    assert any(t == "internet.offline" for t, _ in events)


def test_recovered_resolves_after_recovery_threshold():
    m = InternetHealthMonitor(_settings(internet_failure_threshold=1, internet_recovery_threshold=2))
    events: list = []
    _run(m, {"internet_online": False}, events)          # offline immediately
    _run(m, {"internet_online": True}, events)            # 1 healthy — not yet recovered
    assert not any(t == "internet.recovered" for t, _ in events)
    _run(m, {"internet_online": True}, events)            # 2 healthy — recovered
    assert any(t == "internet.recovered" for t, _ in events)


def test_dns_degraded_after_threshold():
    m = InternetHealthMonitor(_settings(dns_failure_threshold=2))
    events: list = []
    _run(m, {"internet_online": True, "dns_online": False}, events)  # 1 fail
    assert not any(t == "dns.degraded" for t, _ in events)
    h = _run(m, {"internet_online": True, "dns_online": False}, events)  # 2 fails
    assert any(t == "dns.degraded" for t, _ in events)
    assert "dns" in h.degraded_reasons


def test_latency_high_requires_repeated_samples():
    m = InternetHealthMonitor(_settings(latency_degraded_ms=100, latency_failure_samples=3))
    events: list = []
    for _ in range(2):
        _run(m, {"internet_online": True, "latency_ms": 150}, events)
    assert not any(t == "internet.latencyHigh" for t, _ in events)
    h = _run(m, {"internet_online": True, "latency_ms": 150}, events)
    assert any(t == "internet.latencyHigh" for t, _ in events)
    assert "latency" in h.degraded_reasons
    assert h.status == "degraded"


def test_packet_loss_requires_repeated_samples():
    m = InternetHealthMonitor(_settings(packet_loss_degraded_percent=5, packet_loss_failure_samples=3))
    events: list = []
    for _ in range(2):
        _run(m, {"internet_online": True, "packet_loss_percent": 25.0}, events)
    assert not any(t == "internet.packetLossHigh" for t, _ in events)
    _run(m, {"internet_online": True, "packet_loss_percent": 25.0}, events)
    assert any(t == "internet.packetLossHigh" for t, _ in events)


def test_router_unreachable_and_recovered():
    m = InternetHealthMonitor(_settings())
    events: list = []
    _run(m, {"internet_online": True, "router_online": True}, events)   # baseline up
    _run(m, {"internet_online": True, "router_online": False}, events)  # down
    assert any(t == "router.unreachable" for t, _ in events)
    _run(m, {"internet_online": True, "router_online": True}, events)   # back up
    assert any(t == "router.recovered" for t, _ in events)


def test_latency_recovery_resolves_open_alert():
    m = InternetHealthMonitor(_settings(latency_degraded_ms=100, latency_failure_samples=2))
    events: list = []
    resolved: list = []
    for _ in range(2):
        asyncio.run(m.evaluate({"internet_online": True, "latency_ms": 150},
                               _collect(events), resolved.append))
    assert any(t == "internet.latencyHigh" for t, _ in events)
    asyncio.run(m.evaluate({"internet_online": True, "latency_ms": 20},
                           _collect(events), resolved.append))
    assert "internet.latencyHigh:internet-latency" in resolved
