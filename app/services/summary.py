"""Summary service — the compact, dashboard-shaped rollup of everything.

This is what ``GET /summary`` returns and what catosservice folds into the house
dashboard / the CatOS Home widget. Pure assembly over the live store; cheap to
call on every request.

Sprint 2 adds graded internet health, WiFi quality and a small set of trend hints
(recent instability, last outage, weak-client count, an overall health score) so
CatOS can say *"network healthy / unstable / needs attention"* at a glance.
"""

from __future__ import annotations

from typing import Optional

from ..models import InternetHealthStatus, WifiQualitySummary, now
from ..store import LiveStore
from .metrics import MetricsService
from .presence import PresenceResolver


def build_summary(
    live: LiveStore,
    metrics: MetricsService,
    presence: PresenceResolver,
    internet: Optional[InternetHealthStatus],
    wifi: Optional[WifiQualitySummary],
    last_outage_at: Optional[float] = None,
) -> dict:
    devices = live.device_list()
    online = [d for d in devices if d.is_online]
    unknown = [d for d in online if not d.is_known and not d.ignored]
    guests = [d for d in online if d.trust_level == "guest"]
    alerts = live.alerts()
    last_event = live.events[0] if live.events else None

    internet_status = internet.status if internet else _legacy_internet_status(live)
    wifi_status = wifi.status if wifi else "unknown"
    weak_clients = wifi.weak_client_count if wifi else 0
    trend = _wifi_quality_trend(live)
    score = _health_score(internet, wifi, alerts)

    return {
        "generated_at": now(),
        "devices": {
            "online": len(online),
            "known": sum(1 for d in online if d.is_known),
            "unknown": len(unknown),
            "guests": len(guests),
            "total_tracked": len(devices),
        },
        "presence": {
            "home_count": presence.home_count(),
        },
        "internet": {
            "status": internet_status,
            "quality": internet.quality if internet else "unknown",
            "latency_ms": internet.latency_ms if internet else metrics.latest("internet.latencyMs"),
            "jitter_ms": internet.jitter_ms if internet else None,
            "packet_loss_percent": internet.packet_loss_percent if internet else None,
            "dns_ok": internet.dns_ok if internet else live.dns_online,
            "download_mbps": metrics.latest("internet.downloadMbps"),
            "upload_mbps": metrics.latest("internet.uploadMbps"),
            "degraded_reasons": internet.degraded_reasons if internet else [],
        },
        "wifi": {
            "status": wifi_status,
            "health": _wifi_health_compat(wifi_status),
            "quality": wifi.quality if wifi else "unknown",
            "client_count": wifi.client_count if wifi else 0,
            "weak_client_count": weak_clients,
            "critical_client_count": wifi.critical_client_count if wifi else 0,
            "worst_rssi": _worst_rssi(wifi),
        },
        "router": {
            "status": "healthy" if live.router_online else (
                "unknown" if live.router_online is None else "error"),
            "cpu_percent": metrics.latest("router.cpuPercent"),
            "memory_percent": metrics.latest("router.memoryPercent"),
            "uptime_seconds": metrics.latest("router.uptimeSeconds"),
        },
        "alerts": {
            "active": len(alerts),
            "critical": sum(1 for a in alerts if a.severity == "critical"),
        },
        "trends": {
            "internet_recently_unstable": _recently_unstable(live),
            "internet_last_outage_at": last_outage_at,
            "wifi_weak_clients": weak_clients,
            "wifi_quality_trend": trend,
            "network_health_score": score,
        },
        "network_health_score": score,
        "last_event": last_event.model_dump() if last_event else None,
        "top_bandwidth": metrics.top_bandwidth(),
    }


def _legacy_internet_status(live: LiveStore) -> str:
    if live.internet_online is False:
        return "offline"
    if live.internet_online is None:
        return "unknown"
    return "online"


def _wifi_health_compat(status: str) -> str:
    # keep the old summary.wifi.health vocabulary (good/fair/poor) alive for any
    # existing consumer; map the richer status onto it.
    return {"good": "good", "fair": "fair", "poor": "poor", "critical": "poor"}.get(status, "unknown")


def _worst_rssi(wifi: Optional[WifiQualitySummary]) -> Optional[int]:
    if not wifi or not wifi.worst_clients:
        return None
    rssis = [c.rssi for c in wifi.worst_clients if c.rssi is not None]
    return min(rssis) if rssis else None


def _recently_unstable(live: LiveStore, window: int = 20) -> bool:
    # unstable if the last `window` health samples saw any offline/degraded.
    bad = 0
    for i, s in enumerate(live.health_history):
        if i >= window:
            break
        if s.internet_status in ("offline", "degraded"):
            bad += 1
    return bad >= 2


def _wifi_quality_trend(live: LiveStore, window: int = 10) -> str:
    # compare recent vs older weak-client counts to read improving/worsening.
    samples = list(live.health_history)[:window * 2]
    if len(samples) < 4:
        return "stable"
    recent = samples[: len(samples) // 2]
    older = samples[len(samples) // 2:]
    r = sum(s.wifi_weak_client_count for s in recent) / max(1, len(recent))
    o = sum(s.wifi_weak_client_count for s in older) / max(1, len(older))
    if r < o - 0.5:
        return "improving"
    if r > o + 0.5:
        return "worsening"
    return "stable"


def _health_score(internet, wifi, alerts) -> int:
    """0-100 overall network health. Starts at 100, subtracts for problems."""
    score = 100
    if internet:
        if internet.status == "offline":
            score -= 60
        elif internet.status == "degraded":
            score -= 25
        elif internet.status == "unknown":
            score -= 5
        score -= 10 * len(internet.degraded_reasons)
    if wifi:
        score -= 8 * wifi.critical_client_count
        score -= 4 * (wifi.weak_client_count - wifi.critical_client_count)
    score -= 10 * sum(1 for a in alerts if a.severity == "critical")
    score -= 3 * sum(1 for a in alerts if a.severity == "warning")
    return max(0, min(100, score))
