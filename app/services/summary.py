"""Summary service — the compact, dashboard-shaped rollup of everything.

This is what ``GET /summary`` returns and what catosservice folds into the house
dashboard / the CatOS Home widget. Pure assembly over the live store; cheap to
call on every request.
"""

from __future__ import annotations

from ..models import now
from ..store import LiveStore
from .metrics import MetricsService
from .presence import PresenceResolver


def _internet_status(live: LiveStore) -> str:
    if live.internet_online is False:
        return "offline"
    if live.internet_online is None:
        return "unknown"
    # degraded if latency metric is high
    return "online"


def build_summary(
    live: LiveStore,
    metrics: MetricsService,
    presence: PresenceResolver,
    wifi: dict,
) -> dict:
    devices = live.device_list()
    online = [d for d in devices if d.is_online]
    unknown = [d for d in online if not d.is_known and d.trust_level != "ignored"]
    guests = [d for d in online if d.trust_level == "guest"]
    alerts = live.alerts()
    last_event = live.events[0] if live.events else None

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
            "status": _internet_status(live),
            "latency_ms": metrics.latest("internet.latencyMs"),
            "download_mbps": metrics.latest("internet.downloadMbps"),
            "upload_mbps": metrics.latest("internet.uploadMbps"),
        },
        "wifi": {
            "health": wifi.get("health", "unknown"),
            "client_count": wifi.get("client_count", 0),
            "worst_rssi": wifi.get("worst_rssi"),
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
        "last_event": last_event.model_dump() if last_event else None,
        "top_bandwidth": metrics.top_bandwidth(),
    }
