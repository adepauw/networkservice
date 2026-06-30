"""Metrics service — records source metrics into the ring buffer and answers
simple aggregate queries (latest value, top bandwidth).

WiFi-quality assessment moved to ``services/wifi.py`` (the WiFi Quality Coach) in
Sprint 2; this module is now purely about metric storage + lookups.
"""

from __future__ import annotations

from ..config import Settings
from ..models import NetworkMetric
from ..store import LiveStore


class MetricsService:
    def __init__(self, settings: Settings, live: LiveStore) -> None:
        self.settings = settings
        self.live = live

    def record(self, metrics: list[NetworkMetric]) -> None:
        for m in metrics:
            self.live.append_metric(m)

    def top_bandwidth(self, limit: int = 3) -> list[dict]:
        """Most recent per-device rx volume — the 'top traffic' card."""
        latest: dict[str, NetworkMetric] = {}
        for m in self.live.metrics:
            if m.type == "device.rxBytes" and m.device_id and m.device_id not in latest:
                latest[m.device_id] = m
        ranked = sorted(latest.values(), key=lambda m: m.value, reverse=True)[:limit]
        out = []
        for m in ranked:
            dev = self.live.device(m.device_id) if m.device_id else None
            out.append({"device_id": m.device_id,
                        "name": dev.name if dev else m.device_id,
                        "rx_bytes": m.value})
        return out

    def latest(self, metric_type: str) -> float | None:
        for m in self.live.metrics:
            if m.type == metric_type:
                return m.value
        return None
