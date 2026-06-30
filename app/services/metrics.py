"""Metrics service — records source metrics into the ring buffer and derives the
WiFi-health view (which drives both the summary and the wifi.signalPoor events).

Poor-WiFi alerting is debounced: a device must read below the RSSI threshold for
``poor_rssi_samples`` consecutive polls before it counts as poor — a single bad
sample (a phone in a pocket for one tick) shouldn't alert.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import Settings
from ..models import EventType, NetworkDevice, NetworkMetric, now
from ..store import LiveStore


class MetricsService:
    def __init__(self, settings: Settings, live: LiveStore) -> None:
        self.settings = settings
        self.live = live
        self._bad_rssi_streak: dict[str, int] = defaultdict(int)

    def record(self, metrics: list[NetworkMetric]) -> None:
        for m in metrics:
            self.live.append_metric(m)

    def evaluate_wifi(self, devices: list[NetworkDevice], emit) -> dict:
        """Return a WiFi-health summary and emit debounced poor-signal events."""
        poor: list[dict] = []
        wifi_clients = 0
        worst_rssi: int | None = None
        worst_device: str | None = None

        for dev in devices:
            if not dev.is_online or not dev.interfaces:
                continue
            iface = dev.interfaces[0]
            if iface.connection_type != "wifi":
                continue
            wifi_clients += 1
            # Some sources (e.g. the GL.iNet API) don't report per-client RSSI;
            # still count the client, just skip the signal-quality assessment.
            if iface.rssi is None:
                continue
            if worst_rssi is None or iface.rssi < worst_rssi:
                worst_rssi, worst_device = iface.rssi, dev.name

            if iface.rssi <= self.settings.poor_rssi_dbm:
                self._bad_rssi_streak[dev.id] += 1
                if self._bad_rssi_streak[dev.id] == self.settings.poor_rssi_samples:
                    emit(EventType.WIFI_SIGNAL_POOR.value, "warning",
                         f"Zwak WiFi-signaal: {dev.name}",
                         f"{iface.rssi} dBm op {iface.band} ({iface.ssid or '?'})",
                         dev, {"rssi": iface.rssi, "band": iface.band})
                if self._bad_rssi_streak[dev.id] >= self.settings.poor_rssi_samples:
                    poor.append({"device_id": dev.id, "name": dev.name,
                                 "rssi": iface.rssi, "band": iface.band})
            else:
                self._bad_rssi_streak[dev.id] = 0

        health = "good"
        if worst_rssi is not None and worst_rssi <= self.settings.poor_rssi_dbm:
            health = "poor" if poor else "fair"
        return {
            "health": health,
            "client_count": wifi_clients,
            "poor_devices": poor,
            "worst_rssi": worst_rssi,
            "worst_device": worst_device,
        }

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
