"""Traffic insights — pragmatic, not a NetFlow system.

We work with whatever counters the sources already give us: per-device rx/tx byte
metrics (``device.rxBytes`` / ``device.txBytes``) and the internet up/down rate
metrics. From those we build a compact "who used the most" rollup plus a current
throughput read, and flag a device as *unusual* only when it crosses a
conservative, configurable threshold (so normal streaming/downloads stay quiet).

If a source can't break traffic down per device, we say so honestly
(``history_available=False`` / empty top lists) rather than inventing numbers.
"""

from __future__ import annotations

import uuid

from ..config import Settings
from ..models import (
    NetworkDevice,
    NetworkMetric,
    TrafficDeviceStats,
    TrafficSample,
    TrafficSummary,
    now,
)
from ..store import LiveStore


class TrafficService:
    def __init__(self, settings: Settings, live: LiveStore) -> None:
        self.settings = settings
        self.live = live

    # --- aggregation ----------------------------------------------------------
    def _device_stats(self, period: str = "current") -> list[TrafficDeviceStats]:
        """One TrafficDeviceStats per device we have byte counters for.

        ``device.rxBytes`` / ``device.txBytes`` are per-poll byte deltas, so the
        *latest* sample over the poll interval gives an honest current bps, and
        summing the recent window gives a rolling volume.
        """
        interval = max(1, self.settings.poll_interval_seconds)
        # window of samples to roll up: ~last hour at the configured poll rate,
        # bounded so a fast poll doesn't scan the whole buffer.
        window = min(3600 // interval + 1, 240)
        rx: dict[str, list[float]] = {}
        tx: dict[str, list[float]] = {}
        for m in self.live.metrics:
            if m.device_id is None:
                continue
            if m.type == "device.rxBytes":
                rx.setdefault(m.device_id, []).append(m.value)
            elif m.type == "device.txBytes":
                tx.setdefault(m.device_id, []).append(m.value)

        out: list[TrafficDeviceStats] = []
        for did in set(rx) | set(tx):
            rx_samples = rx.get(did, [])[:window]
            tx_samples = tx.get(did, [])[:window]
            dev = self.live.device(did)
            rx_total = sum(rx_samples)
            tx_total = sum(tx_samples)
            dl_bps = (rx_samples[0] * 8 / interval) if rx_samples else None
            ul_bps = (tx_samples[0] * 8 / interval) if tx_samples else None
            unusual = bool(
                (dl_bps is not None and dl_bps >= self.settings.traffic_high_usage_threshold_bps)
                or (ul_bps is not None and ul_bps >= self.settings.traffic_unusual_upload_threshold_bps)
            )
            out.append(TrafficDeviceStats(
                device_id=did,
                display_name=dev.name if dev else did,
                rx_bytes=rx_total, tx_bytes=tx_total,
                download_bps=dl_bps, upload_bps=ul_bps,
                total_bytes=rx_total + tx_total,
                period=period, is_unusual=unusual,
            ))
        return out

    def build_summary(self, limit: int = 10, period: str = "current") -> TrafficSummary:
        if not self.settings.traffic_enabled:
            return TrafficSummary(period=period, history_available=False, source=None,
                                  metadata={"enabled": False})
        stats = self._device_stats(period)
        history_available = len(self.live.traffic_history) > 1
        if not stats:
            return TrafficSummary(
                period=period, history_available=history_available, source=None,
                metadata={"reason": "no per-device traffic counters from this source"})

        by_dl = sorted(stats, key=lambda s: (s.download_bps or 0, s.rx_bytes), reverse=True)
        by_ul = sorted(stats, key=lambda s: (s.upload_bps or 0, s.tx_bytes), reverse=True)
        for rank, s in enumerate(by_dl, 1):
            s.rank = rank
        total_rx = sum(s.rx_bytes for s in stats)
        total_tx = sum(s.tx_bytes for s in stats)
        cur_dl = sum(s.download_bps or 0 for s in stats) or None
        cur_ul = sum(s.upload_bps or 0 for s in stats) or None
        unusual = [s for s in by_dl if s.is_unusual][:limit]
        return TrafficSummary(
            total_rx_bytes=total_rx, total_tx_bytes=total_tx,
            current_download_bps=cur_dl, current_upload_bps=cur_ul,
            top_download_devices=by_dl[:limit],
            top_upload_devices=[s for s in by_ul if (s.upload_bps or s.tx_bytes)][:limit],
            unusual_devices=unusual,
            period=period, history_available=history_available,
            source="metrics",
        )

    def device_stats(self, device_id: str, period: str = "current") -> TrafficDeviceStats | None:
        return next((s for s in self._device_stats(period) if s.device_id == device_id), None)

    # --- history --------------------------------------------------------------
    def record_sample(self, summary: TrafficSummary) -> None:
        if not self.settings.traffic_enabled:
            return
        top = summary.top_download_devices[0].device_id if summary.top_download_devices else None
        self.live.append_traffic_sample(TrafficSample(
            id=f"ts_{uuid.uuid4().hex[:10]}",
            total_rx_bytes=summary.total_rx_bytes,
            total_tx_bytes=summary.total_tx_bytes,
            current_download_bps=summary.current_download_bps,
            current_upload_bps=summary.current_upload_bps,
            top_device_id=top,
        ))


def device_metrics(devices: list[NetworkDevice]) -> list[NetworkMetric]:  # pragma: no cover
    """Reserved seam: synthesize traffic metrics from device interface counters
    for sources that expose rates but not byte metrics. Unused today."""
    return []
