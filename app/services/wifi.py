"""WiFi Quality Coach — turns per-client RSSI into actionable quality verdicts.

Not just a dBm readout: each WiFi client is bucketed (excellent…critical), the
whole network is rolled up into a ``WifiQualitySummary`` with human-readable
recommendations, and debounced events fire only when a device's quality actually
changes or crosses a threshold.

Degrades gracefully: a source that doesn't report per-client RSSI (e.g. the
GL.iNet API) still yields client/band counts, just with ``unknown`` quality and a
"no signal data" recommendation rather than false alarms. Ignored devices are
excluded entirely — the user told us not to care.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import Settings
from ..models import (
    EventType,
    NetworkDevice,
    WifiClientQuality,
    WifiQualitySummary,
    now,
)

# group labels considered "weak" (alert-worthy) vs "healthy" (recovery-worthy).
_WEAK = {"poor", "critical"}
_HEALTHY = {"excellent", "good", "fair"}


def client_quality(rssi: int | None, poor_dbm: int, critical_dbm: int) -> str:
    if rssi is None:
        return "unknown"
    if rssi < critical_dbm:
        return "critical"
    if rssi <= poor_dbm:
        return "poor"
    if rssi <= -68:
        return "fair"
    if rssi <= -56:
        return "good"
    return "excellent"


def wifi_clients(devices: list[NetworkDevice], settings: Settings) -> list[WifiClientQuality]:
    """Build the per-device WiFi quality list (read-only, no events/streaks).

    Used by ``GET /wifi/clients`` so a request never perturbs the coach's debounce
    state. Ignored devices are excluded.
    """
    out: list[WifiClientQuality] = []
    for dev in devices:
        if dev.ignored or not dev.is_online or not dev.interfaces:
            continue
        iface = dev.interfaces[0]
        if iface.connection_type != "wifi":
            continue
        q = client_quality(iface.rssi, settings.poor_rssi_dbm, settings.wifi_critical_rssi_dbm)
        out.append(WifiClientQuality(
            device_id=dev.id, name=dev.name, quality=q,  # type: ignore[arg-type]
            rssi=iface.rssi, signal_quality=iface.signal_quality, band=iface.band,
            channel=iface.channel, ssid=iface.ssid,
            tx_rate_mbps=iface.tx_rate_mbps, rx_rate_mbps=iface.rx_rate_mbps,
            last_seen_at=iface.last_seen_at, role=dev.role,
            recommendation=_client_recommendation(dev.name, q, iface.band),
        ))
    out.sort(key=lambda c: (c.rssi if c.rssi is not None else 0))
    return out


class WifiQualityCoach:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._weak_streak: dict[str, int] = defaultdict(int)
        self._good_streak: dict[str, int] = defaultdict(int)
        self._committed: dict[str, str] = {}   # device_id -> committed quality
        self._poor_alerted: set[str] = set()    # devices with an open poor/critical alert
        self._too_many_alerted = False
        self.last: WifiQualitySummary | None = None

    def evaluate(self, devices: list[NetworkDevice], emit) -> WifiQualitySummary:
        s = self.settings
        t = now()
        clients: list[WifiClientQuality] = []
        bands: dict[str, int] = defaultdict(int)
        channels: dict[str, int] = defaultdict(int)
        any_rssi = False

        for dev in devices:
            if dev.ignored or not dev.is_online or not dev.interfaces:
                continue
            iface = dev.interfaces[0]
            if iface.connection_type != "wifi":
                continue
            q = client_quality(iface.rssi, s.poor_rssi_dbm, s.wifi_critical_rssi_dbm)
            if iface.rssi is not None:
                any_rssi = True
            bands[iface.band] += 1
            if iface.channel is not None:
                channels[str(iface.channel)] += 1
            cq = WifiClientQuality(
                device_id=dev.id, name=dev.name, quality=q,  # type: ignore[arg-type]
                rssi=iface.rssi, signal_quality=iface.signal_quality, band=iface.band,
                channel=iface.channel, ssid=iface.ssid,
                tx_rate_mbps=iface.tx_rate_mbps, rx_rate_mbps=iface.rx_rate_mbps,
                last_seen_at=iface.last_seen_at, role=dev.role,
                recommendation=_client_recommendation(dev.name, q, iface.band),
            )
            clients.append(cq)
            self._track(dev, q, emit)

        weak = [c for c in clients if c.quality in _WEAK]
        critical = [c for c in clients if c.quality == "critical"]
        worst = sorted(
            [c for c in clients if c.rssi is not None],
            key=lambda c: c.rssi,  # type: ignore[arg-type,return-value]
        )[:5]

        self._eval_too_many_weak(len(weak), emit)

        status, quality = _aggregate_status(clients, weak, critical, any_rssi)
        summary = WifiQualitySummary(
            status=status, quality=quality, checked_at=t,  # type: ignore[arg-type]
            client_count=len(clients), weak_client_count=len(weak),
            critical_client_count=len(critical),
            bands=dict(bands), channels=dict(channels), worst_clients=worst,
            recommendations=_aggregate_recommendations(clients, weak, bands, any_rssi),
        )
        self.last = summary
        return summary

    # --- per-device debounced events -----------------------------------------
    def _track(self, dev: NetworkDevice, q: str, emit) -> None:
        s = self.settings
        did = dev.id
        weak = q in _WEAK
        if weak:
            self._weak_streak[did] += 1
            self._good_streak[did] = 0
            if self._weak_streak[did] == s.wifi_poor_sample_threshold:
                if q == "critical":
                    emit(EventType.WIFI_SIGNAL_CRITICAL.value, "warning",
                         f"Kritiek WiFi-signaal: {dev.name}",
                         _client_recommendation(dev.name, q, dev.interfaces[0].band),
                         dev, {"rssi": dev.interfaces[0].rssi, "band": dev.interfaces[0].band, "role": dev.role})
                else:
                    emit(EventType.WIFI_SIGNAL_POOR.value, "warning",
                         f"Zwak WiFi-signaal: {dev.name}",
                         _client_recommendation(dev.name, q, dev.interfaces[0].band),
                         dev, {"rssi": dev.interfaces[0].rssi, "band": dev.interfaces[0].band, "role": dev.role})
                self._poor_alerted.add(did)
        elif q in _HEALTHY:
            self._good_streak[did] += 1
            self._weak_streak[did] = 0
            if did in self._poor_alerted and self._good_streak[did] >= s.wifi_recovery_sample_threshold:
                emit(EventType.WIFI_SIGNAL_RECOVERED.value, "success",
                     f"WiFi-signaal hersteld: {dev.name}", None, dev, {"role": dev.role})
                self._poor_alerted.discard(did)
        # client quality bucket change (info) — committed only once it's stable
        self._maybe_commit(dev, q, emit)

    def _maybe_commit(self, dev: NetworkDevice, q: str, emit) -> None:
        s = self.settings
        did = dev.id
        stable = (
            q == "unknown"
            or (q in _WEAK and self._weak_streak[did] >= s.wifi_poor_sample_threshold)
            or (q in _HEALTHY and self._good_streak[did] >= s.wifi_recovery_sample_threshold)
        )
        if not stable:
            return
        prev = self._committed.get(did)
        if prev is not None and prev != q:
            emit(EventType.WIFI_CLIENT_QUALITY_CHANGED.value, "info",
                 f"WiFi-kwaliteit gewijzigd: {dev.name}", f"{prev} → {q}",
                 dev, {"from": prev, "to": q, "role": dev.role})
        self._committed[did] = q

    def _eval_too_many_weak(self, weak_count: int, emit) -> None:
        if weak_count >= self.settings.wifi_too_many_weak_clients:
            if not self._too_many_alerted:
                emit(EventType.WIFI_TOO_MANY_WEAK_CLIENTS.value, "warning",
                     "Veel toestellen met zwak WiFi-signaal",
                     f"{weak_count} toestellen hebben zwak of kritiek signaal", None,
                     {"mac": "wifi", "weak_count": weak_count})
                self._too_many_alerted = True
        else:
            if self._too_many_alerted:
                # shared "mac" suffix lets the engine resolve the open alert.
                emit(EventType.WIFI_WEAK_CLIENTS_RECOVERED.value, "success",
                     "WiFi-signaal breed hersteld",
                     "Het aantal zwakke WiFi-clients is weer normaal", None,
                     {"mac": "wifi", "weak_count": weak_count})
            self._too_many_alerted = False


def _client_recommendation(name: str, quality: str, band: str) -> str | None:
    if quality == "critical":
        return f"{name} heeft kritiek WiFi-signaal — staat waarschijnlijk te ver van de router"
    if quality == "poor":
        extra = " (2.4 GHz)" if band == "2.4ghz" else ""
        return f"{name} heeft zwak WiFi-signaal{extra}"
    return None


def _aggregate_status(clients, weak, critical, any_rssi):
    if not clients:
        return "unknown", "unknown"
    if not any_rssi:
        # clients present but no signal data from this source
        return "unknown", "unknown"
    if critical:
        return "critical", "poor"
    if weak:
        return "poor", "fair"
    # any fair clients → fair, else good
    if any(c.quality == "fair" for c in clients):
        return "fair", "good"
    return "good", "excellent"


def _aggregate_recommendations(clients, weak, bands, any_rssi) -> list[str]:
    recs: list[str] = []
    if clients and not any_rssi:
        recs.append("Geen WiFi-signaaldata beschikbaar via deze bron")
        return recs
    for c in sorted(weak, key=lambda c: (c.rssi if c.rssi is not None else 0))[:3]:
        if c.recommendation:
            recs.append(c.recommendation)
    on_24 = bands.get("2.4ghz", 0)
    if on_24 >= 4 and on_24 >= sum(bands.values()) / 2:
        recs.append("Veel toestellen zitten op 2.4 GHz")
    return recs
