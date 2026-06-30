"""NetworkEngine — the orchestrator that ties sources, services and state together.

One poll tick:
    1. Poll every source adapter (fault-tolerant; a failing source degrades but
       keeps its last snapshot).
    2. Merge snapshots → canonical device list (inventory).
    3. Reconcile against the previous snapshot → device transition events.
    4. Record metrics; evaluate WiFi health → poor-signal events.
    5. Resolve presence → arrival/leave events.
    6. Run the defensive security monitor → threat events.
    7. Check internet/DNS health (debounced) → connectivity events.
    8. Rebuild the summary, update source health, fan out an SSE signal.

Event hygiene: every event goes through ``_emit``, which applies a per-dedupe-key
cooldown (and a longer per-MAC cooldown for unknown-device alerts) so a sustained
condition produces one event, not one per poll. Resolved conditions close their
open alert.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid

from .config import Settings
from .events import broker
from .models import (
    DnsSourceStatus,
    EventType,
    NetworkEvent,
    NetworkHealthSample,
    VpnPeerStatus,
    now,
)
from .services.dns import DnsService
from .services.internet import InternetHealthMonitor
from .services.inventory import NetworkInventoryService
from .services.metrics import MetricsService
from .services.presence import PresenceResolver
from .services.security import SecurityMonitor
from .services.summary import build_summary
from .services.topology import TopologyService
from .services.traffic import TrafficService
from .services.vpn import VpnService
from .services.wifi import WifiQualityCoach
from .store import LiveStore, MetadataStore

log = logging.getLogger("networkservice.engine")


def _mbps(bps: float | None) -> str:
    """Format a bits-per-second value as a compact Mbps string for event copy."""
    if not bps:
        return "0 Mbps"
    return f"{bps / 1_000_000:.0f} Mbps"


class NetworkEngine:
    def __init__(self, settings: Settings, adapters: list) -> None:
        self.settings = settings
        self.adapters = adapters
        self.metadata = MetadataStore(settings.db_path)
        self.live = LiveStore(settings.event_buffer_size, settings.metric_buffer_size,
                              settings.health_history_limit)
        self.inventory = NetworkInventoryService(settings, self.live, self.metadata)
        self.metrics = MetricsService(settings, self.live)
        self.presence = PresenceResolver(settings, settings.persons)
        self.security = SecurityMonitor(settings)
        self.internet = InternetHealthMonitor(settings)
        self.wifi = WifiQualityCoach(settings)
        # Sprint 3 services
        self.traffic = TrafficService(settings, self.live)
        self.dns = DnsService(settings)
        self.vpn = VpnService(settings)
        self.topology = TopologyService(settings)
        self._cooldowns: dict[str, float] = {}
        self._unknown_cooldowns: dict[str, float] = {}
        # Sprint 3 transition state (kept across polls for event hysteresis)
        self._dns_protection_ok: bool | None = None
        self._dns_blocked_baseline: float | None = None
        self._vpn_peer_status: dict[str, VpnPeerStatus] = {}
        self._vpn_source_ok: dict[str, bool] = {}
        self._traffic_high_active = False
        self._task: asyncio.Task | None = None

    @property
    def has_real_source(self) -> bool:
        return any(a.config.type not in ("mock",) for a in self.adapters)

    def source_descriptions(self):
        return [a.describe() for a in self.adapters]

    # --- lifecycle ------------------------------------------------------------
    async def start(self) -> None:
        self.metadata.init()
        self.inventory.load_metadata()
        for a in self.adapters:
            with contextlib.suppress(Exception):
                await a.start()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        for a in self.adapters:
            with contextlib.suppress(Exception):
                await a.stop()

    async def _loop(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception as exc:  # noqa: BLE001 — keep the loop alive
                self.live.last_error = str(exc)
                log.warning("Poll tick failed: %s", exc)
            await asyncio.sleep(self.settings.poll_interval_seconds)

    # --- event emission with dedupe/cooldown ---------------------------------
    def _emit(self, type_: str, severity: str, title: str, message, target=None, metadata=None):
        """Append an event unless an identical one fired within its cooldown.

        ``target`` may be a NetworkDevice, a person_id (str) or None. Unknown-device
        alerts use a longer per-MAC cooldown so a device flapping on/off doesn't
        re-alert hourly-rule users every poll.
        """
        device_id = getattr(target, "id", None) if not isinstance(target, str) else None
        meta = dict(metadata or {})
        if isinstance(target, str):
            meta.setdefault("person_id", target)
        dedupe = f"{type_}:{device_id or meta.get('person_id') or meta.get('mac') or title}"
        t = now()

        # per-MAC cooldown for the unknown-device alert
        if type_ == EventType.DEVICE_UNKNOWN_JOINED.value:
            mac = meta.get("mac") or device_id or ""
            last = self._unknown_cooldowns.get(mac, 0)
            if t - last < self.settings.unknown_device_alert_cooldown_seconds:
                return
            self._unknown_cooldowns[mac] = t
        else:
            last = self._cooldowns.get(dedupe, 0)
            if t - last < self.settings.event_dedupe_cooldown_seconds:
                return
            self._cooldowns[dedupe] = t

        event = NetworkEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}", type=type_, severity=severity,  # type: ignore[arg-type]
            title=title, message=message, device_id=device_id,
            source=meta.get("source"), dedupe_key=dedupe, metadata=meta,
        )
        self.live.append_event(event)
        broker.publish(type_, {"id": event.id, "type": type_, "severity": severity, "title": title})
        return event

    def emit_event(self, type_, severity, title, message, target=None, metadata=None):
        """Public event-emit for request-driven events (e.g. Wake-on-LAN). Goes
        through the same dedupe/cooldown gate and SSE fan-out as poll events."""
        return self._emit(type_, severity, title, message, target, metadata)

    def _resolve_open(self, dedupe_key: str) -> None:
        ev = self.live.find_open_event(dedupe_key)
        if ev:
            ev.resolved_at = now()

    # --- one poll tick --------------------------------------------------------
    async def poll_once(self) -> None:
        snapshots = [await a.poll() for a in self.adapters]

        # 2-3: inventory merge + transitions
        merged = self.inventory.merge(snapshots)
        reconciled = self.inventory.reconcile(merged, self._emit_inventory)
        self.live.set_devices(reconciled)

        # 4: metrics + wifi quality
        for snap in snapshots:
            self.metrics.record(snap.metrics)
        wifi = self.wifi.evaluate(reconciled, self._emit_inventory)
        self.live.wifi_quality = wifi

        # 5: presence
        self.presence.resolve(reconciled, self._emit_presence)

        # 6: defensive security
        self.security.inspect(snapshots, reconciled, self._emit_inventory)

        # 7: internet health monitor (router + dns + external + latency/jitter/loss)
        await self._update_connectivity(snapshots)

        # 8: Sprint 3 — traffic, DNS, VPN, topology (each emits its own events)
        self._update_traffic()
        self._update_dns(snapshots, reconciled)
        self._update_vpn(snapshots, reconciled)
        self._update_topology(reconciled)

        # 9: record a health-history sample
        self._record_health_sample(reconciled)

        # 10: summary + source health + push
        self.live.summary = build_summary(
            self.live, self.metrics, self.presence,
            self.live.internet_health, wifi, self.internet.last_outage_at,
            traffic=self.live.traffic_summary, dns=self.live.dns_summary,
            vpn=self.live.vpn_summary, topology=self.live.topology)
        self.live.last_poll_at = now()
        self.live.last_error = None
        broker.publish("changed", {"reason": "poll"})

    # emit adapters that match the (type, severity, title, message, target, metadata) shape
    def _emit_inventory(self, type_, severity, title, message, target, metadata):
        self._emit(type_, severity, title, message, target, metadata)

    def _emit_presence(self, type_, severity, title, message, person_id):
        self._emit(type_, severity, title, message, person_id, {})

    def _emit_health(self, type_, severity, title, message, metadata):
        self._emit(type_, severity, title, message, None, metadata)

    async def _update_connectivity(self, snapshots: list) -> None:
        # gather source-reported hints; the monitor probes for real only when a
        # source doesn't already report a value (keeps mock mode network-free).
        hints = {
            "router_online": next((s.router_online for s in snapshots if s.router_online is not None), None),
            "internet_online": next((s.internet_online for s in snapshots if s.internet_online is not None), None),
            "dns_online": next((s.dns_online for s in snapshots if s.dns_online is not None), None),
            "latency_ms": self.metrics.latest("internet.latencyMs"),
            "wan_ip": next((s.raw.get("wan_ip") for s in snapshots if s.raw.get("wan_ip")), None),
            "source": next((s.source_id for s in snapshots if s.internet_online is not None), None),
        }
        health = await self.internet.evaluate(hints, self._emit_health, self._resolve_open)
        self.live.internet_health = health
        # keep the legacy flat flags in sync for /health + summary back-compat
        self.live.router_online = health.router_reachable
        self.live.internet_online = (
            True if health.status == "online" else
            False if health.status == "offline" else self.live.internet_online)
        self.live.dns_online = health.dns_ok

    # --- Sprint 3: traffic ----------------------------------------------------
    def _update_traffic(self) -> None:
        if not self.settings.traffic_enabled:
            self.live.traffic_summary = None
            return
        summary = self.traffic.build_summary()
        self.live.traffic_summary = summary
        self.traffic.record_sample(summary)

        # conservative events: only when a device crosses the configured threshold,
        # not for normal streaming. highUsage is hysteretic (one event per spell).
        unusual = summary.unusual_devices
        high = next((d for d in unusual if (d.download_bps or 0)
                     >= self.settings.traffic_high_usage_threshold_bps), None)
        if high and not self._traffic_high_active:
            self._emit(EventType.TRAFFIC_HIGH_USAGE.value, "info",
                       f"Hoog verbruik: {high.display_name}",
                       f"{_mbps(high.download_bps)} download",
                       None, {"device_id": high.device_id, "download_bps": high.download_bps})
            self._traffic_high_active = True
        elif not high:
            self._traffic_high_active = False
        for d in unusual:
            if (d.upload_bps or 0) >= self.settings.traffic_unusual_upload_threshold_bps:
                self._emit(EventType.TRAFFIC_UNUSUAL_UPLOAD.value, "info",
                           f"Ongebruikelijke upload: {d.display_name}",
                           f"{_mbps(d.upload_bps)} upload",
                           None, {"device_id": d.device_id, "upload_bps": d.upload_bps})

    # --- Sprint 3: DNS --------------------------------------------------------
    def _dns_source_status(self, snapshots: list) -> dict[str, DnsSourceStatus]:
        out: dict[str, DnsSourceStatus] = {}
        for desc in self.source_descriptions():
            if desc.type not in ("adguard", "pihole", "dns"):
                continue
            snap = next((s for s in snapshots if s.source_id == desc.id), None)
            enabled = bool(snap and snap.dns and snap.dns.protection_enabled)
            out[desc.id] = DnsSourceStatus(
                id=desc.id, type=desc.type, display_name=desc.display_name,
                status=desc.status, protection_enabled=enabled,
                last_success_at=desc.last_success_at, error_message=desc.error_message)
        return out

    def _update_dns(self, snapshots: list, devices: list) -> None:
        statuses = self._dns_source_status(snapshots)
        summary = self.dns.build_summary(snapshots, devices, statuses)
        self.live.dns_summary = summary
        if not summary.configured:
            self._dns_protection_ok = None
            return

        ok = summary.protection_status == "active"
        if self._dns_protection_ok is None:
            # baseline: announce active once, silently seed degraded.
            if ok:
                self._emit(EventType.DNS_PROTECTION_ACTIVE.value, "info",
                           "DNS-bescherming actief", None, None, {})
        elif ok and not self._dns_protection_ok:
            self._emit(EventType.DNS_PROTECTION_RECOVERED.value, "info",
                       "DNS-bescherming hersteld", None, None, {})
        elif not ok and self._dns_protection_ok:
            self._emit(EventType.DNS_PROTECTION_DEGRADED.value, "warning",
                       "DNS-bescherming verstoord",
                       "Een DNS-bron meldt dat bescherming uit staat of onbereikbaar is.",
                       None, {})
        self._dns_protection_ok = ok

        # blocked-spike: blocked-% jumps well above the rolling baseline.
        pct = summary.blocked_percent
        if self._dns_blocked_baseline is None:
            self._dns_blocked_baseline = pct
        else:
            if pct - self._dns_blocked_baseline >= self.settings.dns_blocked_spike_percent:
                self._emit(EventType.DNS_BLOCKED_SPIKE.value, "warning",
                           "Piek in geblokkeerde DNS-verzoeken",
                           f"{pct:.0f}% geblokkeerd (was {self._dns_blocked_baseline:.0f}%)",
                           None, {"blocked_percent": pct})
            # slow EMA so the baseline tracks the new normal.
            self._dns_blocked_baseline = self._dns_blocked_baseline * 0.8 + pct * 0.2

        for dev in summary.top_devices:
            if dev.is_noisy:
                self._emit(EventType.DNS_DEVICE_NOISY.value, "info",
                           f"Veel DNS-verkeer: {dev.display_name}",
                           f"{dev.query_count} queries",
                           None, {"device_id": dev.device_id, "query_count": dev.query_count})

    # --- Sprint 3: VPN --------------------------------------------------------
    def _update_vpn(self, snapshots: list, devices: list) -> None:
        descs = self.source_descriptions()
        vpn_descs = {d.id: d for d in descs if d.type in
                     ("tailscale", "wireguard", "glinet_vpn", "openwrt_vpn")}
        desc_map: dict[str, str] = {}
        for sid, d in vpn_descs.items():
            desc_map[sid] = d.type
            desc_map[f"{sid}:name"] = d.display_name
        summary = self.vpn.build_summary(snapshots, devices, desc_map, len(vpn_descs))
        peers = self.vpn.collect_peers(snapshots, devices)
        self.live.vpn_summary = summary
        self.live.vpn_peers = peers
        if not summary.configured:
            self._vpn_peer_status.clear()
            self._vpn_source_ok.clear()
            return

        # per-source degraded/recovered transitions
        for src in summary.sources:
            ok = src.status == "online"
            prev = self._vpn_source_ok.get(src.id)
            if prev is None:
                pass
            elif ok and not prev:
                self._emit(EventType.VPN_SOURCE_RECOVERED.value, "info",
                           f"VPN hersteld: {src.display_name}", None, None,
                           {"source": src.id})
            elif not ok and prev:
                self._emit(EventType.VPN_SOURCE_DEGRADED.value, "warning",
                           f"VPN verstoord: {src.display_name}", None, None,
                           {"source": src.id})
            self._vpn_source_ok[src.id] = ok

        # per-peer connect/disconnect/stale transitions
        seen: set[str] = set()
        for peer in peers:
            seen.add(peer.id)
            prev = self._vpn_peer_status.get(peer.id)
            connected = peer.status in ("connected", "online")
            if prev is None:
                pass  # baseline seed, no event
            elif connected and prev not in ("connected", "online"):
                self._emit(EventType.VPN_PEER_CONNECTED.value, "info",
                           f"VPN-peer verbonden: {peer.display_name}", None, None,
                           {"peer_id": peer.id, "source": peer.source})
            elif peer.status == "stale" and prev != "stale":
                self._emit(EventType.VPN_PEER_STALE.value, "info",
                           f"VPN-peer inactief: {peer.display_name}", None, None,
                           {"peer_id": peer.id, "source": peer.source})
            elif not connected and prev in ("connected", "online"):
                self._emit(EventType.VPN_PEER_DISCONNECTED.value, "info",
                           f"VPN-peer losgekoppeld: {peer.display_name}", None, None,
                           {"peer_id": peer.id, "source": peer.source})
            self._vpn_peer_status[peer.id] = peer.status
        for pid in [p for p in self._vpn_peer_status if p not in seen]:
            self._vpn_peer_status.pop(pid, None)

    # --- Sprint 3: topology ---------------------------------------------------
    def _update_topology(self, devices: list) -> None:
        if not self.settings.topology_enabled:
            self.live.topology = None
            return
        self.live.topology = self.topology.build(devices, self.live.vpn_peers)

    def _record_health_sample(self, devices: list) -> None:
        h = self.live.internet_health
        w = self.live.wifi_quality
        online = [d for d in devices if d.is_online]
        sample = NetworkHealthSample(
            id=f"hs_{uuid.uuid4().hex[:10]}",
            internet_status=h.status if h else "unknown",
            internet_quality=h.quality if h else "unknown",
            latency_ms=h.latency_ms if h else None,
            jitter_ms=h.jitter_ms if h else None,
            packet_loss_percent=h.packet_loss_percent if h else None,
            dns_ok=h.dns_ok if h else None,
            router_status="healthy" if self.live.router_online else (
                "unknown" if self.live.router_online is None else "error"),
            wifi_status=w.status if w else "unknown",
            wifi_weak_client_count=w.weak_client_count if w else 0,
            online_device_count=len(online),
            unknown_device_count=sum(1 for d in online if not d.is_known and not d.ignored),
            source_statuses={s.id: s.status for s in self.source_descriptions()},
        )
        self.live.append_health_sample(sample)
