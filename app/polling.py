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
from .health import check_dns, check_internet
from .models import EventType, NetworkEvent, now
from .services.inventory import NetworkInventoryService
from .services.metrics import MetricsService
from .services.presence import PresenceResolver
from .services.security import SecurityMonitor
from .services.summary import build_summary
from .store import LiveStore, MetadataStore

log = logging.getLogger("networkservice.engine")


class NetworkEngine:
    def __init__(self, settings: Settings, adapters: list) -> None:
        self.settings = settings
        self.adapters = adapters
        self.metadata = MetadataStore(settings.db_path)
        self.live = LiveStore(settings.event_buffer_size, settings.metric_buffer_size)
        self.inventory = NetworkInventoryService(settings, self.live, self.metadata)
        self.metrics = MetricsService(settings, self.live)
        self.presence = PresenceResolver(settings, settings.persons)
        self.security = SecurityMonitor(settings)
        self._cooldowns: dict[str, float] = {}
        self._unknown_cooldowns: dict[str, float] = {}
        self._internet_fail_streak = 0
        self._dns_fail_streak = 0
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

        # 4: metrics + wifi
        for snap in snapshots:
            self.metrics.record(snap.metrics)
        wifi = self.metrics.evaluate_wifi(reconciled, self._emit_inventory)

        # 5: presence
        self.presence.resolve(reconciled, self._emit_presence)

        # 6: defensive security
        self.security.inspect(snapshots, reconciled, self._emit_inventory)

        # 7: router + internet + dns health
        await self._update_connectivity(snapshots)

        # 8: summary + source health + push
        self.live.summary = build_summary(self.live, self.metrics, self.presence, wifi)
        self.live.last_poll_at = now()
        self.live.last_error = None
        broker.publish("changed", {"reason": "poll"})

    # emit adapters that match the (type, severity, title, message, target, metadata) shape
    def _emit_inventory(self, type_, severity, title, message, target, metadata):
        self._emit(type_, severity, title, message, target, metadata)

    def _emit_presence(self, type_, severity, title, message, person_id):
        self._emit(type_, severity, title, message, person_id, {})

    async def _update_connectivity(self, snapshots: list) -> None:
        # router
        router = next((s.router_online for s in snapshots if s.router_online is not None), None)
        self.live.router_online = router

        # internet: prefer a source that reports it, else do a real check
        reported = next((s.internet_online for s in snapshots if s.internet_online is not None), None)
        online = reported if reported is not None else await check_internet(
            self.settings.internet_check_hosts, self.settings.request_timeout)
        self._eval_internet(online)

        # dns
        dns_reported = next((s.dns_online for s in snapshots if s.dns_online is not None), None)
        dns_ok = dns_reported if dns_reported is not None else await check_dns(
            self.settings.dns_check_host, self.settings.request_timeout)
        self._eval_dns(dns_ok)

    def _eval_internet(self, online: bool) -> None:
        prev = self.live.internet_online
        if online:
            self._internet_fail_streak = 0
            if prev is False:
                self._resolve_open(f"{EventType.INTERNET_OFFLINE.value}:internet")
                self._emit(EventType.INTERNET_ONLINE.value, "success",
                           "Internet is hersteld", None, None, {})
            self.live.internet_online = True
        else:
            self._internet_fail_streak += 1
            if self._internet_fail_streak >= self.settings.internet_fail_samples:
                if prev is not False:
                    self._emit(EventType.INTERNET_OFFLINE.value, "critical",
                               "Internet is offline",
                               f"{self._internet_fail_streak} mislukte checks", None,
                               {"mac": "internet"})
                self.live.internet_online = False

    def _eval_dns(self, ok: bool) -> None:
        prev = self.live.dns_online
        if ok:
            self._dns_fail_streak = 0
            self.live.dns_online = True
        else:
            self._dns_fail_streak += 1
            if self._dns_fail_streak >= self.settings.internet_fail_samples:
                if prev is not False:
                    self._emit(EventType.DNS_DEGRADED.value, "warning",
                               "DNS reageert niet", None, None, {"mac": "dns"})
                self.live.dns_online = False
