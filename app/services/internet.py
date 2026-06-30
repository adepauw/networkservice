"""Internet Health Monitor — turns raw reachability into a graded health verdict.

Each poll runs a small, safe diagnostic pipeline:

* **gateway/router reachability** — from the source snapshot (the router adapter
  already knows if it's up), no extra probe.
* **DNS** — resolve a stable domain (worker thread; getaddrinfo is blocking).
* **external reachability + latency/jitter/packet-loss** — a handful of TCP
  handshakes to stable anycast hosts (unprivileged ICMP stand-in). Mean = latency,
  stdev = jitter, failed fraction = packet loss.

When a source already reports internet/DNS health (e.g. the mock, or a router that
exposes WAN status) we trust that and skip the real probes — cheap, and keeps mock
mode fully populated without touching the network.

Verdicts are **debounced**: a major change (offline, recovered) needs repeated
samples so a single blip never flips the state. Every event flows through the
engine's dedupe/cooldown gate, and recovery events resolve their open alerts.
"""

from __future__ import annotations

import logging

from ..config import Settings
from ..health import check_dns, probe_latency
from ..models import EventType, InternetHealthStatus, now

log = logging.getLogger("networkservice.internet")


class InternetHealthMonitor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # streak counters for the debounced transitions
        self._offline_streak = 0
        self._online_streak = 0
        self._dns_fail_streak = 0
        self._dns_ok_streak = 0
        self._latency_high_streak = 0
        self._loss_high_streak = 0
        # last committed sub-states (so we only emit on a real change)
        self._status: str = "unknown"
        self._dns_ok: bool | None = None
        self._router_up: bool | None = None
        self._latency_alerted = False
        self._loss_alerted = False
        self._jitter_alerted = False
        self._last_wan_ip: str | None = None
        self._last_outage_at: float | None = None
        self.last: InternetHealthStatus | None = None

    @property
    def last_outage_at(self) -> float | None:
        return self._last_outage_at

    async def evaluate(self, hints: dict, emit, resolve) -> InternetHealthStatus:
        """Build the current InternetHealthStatus and emit transition events.

        ``hints`` may carry source-reported facts: ``router_online``,
        ``internet_online``, ``dns_online``, ``latency_ms``, ``wan_ip``, ``ipv6``.
        ``emit(type, severity, title, message, metadata)`` and ``resolve(key)``
        are supplied by the engine (which owns dedupe/cooldown).
        """
        s = self.settings
        t = now()
        reasons: list[str] = []

        router_up = hints.get("router_online")
        self._eval_router(router_up, emit, resolve)

        # --- external reachability + latency/jitter/loss ----------------------
        reported = hints.get("internet_online")
        latency = hints.get("latency_ms")
        jitter = None
        loss = None
        external = None
        if reported is not None:
            external = bool(reported)
        elif s.internet_check_enabled:
            probe = await probe_latency(
                s.internet_check_hosts, s.request_timeout, s.latency_probe_count)
            external = probe["reachable"]
            latency = probe["latency_ms"] if latency is None else latency
            jitter = probe["jitter_ms"]
            loss = probe["packet_loss_percent"]
        # else: checks disabled → external stays None (unknown)
        # a source may also report loss/jitter directly (or a test can inject them)
        if loss is None:
            loss = hints.get("packet_loss_percent")
        if jitter is None:
            jitter = hints.get("jitter_ms")

        # --- DNS --------------------------------------------------------------
        dns_reported = hints.get("dns_online")
        if dns_reported is not None:
            dns_ok = bool(dns_reported)
        elif s.internet_check_enabled:
            dns_ok = await check_dns(s.dns_check_host, s.request_timeout)
        else:
            dns_ok = None
        self._eval_dns(dns_ok, reasons, emit, resolve)

        # --- latency / jitter / packet-loss degradation -----------------------
        if latency is not None:
            self._eval_latency(latency, reasons, emit)
        if loss is not None:
            self._eval_loss(loss, reasons, emit)
        if jitter is not None:
            self._eval_jitter(jitter, reasons, emit)

        # --- WAN IP change ----------------------------------------------------
        wan_ip = hints.get("wan_ip")
        wan_changed = False
        if wan_ip and self._last_wan_ip and wan_ip != self._last_wan_ip:
            wan_changed = True
            emit(EventType.WAN_IP_CHANGED.value, "info", "WAN-IP gewijzigd",
                 f"{self._last_wan_ip} → {wan_ip}", {"mac": "wan", "old": self._last_wan_ip, "new": wan_ip})
        if wan_ip:
            self._last_wan_ip = wan_ip

        # --- overall status (debounced offline/online) ------------------------
        status = self._eval_status(external, reasons, emit, resolve, t)
        quality = _quality(status, latency, loss, reasons)

        health = InternetHealthStatus(
            status=status, quality=quality, checked_at=t,
            router_reachable=router_up, gateway_reachable=router_up,
            dns_ok=dns_ok, external_reachable=external,
            latency_ms=latency, jitter_ms=jitter, packet_loss_percent=loss,
            wan_ip=wan_ip, wan_ip_changed=wan_changed,
            ipv6_available=hints.get("ipv6"),
            degraded_reasons=reasons, source=hints.get("source"),
        )
        self.last = health
        return health

    # --- sub-evaluators -------------------------------------------------------
    def _eval_router(self, up, emit, resolve) -> None:
        if up is None:
            return
        if up:
            if self._router_up is False:
                resolve(f"{EventType.ROUTER_UNREACHABLE.value}:router")
                emit(EventType.ROUTER_RECOVERED.value, "success",
                     "Router weer bereikbaar", None, {"mac": "router"})
            self._router_up = True
        else:
            if self._router_up is not False:
                emit(EventType.ROUTER_UNREACHABLE.value, "critical",
                     "Router onbereikbaar", None, {"mac": "router"})
            self._router_up = False

    def _eval_dns(self, dns_ok, reasons, emit, resolve) -> None:
        if dns_ok is None:
            return
        if dns_ok:
            self._dns_fail_streak = 0
            self._dns_ok_streak += 1
            if self._dns_ok is False and self._dns_ok_streak >= self.settings.dns_recovery_threshold:
                resolve(f"{EventType.DNS_DEGRADED.value}:dns")
                emit(EventType.DNS_RECOVERED.value, "success", "DNS werkt weer", None, {"mac": "dns"})
                self._dns_ok = True
            elif self._dns_ok is None:
                self._dns_ok = True
        else:
            self._dns_ok_streak = 0
            self._dns_fail_streak += 1
            reasons.append("dns")
            if self._dns_fail_streak >= self.settings.dns_failure_threshold and self._dns_ok is not False:
                emit(EventType.DNS_DEGRADED.value, "warning", "DNS reageert niet", None, {"mac": "dns"})
                self._dns_ok = False

    def _eval_latency(self, latency, reasons, emit) -> None:
        if latency > self.settings.latency_degraded_ms:
            self._latency_high_streak += 1
            if self._latency_high_streak >= self.settings.latency_failure_samples:
                reasons.append("latency")
                if not self._latency_alerted:
                    emit(EventType.INTERNET_LATENCY_HIGH.value, "warning",
                         "Hoge latency", f"{round(latency)} ms", {"mac": "internet-latency", "latency_ms": latency})
                    self._latency_alerted = True
        else:
            self._latency_high_streak = 0
            self._latency_alerted = False

    def _eval_loss(self, loss, reasons, emit) -> None:
        if loss > self.settings.packet_loss_degraded_percent:
            self._loss_high_streak += 1
            if self._loss_high_streak >= self.settings.packet_loss_failure_samples:
                reasons.append("packet_loss")
                if not self._loss_alerted:
                    emit(EventType.INTERNET_PACKET_LOSS_HIGH.value, "warning",
                         "Pakketverlies", f"{loss}%", {"mac": "internet-loss", "loss": loss})
                    self._loss_alerted = True
        else:
            self._loss_high_streak = 0
            self._loss_alerted = False

    def _eval_jitter(self, jitter, reasons, emit) -> None:
        if jitter > self.settings.jitter_degraded_ms:
            reasons.append("jitter")
            if not self._jitter_alerted:
                emit(EventType.INTERNET_JITTER_HIGH.value, "warning",
                     "Onstabiele verbinding (jitter)", f"{round(jitter)} ms", {"mac": "internet-jitter"})
                self._jitter_alerted = True
        else:
            self._jitter_alerted = False

    def _eval_status(self, external, reasons, emit, resolve, t) -> str:
        s = self.settings
        if external is None:
            # checks disabled / unknown — don't fabricate a verdict
            return "degraded" if reasons else "unknown"
        if external:
            self._offline_streak = 0
            self._online_streak += 1
            # debounce recovery: stay "offline" until enough healthy samples, so a
            # single good blip during an outage doesn't flap us back online.
            if self._status == "offline":
                if self._online_streak < s.internet_recovery_threshold:
                    return "offline"
                resolve(f"{EventType.INTERNET_OFFLINE.value}:internet")
                resolve(f"{EventType.INTERNET_DEGRADED.value}:internet")
                emit(EventType.INTERNET_RECOVERED.value, "success", "Internet is hersteld", None, {"mac": "internet"})
                emit(EventType.INTERNET_ONLINE.value, "success", "Internet online", None, {"mac": "internet"})
                self._status = "degraded" if reasons else "online"
                if reasons:
                    emit(EventType.INTERNET_DEGRADED.value, "warning", "Internet verstoord",
                         ", ".join(reasons), {"mac": "internet", "reasons": reasons})
                return self._status
            status = "degraded" if reasons else "online"
            if status == "degraded" and self._status != "degraded":
                emit(EventType.INTERNET_DEGRADED.value, "warning", "Internet verstoord",
                     ", ".join(reasons), {"mac": "internet", "reasons": reasons})
            elif status == "online" and self._status == "degraded":
                resolve(f"{EventType.INTERNET_DEGRADED.value}:internet")
            self._status = status
            return status
        # external unreachable
        self._online_streak = 0
        self._offline_streak += 1
        if self._offline_streak >= s.internet_failure_threshold:
            if self._status != "offline":
                self._last_outage_at = t
                emit(EventType.INTERNET_OFFLINE.value, "critical", "Internet is offline",
                     f"{self._offline_streak} mislukte checks", {"mac": "internet"})
            self._status = "offline"
            return "offline"
        # below the failure threshold → treat as degraded, not yet offline
        return "degraded"


def _quality(status: str, latency, loss, reasons: list[str]):
    if status == "offline":
        return "poor"
    if status in ("unknown",):
        return "unknown"
    if reasons:
        return "fair" if status == "degraded" else "good"
    if latency is None:
        return "good"
    if latency < 30 and (loss in (None, 0, 0.0)):
        return "excellent"
    if latency < 60:
        return "good"
    if latency < 100:
        return "fair"
    return "poor"
