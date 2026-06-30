"""DNS analytics source adapters — AdGuard Home, Pi-hole, and a generic seam.

Each turns a DNS sink's stats API into a normalized ``SourceDnsData`` on the
snapshot. When no ``base_url`` is configured (or ``options.mock`` is set) the
adapter serves a realistic **mock** so the DNS Protection card is demoable without
credentials; with a real ``base_url`` the live path runs (AdGuard is wired against
its documented stats API; Pi-hole is a clear skeleton with TODOs).

Privacy: these adapters only pull aggregate stats and the source's own top-N
domain rankings — never a full per-client query log. Nothing here resolves,
caches, or forwards DNS itself.
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Any

import httpx

from ..models import DnsBlockedEvent, DnsDeviceStats, SourceDnsData, SourceSnapshot
from .base import NetworkSourceAdapter

log = logging.getLogger("networkservice.sources.dns")

# a small, believable household DNS profile keyed to the mock network's IPs so the
# per-device stats line up with the device inventory in mock mode.
_MOCK_CLIENTS = [
    ("Phobos NAS", "192.168.8.10", 9000, 120),
    ("Alex iPhone", "192.168.8.20", 4200, 1400),
    ("Woonkamer TV", "192.168.8.30", 2600, 980),
    ("Hue Bridge", "192.168.8.50", 1200, 60),
    ("Garage Sensor", "192.168.8.80", 700, 30),
]
_MOCK_TOP_DOMAINS = [
    "apple.com", "icloud.com", "google.com", "github.com", "cloudflare.com",
]
_MOCK_TOP_BLOCKED = [
    "ads.example.net", "telemetry.example.com", "tracker.example.org",
    "metrics.example.io", "doubleclick.example",
]


def _mock_dns(rng: random.Random) -> SourceDnsData:
    devices: list[DnsDeviceStats] = []
    total_q = 0
    total_b = 0
    for name, ip, base_q, base_b in _MOCK_CLIENTS:
        q = base_q + rng.randint(-200, 400)
        b = max(0, base_b + rng.randint(-40, 80))
        total_q += q
        total_b += b
        devices.append(DnsDeviceStats(
            display_name=name, query_count=q, blocked_count=b,
            blocked_percent=round(b / q * 100, 1) if q else 0.0,
            top_domains=_MOCK_TOP_DOMAINS[:3],
            top_blocked_domains=_MOCK_TOP_BLOCKED[:2],
            last_query_at=time.time(),
            metadata={"ip": ip},
        ))
    blocked_events = [
        DnsBlockedEvent(domain=_MOCK_TOP_BLOCKED[rng.randrange(len(_MOCK_TOP_BLOCKED))],
                        device_name=devices[rng.randrange(len(devices))].display_name,
                        reason="blocklist")
        for _ in range(3)
    ]
    return SourceDnsData(
        protection_enabled=True, query_count=total_q, blocked_count=total_b,
        devices=devices, top_domains=_MOCK_TOP_DOMAINS,
        top_blocked_domains=_MOCK_TOP_BLOCKED, blocked_events=blocked_events,
    )


class _DnsAdapterBase(NetworkSourceAdapter):
    """Shared plumbing for DNS adapters: mock-vs-live decision + an httpx client."""

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        self._mock = bool(opts.get("mock")) or not config.base_url
        self._password = os.environ.get(opts.get("password_env", ""), opts.get("password", ""))
        self._token = os.environ.get(opts.get("token_env", ""), opts.get("token", ""))
        self._rng = random.Random(hash(config.id) & 0xFFFF)
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if not self._mock:
            self._client = httpx.AsyncClient(timeout=self.settings.request_timeout, verify=False)

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def _poll(self) -> SourceSnapshot:
        if self._mock:
            return SourceSnapshot(source_id=self.id, dns=_mock_dns(self._rng),
                                  capabilities=["dnsStats"])
        dns = await self._fetch_live()
        return SourceSnapshot(source_id=self.id, dns=dns, capabilities=["dnsStats"])

    async def _fetch_live(self) -> SourceDnsData:  # pragma: no cover - real path
        raise NotImplementedError


class AdGuardSourceAdapter(_DnsAdapterBase):
    """AdGuard Home. Live path uses the documented control API
    (``/control/stats`` + ``/control/status``)."""

    source_type = "adguard"

    async def _fetch_live(self) -> SourceDnsData:  # pragma: no cover - needs a live AGH
        assert self._client is not None
        base = self.config.base_url.rstrip("/")
        # AdGuard uses HTTP basic auth (username/password) on the control API.
        auth = (self.config.options.get("username", "admin"), self._password)
        status = (await self._client.get(f"{base}/control/status", auth=auth)).json()
        stats = (await self._client.get(f"{base}/control/stats", auth=auth)).json()
        devices: list[DnsDeviceStats] = []
        for row in stats.get("top_clients", []):
            for ip, count in row.items():
                devices.append(DnsDeviceStats(display_name=ip, query_count=int(count),
                                              metadata={"ip": ip}))
        return SourceDnsData(
            protection_enabled=bool(status.get("protection_enabled", True)),
            query_count=int(stats.get("num_dns_queries", 0)),
            blocked_count=int(stats.get("num_blocked_filtering", 0)),
            devices=devices,
            top_domains=[next(iter(d)) for d in stats.get("top_queried_domains", []) if d],
            top_blocked_domains=[next(iter(d)) for d in stats.get("top_blocked_domains", []) if d],
        )


class PiHoleSourceAdapter(_DnsAdapterBase):
    """Pi-hole. Skeleton: live path against the admin API
    (``/admin/api.php?summaryRaw&topClients&topItems``, auth token)."""

    source_type = "pihole"

    async def _fetch_live(self) -> SourceDnsData:  # pragma: no cover - real path TODO
        # TODO(real): GET {base_url}/admin/api.php?summaryRaw&topClients&topItems
        #   &auth=<token> and map dns_queries_today / ads_blocked_today / top_sources
        #   / top_ads into SourceDnsData. Pi-hole v6 uses a different /api endpoint
        #   with a session token — branch on options.api_version.
        raise NotImplementedError("Pi-hole live API not yet wired — see TODO")


class DnsSourceAdapter(_DnsAdapterBase):
    """Generic DNS analytics seam for any other sink. Mock-only until a concrete
    upstream is wired; lets ``type: dns`` configs work for demos/tests."""

    source_type = "dns"

    async def _fetch_live(self) -> SourceDnsData:  # pragma: no cover
        raise NotImplementedError("generic DNS source has no live adapter — use adguard/pihole")
