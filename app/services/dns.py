"""DNS protection rollup — aggregates DNS analytics from any configured DNS source
(AdGuard Home, Pi-hole, …) into one compact ``DnsSummary``.

Privacy-first: in the default ``summary`` privacy mode we only ever surface
aggregate per-device counts and the top domains the source already ranks — never a
full per-device query log. Suspicious-domain detection is deliberately
conservative (we don't try to be a threat-intel feed).

When no DNS source is configured the summary is returned in an honest
``unconfigured`` state so the UI shows "Geen DNS-bron geconfigureerd" rather than
fake numbers.
"""

from __future__ import annotations

from ..config import Settings
from ..models import (
    DnsBlockedEvent,
    DnsDeviceStats,
    DnsSourceStatus,
    DnsSummary,
    NetworkDevice,
    SourceSnapshot,
)


def _blocked_percent(queries: int, blocked: int) -> float:
    return round(blocked / queries * 100, 1) if queries else 0.0


class DnsService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._blocked_log: list[DnsBlockedEvent] = []

    def _resolve_device_id(self, stat: DnsDeviceStats, devices: list[NetworkDevice]) -> str | None:
        if stat.device_id:
            return stat.device_id
        ip = str(stat.metadata.get("ip") or "")
        mac = str(stat.metadata.get("mac") or "").lower()
        for d in devices:
            if mac and (d.mac_address or "").lower() == mac:
                return d.id
            if ip and ip in d.ip_addresses:
                return d.id
        return None

    def build_summary(
        self,
        snapshots: list[SourceSnapshot],
        devices: list[NetworkDevice],
        source_status: dict[str, DnsSourceStatus],
    ) -> DnsSummary:
        dns_sources = [s for s in source_status.values()]
        contributing = [s for s in snapshots if s.dns is not None]

        # not configured at all → honest empty state.
        if not self.settings.dns_enabled and not dns_sources:
            return DnsSummary(configured=False, protection_status="unconfigured",
                              sources=[], metadata={"reason": "no DNS source configured"})

        if not contributing:
            # configured but nothing reporting → degraded/unconfigured.
            status = "degraded" if dns_sources else "unconfigured"
            return DnsSummary(configured=bool(dns_sources), protection_status=status,
                              sources=dns_sources)

        queries = 0
        blocked = 0
        per_device: dict[str, DnsDeviceStats] = {}
        domains: dict[str, int] = {}
        blocked_domains: dict[str, int] = {}
        protection_enabled = False
        primary_source = None

        for snap in contributing:
            d = snap.dns
            assert d is not None
            primary_source = primary_source or snap.source_id
            protection_enabled = protection_enabled or d.protection_enabled
            queries += d.query_count
            blocked += d.blocked_count
            for dom in d.top_domains:
                domains[dom] = domains.get(dom, 0) + 1
            for dom in d.top_blocked_domains:
                blocked_domains[dom] = blocked_domains.get(dom, 0) + 1
            for ev in d.blocked_events:
                self._blocked_log.insert(0, ev)
            for ds in d.devices:
                did = self._resolve_device_id(ds, devices) or ds.display_name
                existing = per_device.get(did)
                merged = ds.model_copy(deep=True)
                merged.device_id = self._resolve_device_id(ds, devices)
                merged.is_noisy = ds.query_count >= self.settings.dns_noisy_device_queries
                merged.blocked_percent = _blocked_percent(ds.query_count, ds.blocked_count)
                if existing:
                    existing.query_count += merged.query_count
                    existing.blocked_count += merged.blocked_count
                    existing.blocked_percent = _blocked_percent(
                        existing.query_count, existing.blocked_count)
                    existing.is_noisy = existing.is_noisy or merged.is_noisy
                else:
                    per_device[did] = merged

        del self._blocked_log[200:]  # bound the rolling blocked log
        top_devices = sorted(per_device.values(), key=lambda s: s.query_count, reverse=True)[:10]
        protection_status = "active" if protection_enabled else "degraded"
        return DnsSummary(
            configured=True,
            query_count=queries,
            blocked_count=blocked,
            blocked_percent=_blocked_percent(queries, blocked),
            top_devices=top_devices,
            top_domains=[d for d, _ in sorted(domains.items(), key=lambda kv: kv[1], reverse=True)][:10],
            top_blocked_domains=[d for d, _ in sorted(blocked_domains.items(), key=lambda kv: kv[1], reverse=True)][:10],
            protection_status=protection_status,
            sources=dns_sources,
            source=primary_source,
            history_available=False,
        )

    def blocked_events(self, limit: int = 50) -> list[DnsBlockedEvent]:
        return self._blocked_log[:limit]
