"""Pluggable network sources.

Each adapter turns one upstream (a router, a DNS sink, a discovery probe) into a
normalized ``SourceSnapshot``. Add a new source by subclassing
``NetworkSourceAdapter`` and registering it in ``build_adapters``.
"""

from __future__ import annotations

import logging

from ..config import Settings, SourceConfig
from .base import NetworkSourceAdapter
from .glinet import GlinetAdapter
from .mock import MockNetworkSourceAdapter
from .openwrt import OpenWrtAdapter

log = logging.getLogger("networkservice.sources")

_REGISTRY: dict[str, type[NetworkSourceAdapter]] = {
    "mock": MockNetworkSourceAdapter,
    "openwrt": OpenWrtAdapter,
    "glinet": GlinetAdapter,
}


def build_adapters(settings: Settings) -> list[NetworkSourceAdapter]:
    """Instantiate the configured source adapters.

    In mock mode (or when nothing real is configured) we inject the mock adapter
    so the API and CatOS UI are immediately useful.
    """
    adapters: list[NetworkSourceAdapter] = []
    for cfg in settings.sources:
        if not cfg.enabled:
            continue
        adapter_cls = _REGISTRY.get(cfg.type)
        if adapter_cls is None:
            log.warning("No adapter for source type %r (source %s)", cfg.type, cfg.id)
            continue
        adapters.append(adapter_cls(cfg, settings))

    real = [a for a in adapters if a.config.type != "mock"]
    if settings.mock or not real:
        if not any(a.config.type == "mock" for a in adapters):
            mock_cfg = SourceConfig(
                id="mock", type="mock", display_name="Mock network",
                capabilities=[
                    "dhcpLeases", "arpTable", "wifiAssociations",
                    "interfaceCounters", "routerHealth", "firewallSummary",
                    "dnsStats", "speedTest",
                ],
            )
            adapters.insert(0, MockNetworkSourceAdapter(mock_cfg, settings))
    return adapters


__all__ = [
    "NetworkSourceAdapter",
    "MockNetworkSourceAdapter",
    "OpenWrtAdapter",
    "GlinetAdapter",
    "build_adapters",
]
