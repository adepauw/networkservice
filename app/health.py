"""Connectivity + service-health helpers.

Real reachability checks used when no source reports internet/DNS health itself
(e.g. a DHCP-only source). Both are cheap, time-bounded and never raise.

* ``check_internet`` — a TCP connect to a well-known host:443. We avoid ICMP ping
  because it needs raw-socket privileges; a TCP handshake to 1.1.1.1:443 is a fine
  liveness proxy and works unprivileged in the container.
* ``check_dns`` — resolve a hostname in a worker thread (getaddrinfo is blocking).

The internet/DNS *flap debounce* (N consecutive failures before alerting) lives in
the engine; these functions just answer "right now, yes/no".
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional


async def check_internet(hosts: tuple[str, ...], timeout: float) -> bool:
    for host in hosts:
        try:
            fut = asyncio.open_connection(host, 443)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            continue
    return False


async def check_dns(host: str, timeout: float) -> bool:
    try:
        await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, 443), timeout=timeout)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def health_payload(engine) -> dict:
    """Assemble GET /health — service + per-source status + reachability."""
    return {
        "status": "ok",
        "service": "networkservice",
        "mock_mode": engine.settings.mock or not engine.has_real_source,
        "last_poll_at": engine.live.last_poll_at,
        "last_error": engine.live.last_error,
        "router_reachable": engine.live.router_online,
        "internet_reachable": engine.live.internet_online,
        "dns_reachable": engine.live.dns_online,
        "sources": [s.model_dump() for s in engine.source_descriptions()],
    }
