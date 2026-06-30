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
import statistics
import time
from typing import Optional


async def _tcp_connect_ms(host: str, port: int, timeout: float) -> Optional[float]:
    """One TCP handshake to host:port; returns round-trip ms, or None on failure.

    Unprivileged stand-in for ICMP ping — a 443 handshake to a stable anycast host
    is a fine latency/reachability proxy and needs no raw-socket capability.
    """
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return elapsed
    except (OSError, asyncio.TimeoutError):
        return None


async def probe_latency(
    hosts: tuple[str, ...], timeout: float, samples: int
) -> dict:
    """Run ``samples`` handshakes (round-robin over hosts) and summarize.

    Returns {reachable, latency_ms (mean of successes), jitter_ms (stdev),
    packet_loss_percent, samples, ok}. Never raises.
    """
    if not hosts or samples <= 0:
        return {"reachable": None, "latency_ms": None, "jitter_ms": None,
                "packet_loss_percent": None, "samples": 0, "ok": 0}
    results: list[Optional[float]] = []
    for i in range(samples):
        host = hosts[i % len(hosts)]
        results.append(await _tcp_connect_ms(host, 443, timeout))
    oks = [r for r in results if r is not None]
    loss = round(100.0 * (len(results) - len(oks)) / len(results), 1)
    latency = round(statistics.mean(oks), 1) if oks else None
    jitter = round(statistics.pstdev(oks), 1) if len(oks) >= 2 else (0.0 if oks else None)
    return {
        "reachable": len(oks) > 0,
        "latency_ms": latency,
        "jitter_ms": jitter,
        "packet_loss_percent": loss,
        "samples": len(results),
        "ok": len(oks),
    }


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
