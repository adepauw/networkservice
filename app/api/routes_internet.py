from __future__ import annotations

from typing import Optional

from fastapi import APIRouter


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/internet/status")
    async def internet_status() -> dict:
        """Current internet/WAN health snapshot (graded status + quality + the
        latency/jitter/loss/DNS signals behind the verdict)."""
        h = engine.live.internet_health
        return {"internet": h.model_dump() if h else None,
                "updated_at": engine.live.last_poll_at}

    @r.get("/internet/history")
    async def internet_history(limit: int = 200, since: Optional[float] = None) -> dict:
        """Recent internet health samples (newest first) for sparklines."""
        samples = engine.live.health_samples(limit=limit, since=since)
        return {"samples": [
            {
                "sampled_at": s.sampled_at,
                "status": s.internet_status,
                "quality": s.internet_quality,
                "latency_ms": s.latency_ms,
                "jitter_ms": s.jitter_ms,
                "packet_loss_percent": s.packet_loss_percent,
                "dns_ok": s.dns_ok,
            } for s in samples],
            "updated_at": engine.live.last_poll_at}

    @r.get("/diagnostics/internet")
    async def diagnostics_internet() -> dict:
        """Verbose diagnostic dump for debugging the internet pipeline: the full
        health snapshot, the configured thresholds, and per-source status."""
        s = engine.settings
        h = engine.live.internet_health
        return {
            "internet": h.model_dump() if h else None,
            "checks_enabled": s.internet_check_enabled,
            "check_hosts": list(s.internet_check_hosts),
            "dns_check_host": s.dns_check_host,
            "thresholds": {
                "internet_failure_threshold": s.internet_failure_threshold,
                "internet_recovery_threshold": s.internet_recovery_threshold,
                "dns_failure_threshold": s.dns_failure_threshold,
                "latency_degraded_ms": s.latency_degraded_ms,
                "latency_failure_samples": s.latency_failure_samples,
                "jitter_degraded_ms": s.jitter_degraded_ms,
                "packet_loss_degraded_percent": s.packet_loss_degraded_percent,
                "packet_loss_failure_samples": s.packet_loss_failure_samples,
            },
            "sources": [src.model_dump() for src in engine.source_descriptions()],
            "last_poll_at": engine.live.last_poll_at,
            "last_error": engine.live.last_error,
        }

    return r
