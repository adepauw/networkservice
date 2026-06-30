from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from ..health import health_payload


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/health")
    async def health() -> dict:
        """Liveness + per-source status + router/internet/DNS reachability.
        Always 200 so the compose healthcheck passes even with a degraded source."""
        return health_payload(engine)

    @r.get("/health/history")
    async def health_history(limit: int = 200, since: Optional[float] = None) -> dict:
        """Rolling network-health samples (newest first): internet status/quality,
        latency/jitter/loss, DNS, router, WiFi and device counts — for CatOS charts."""
        samples = engine.live.health_samples(limit=limit, since=since)
        return {"samples": [s.model_dump() for s in samples],
                "count": len(samples),
                "updated_at": engine.live.last_poll_at}

    return r
