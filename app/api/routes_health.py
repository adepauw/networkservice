from __future__ import annotations

from fastapi import APIRouter

from ..health import health_payload


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/health")
    async def health() -> dict:
        """Liveness + per-source status + router/internet/DNS reachability.
        Always 200 so the compose healthcheck passes even with a degraded source."""
        return health_payload(engine)

    return r
