from __future__ import annotations

from fastapi import APIRouter


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/summary")
    async def summary() -> dict:
        """Compact dashboard rollup: device counts, presence, internet/router/WiFi
        health, active alerts, last event and top-bandwidth devices."""
        return engine.live.summary or {"generated_at": None, "devices": {}, "pending": True}

    return r
