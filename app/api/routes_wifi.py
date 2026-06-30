from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException

from ..services.wifi import wifi_clients


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/wifi/summary")
    async def wifi_summary() -> dict:
        """Compact WiFi quality rollup: status, client/weak/critical counts, band
        distribution, worst clients and human-readable recommendations."""
        w = engine.live.wifi_quality
        return {"wifi": w.model_dump() if w else None,
                "updated_at": engine.live.last_poll_at}

    @r.get("/wifi/clients")
    async def list_wifi_clients() -> dict:
        """Per-device WiFi quality (worst signal first)."""
        clients = wifi_clients(engine.live.device_list(), engine.settings)
        return {"clients": [c.model_dump() for c in clients],
                "updated_at": engine.live.last_poll_at}

    @r.get("/wifi/clients/{device_id}")
    async def wifi_client(device_id: str) -> dict:
        clients = wifi_clients(engine.live.device_list(), engine.settings)
        match = next((c for c in clients if c.device_id == device_id), None)
        if match is None:
            raise HTTPException(status_code=404,
                                detail=f"no WiFi client '{device_id}' (offline or not on WiFi)")
        return {"client": match.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.get("/wifi/history")
    async def wifi_history(limit: int = 200, since: Optional[float] = None) -> dict:
        """Recent aggregate WiFi samples (newest first)."""
        samples = engine.live.health_samples(limit=limit, since=since)
        return {"samples": [
            {
                "sampled_at": s.sampled_at,
                "status": s.wifi_status,
                "weak_client_count": s.wifi_weak_client_count,
            } for s in samples],
            "updated_at": engine.live.last_poll_at}

    return r
