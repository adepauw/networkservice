from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/dns/summary")
    async def dns_summary() -> dict:
        """DNS protection rollup: query/blocked counts, protection status, top
        devices/domains. ``configured=false`` when no DNS source is set up."""
        s = engine.live.dns_summary
        return {"dns": s.model_dump() if s else None, "updated_at": engine.live.last_poll_at}

    @r.get("/dns/devices")
    async def dns_devices() -> dict:
        s = engine.live.dns_summary
        devices = [d.model_dump() for d in s.top_devices] if s else []
        return {"devices": devices, "configured": bool(s and s.configured),
                "updated_at": engine.live.last_poll_at}

    @r.get("/dns/devices/{device_id}")
    async def dns_device(device_id: str) -> dict:
        s = engine.live.dns_summary
        match = next((d for d in (s.top_devices if s else [])
                      if d.device_id == device_id), None)
        if match is None:
            raise HTTPException(status_code=404,
                                detail=f"no DNS stats for '{device_id}'")
        return {"device": match.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.get("/dns/blocked")
    async def dns_blocked(limit: int = 50) -> dict:
        events = engine.dns.blocked_events(limit=limit)
        return {"blocked": [e.model_dump() for e in events],
                "configured": bool(engine.live.dns_summary and engine.live.dns_summary.configured),
                "updated_at": engine.live.last_poll_at}

    @r.get("/dns/history")
    async def dns_history(limit: int = 200, since: Optional[float] = None) -> dict:
        # DNS history is not yet retained as a ring buffer; report honestly.
        return {"samples": [], "history_available": False,
                "updated_at": engine.live.last_poll_at}

    return r
