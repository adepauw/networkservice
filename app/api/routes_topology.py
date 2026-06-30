from __future__ import annotations

from fastapi import APIRouter


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/topology")
    async def topology() -> dict:
        """Simple grouped topology: devices bucketed by connectivity/role plus a
        light star of links off the router. ``available=false`` when disabled."""
        t = engine.live.topology
        if t is None:
            return {"available": False, "groups": [], "links": [], "counts": {},
                    "updated_at": engine.live.last_poll_at}
        payload = t.model_dump()
        payload["available"] = True
        payload["updated_at"] = engine.live.last_poll_at
        return payload

    return r
