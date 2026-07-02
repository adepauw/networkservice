from __future__ import annotations

from fastapi import APIRouter


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/presence")
    async def presence() -> dict:
        """Person-level derived presence (home/away/probably_*), with confidence
        and the evidence each verdict rests on."""
        states = engine.presence.states()
        states.sort(key=lambda s: s.display_name.lower())
        return {"presence": [s.model_dump() for s in states],
                "home_count": engine.presence.home_count(),
                "updated_at": engine.live.last_poll_at}

    return r
