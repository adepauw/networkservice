from __future__ import annotations

from typing import Optional

from fastapi import APIRouter


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/metrics/recent")
    async def recent(type: Optional[str] = None, limit: int = 200) -> dict:
        """Recent metric samples (newest first), optionally filtered by type —
        shaped for simple CatOS sparkline/charts."""
        metrics = engine.live.recent_metrics(limit if type is None else 2000)
        if type is not None:
            metrics = [m for m in metrics if m.type == type][:limit]
        return {"metrics": [m.model_dump() for m in metrics],
                "updated_at": engine.live.last_poll_at}

    return r
