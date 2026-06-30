from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models import now


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/alerts")
    async def list_alerts() -> dict:
        """Open warning/critical events — the actionable subset of the timeline."""
        alerts = engine.live.alerts()
        return {"alerts": [a.model_dump() for a in alerts],
                "updated_at": engine.live.last_poll_at}

    @r.post("/alerts/{alert_id}/ack")
    async def ack_alert(alert_id: str) -> dict:
        for ev in engine.live.events:
            if ev.id == alert_id:
                ev.acknowledged_at = now()
                ev.resolved_at = ev.resolved_at or now()
                return {"ok": True, "alert": ev.model_dump()}
        raise HTTPException(status_code=404, detail=f"unknown alert '{alert_id}'")

    return r
