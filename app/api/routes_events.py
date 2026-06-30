from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from ..events import event_source


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/events")
    async def list_events(
        severity: Optional[str] = None,
        type: Optional[str] = None,
        device_id: Optional[str] = None,
        unresolved: Optional[bool] = None,
        limit: int = 100,
    ) -> dict:
        events = engine.live.event_list()
        if severity is not None:
            events = [e for e in events if e.severity == severity]
        if type is not None:
            events = [e for e in events if e.type == type]
        if device_id is not None:
            events = [e for e in events if e.device_id == device_id]
        if unresolved:
            events = [e for e in events if e.is_open]
        return {"events": [e.model_dump() for e in events[:limit]],
                "updated_at": engine.live.last_poll_at}

    @r.get("/events/stream")
    async def stream(request: Request) -> StreamingResponse:
        """SSE stream of live network events (device on/offline, unknown joined,
        internet/wifi/presence/security/source changes). Emits a `changed` event
        plus per-type events; CatOS revalidates on each."""
        return StreamingResponse(
            event_source(request),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return r
