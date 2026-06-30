from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/vpn/summary")
    async def vpn_summary() -> dict:
        """VPN rollup: overall status, peer/connected counts, per-source status.
        ``configured=false`` when no VPN source is set up."""
        s = engine.live.vpn_summary
        return {"vpn": s.model_dump() if s else None, "updated_at": engine.live.last_poll_at}

    @r.get("/vpn/peers")
    async def vpn_peers() -> dict:
        peers = engine.live.vpn_peers
        return {"peers": [p.model_dump() for p in peers],
                "configured": bool(engine.live.vpn_summary and engine.live.vpn_summary.configured),
                "updated_at": engine.live.last_poll_at}

    @r.get("/vpn/peers/{peer_id}")
    async def vpn_peer(peer_id: str) -> dict:
        match = next((p for p in engine.live.vpn_peers if p.id == peer_id), None)
        if match is None:
            raise HTTPException(status_code=404, detail=f"no VPN peer '{peer_id}'")
        return {"peer": match.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.get("/vpn/history")
    async def vpn_history(limit: int = 200, since: Optional[float] = None) -> dict:
        # VPN history is not yet retained; honest empty response.
        return {"samples": [], "history_available": False,
                "updated_at": engine.live.last_poll_at}

    return r
