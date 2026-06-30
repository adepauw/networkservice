from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/traffic/summary")
    async def traffic_summary(period: str = "now", limit: int = 10) -> dict:
        """Compact traffic rollup: current throughput + top download/upload devices
        + unusual hints. Honest empty state when no per-device counters exist."""
        summary = engine.traffic.build_summary(limit=limit, period=_period(period))
        return {"traffic": summary.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.get("/traffic/devices")
    async def traffic_devices(period: str = "now", limit: int = 50) -> dict:
        summary = engine.traffic.build_summary(limit=limit, period=_period(period))
        # union of both directions, ranked by total bytes
        seen: dict[str, dict] = {}
        for s in summary.top_download_devices + summary.top_upload_devices:
            seen[s.device_id] = s.model_dump()
        devices = sorted(seen.values(), key=lambda d: d["total_bytes"], reverse=True)
        return {"devices": devices, "period": summary.period,
                "history_available": summary.history_available,
                "updated_at": engine.live.last_poll_at}

    @r.get("/traffic/devices/{device_id}")
    async def traffic_device(device_id: str, period: str = "now") -> dict:
        stats = engine.traffic.device_stats(device_id, period=_period(period))
        if stats is None:
            raise HTTPException(status_code=404,
                                detail=f"no traffic data for '{device_id}'")
        return {"device": stats.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.get("/traffic/history")
    async def traffic_history(limit: int = 200, since: Optional[float] = None) -> dict:
        samples = engine.live.traffic_samples(limit=limit, since=since)
        return {"samples": [s.model_dump() for s in samples], "count": len(samples),
                "history_available": len(samples) > 1,
                "updated_at": engine.live.last_poll_at}

    return r


def _period(period: str) -> str:
    # only "current" is real today; hour/day are accepted but map to current with
    # an honest period label (no fabricated historical aggregation yet).
    return {"now": "current", "hour": "hour", "day": "day"}.get(period, "current")
