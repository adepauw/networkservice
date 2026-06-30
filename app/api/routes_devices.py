from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..models import USER_EDITABLE_FIELDS, DeviceMetadata, now
from ..services import identity
from ..services.wol import send_wol


class DevicePatch(BaseModel):
    display_name: Optional[str] = None
    device_type: Optional[str] = None
    role: Optional[str] = None
    trust_level: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    presence_candidate: Optional[bool] = None
    automation_candidate: Optional[bool] = None


def build_router(engine) -> APIRouter:
    r = APIRouter()

    @r.get("/devices")
    async def list_devices(
        online: Optional[bool] = None,
        known: Optional[bool] = None,
        type: Optional[str] = None,
        role: Optional[str] = None,
    ) -> dict:
        devices = engine.live.device_list()
        if online is not None:
            devices = [d for d in devices if d.is_online == online]
        if known is not None:
            devices = [d for d in devices if d.is_known == known]
        if type is not None:
            devices = [d for d in devices if d.device_type == type]
        if role is not None:
            devices = [d for d in devices if d.role == role]
        devices.sort(key=lambda d: (not d.is_online, not d.is_known, d.name.lower()))
        return {"devices": [d.model_dump() for d in devices],
                "updated_at": engine.live.last_poll_at}

    @r.get("/devices/{device_id}")
    async def get_device(device_id: str) -> dict:
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        return {"device": dev.model_dump(), "updated_at": engine.live.last_poll_at}

    @r.patch("/devices/{device_id}")
    async def patch_device(device_id: str, patch: DevicePatch) -> dict:
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        if not dev.mac_address:
            raise HTTPException(status_code=409,
                                detail="device has no MAC; cannot persist metadata")
        updates = {k: v for k, v in patch.model_dump(exclude_none=True).items()
                   if k in USER_EDITABLE_FIELDS}
        if not updates:
            raise HTTPException(status_code=400, detail="no editable fields supplied")

        existing = engine.inventory.metadata_for(dev.mac_address)
        meta = existing or DeviceMetadata(mac_address=dev.mac_address,
                                          first_seen_at=dev.first_seen_at)
        for k, v in updates.items():
            setattr(meta, k, v)
        meta.updated_at = now()
        import asyncio
        await asyncio.to_thread(engine.metadata.upsert, meta)
        engine.inventory.load_metadata()
        # reflect immediately on the live copy
        from ..services.identity import apply_metadata
        engine.live.devices[device_id] = apply_metadata(dev, meta)
        return {"ok": True, "device": engine.live.devices[device_id].model_dump()}

    @r.post("/devices/{device_id}/wake")
    async def wake_device(device_id: str) -> dict:
        if not engine.settings.wol_enabled:
            raise HTTPException(status_code=501, detail="Wake-on-LAN is disabled")
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        if not dev.mac_address:
            raise HTTPException(status_code=409, detail="device has no MAC address")
        if dev.trust_level not in ("trusted", "known"):
            raise HTTPException(status_code=403,
                                detail="Wake-on-LAN only allowed for known/trusted devices")
        try:
            import asyncio
            await asyncio.to_thread(send_wol, dev.mac_address, engine.settings.wol_broadcast)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"WoL failed: {exc}") from exc
        return {"ok": True, "sent_to": dev.mac_address}

    return r
