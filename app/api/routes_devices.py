from __future__ import annotations

import asyncio
from typing import Optional, get_args

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..models import (
    USER_EDITABLE_FIELDS,
    DeviceMetadata,
    DeviceRole,
    DeviceType,
    TrustLevel,
    now,
)
from ..models import EventType
from ..services.identity import apply_metadata
from ..services.wol import attempt_wake, evaluate_eligibility


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
    ignored: Optional[bool] = None
    is_known: Optional[bool] = None


class OwnerBody(BaseModel):
    owner: str


# allowed values for the validated enum-ish fields. anything else is a 422 so a
# typo can never poison the persisted metadata.
_VALID = {
    "device_type": set(get_args(DeviceType)),
    "role": set(get_args(DeviceRole)),
    "trust_level": set(get_args(TrustLevel)),
}


def build_router(engine) -> APIRouter:
    r = APIRouter()

    def _apply_metadata_update(device_id: str, updates: dict) -> dict:
        """Validate + persist a metadata patch, then reflect it on the live copy.

        Shared by PATCH and every convenience endpoint so they all go through the
        same validation, persistence and live-overlay path.
        """
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        if not dev.mac_address:
            raise HTTPException(status_code=409,
                                detail="device has no MAC; cannot persist metadata")
        updates = {k: v for k, v in updates.items() if k in USER_EDITABLE_FIELDS}
        if not updates:
            raise HTTPException(status_code=400, detail="no editable fields supplied")
        for field, allowed in _VALID.items():
            if field in updates and updates[field] not in allowed:
                raise HTTPException(status_code=422,
                                    detail=f"invalid {field}: {updates[field]!r}")

        existing = engine.inventory.metadata_for(dev.mac_address)
        # Un-ignoring must also clear the legacy trust sentinel, or the
        # `trust_level == "ignored"` overlay re-ignores the device next poll.
        if (updates.get("ignored") is False and "trust_level" not in updates
                and "ignored" in ((existing.trust_level if existing else None), dev.trust_level)):
            updates["trust_level"] = "unknown"
        meta = existing or DeviceMetadata(mac_address=dev.mac_address,
                                          first_seen_at=dev.first_seen_at)
        for k, v in updates.items():
            setattr(meta, k, v)
        meta.updated_at = now()
        engine.metadata.upsert(meta)
        engine.inventory.load_metadata()
        engine.live.devices[device_id] = apply_metadata(dev, meta)
        return engine.live.devices[device_id].model_dump()

    @r.get("/devices")
    async def list_devices(
        online: Optional[bool] = None,
        known: Optional[bool] = None,
        ignored: Optional[bool] = None,
        type: Optional[str] = None,
        role: Optional[str] = None,
    ) -> dict:
        devices = engine.live.device_list()
        if online is not None:
            devices = [d for d in devices if d.is_online == online]
        if known is not None:
            devices = [d for d in devices if d.is_known == known]
        if ignored is not None:
            devices = [d for d in devices if d.ignored == ignored]
        if type is not None:
            devices = [d for d in devices if d.device_type == type]
        if role is not None:
            devices = [d for d in devices if d.role == role]
        devices.sort(key=lambda d: (not d.is_online, not d.is_known, d.name.lower()))
        return {"devices": [d.model_dump() for d in devices],
                "updated_at": engine.live.last_poll_at}

    @r.get("/devices/{device_id}")
    async def get_device(device_id: str) -> dict:
        """Full device detail: the normalized device plus its interfaces, recent
        events + metrics, presence usage and which sources reported it."""
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        events = [e.model_dump() for e in engine.live.event_list()
                  if e.device_id == device_id][:25]
        metrics = [m.model_dump() for m in engine.live.recent_metrics(2000)
                   if m.device_id == device_id][:50]
        return {
            "device": dev.model_dump(),
            "interfaces": [i.model_dump() for i in dev.interfaces],
            "events": events,
            "metrics": metrics,
            "presence_usage": _presence_usage(engine, device_id),
            "sources": [s.model_dump() for s in engine.source_descriptions()
                        if s.id in dev.source_ids],
            "updated_at": engine.live.last_poll_at,
        }

    @r.patch("/devices/{device_id}")
    async def patch_device(device_id: str, patch: DevicePatch) -> dict:
        updates = patch.model_dump(exclude_none=True)
        if not updates:
            raise HTTPException(status_code=400, detail="no editable fields supplied")
        device = await asyncio.to_thread(_apply_metadata_update, device_id, updates)
        return {"ok": True, "device": device}

    # --- convenience endpoints (all funnel through the metadata update path) ---
    @r.post("/devices/{device_id}/mark-known")
    async def mark_known(device_id: str) -> dict:
        device = await asyncio.to_thread(
            _apply_metadata_update, device_id, {"trust_level": "known", "ignored": False, "is_known": True})
        return {"ok": True, "device": device}

    @r.post("/devices/{device_id}/mark-guest")
    async def mark_guest(device_id: str) -> dict:
        device = await asyncio.to_thread(
            _apply_metadata_update, device_id,
            {"trust_level": "guest", "role": "guest_device", "ignored": False})
        return {"ok": True, "device": device}

    @r.post("/devices/{device_id}/ignore")
    async def ignore_device(device_id: str) -> dict:
        device = await asyncio.to_thread(
            _apply_metadata_update, device_id, {"ignored": True, "trust_level": "ignored"})
        return {"ok": True, "device": device}

    @r.post("/devices/{device_id}/assign-owner")
    async def assign_owner(device_id: str, body: OwnerBody) -> dict:
        device = await asyncio.to_thread(
            _apply_metadata_update, device_id, {"owner": body.owner})
        return {"ok": True, "device": device}

    @r.get("/devices/{device_id}/wake/status")
    async def wake_status(device_id: str) -> dict:
        """Whether this device may be woken (drives the conditional Wake action).
        404 only for a truly unknown id; an ineligible-but-known device returns a
        200 with ``can_wake=false`` and a Dutch ``reason``."""
        dev = engine.live.device(device_id)
        if dev is None:
            raise HTTPException(status_code=404, detail=f"unknown device '{device_id}'")
        elig = evaluate_eligibility(dev, engine.settings)
        return {"eligibility": elig.model_dump()}

    @r.post("/devices/{device_id}/wake")
    async def wake_device(device_id: str) -> dict:
        """Wake-on-LAN. Returns a structured WakeResult and maps its status to an
        HTTP code (sent→200, forbidden→403, unsupported→501, failed→502). Emits
        wake request/sent/failed events for the timeline (no alert by default)."""
        dev = engine.live.device(device_id)
        engine.emit_event(EventType.DEVICE_WAKE_REQUESTED.value, "info",
                          f"Wake-on-LAN aangevraagd: {dev.name if dev else device_id}",
                          None, dev, {})
        result = await asyncio.to_thread(attempt_wake, dev, engine.settings, device_id)
        if result.status == "sent":
            engine.emit_event(EventType.DEVICE_WAKE_SENT.value, "info",
                              f"Wake-on-LAN verzonden: {dev.name if dev else device_id}",
                              result.message, dev, {"target_mac": result.target_mac})
            return {"ok": True, "result": result.model_dump()}
        if result.status in ("failed",):
            engine.emit_event(EventType.DEVICE_WAKE_FAILED.value, "warning",
                              f"Wake-on-LAN mislukt: {dev.name if dev else device_id}",
                              result.message, dev, {})
        status_code = {"forbidden": 403, "unsupported": 501, "failed": 502}.get(result.status, 400)
        # detail is a plain string so the app surfaces the Dutch reason directly;
        # the structured result rides along in a header-free body field via 'result'.
        raise HTTPException(status_code=status_code, detail=result.message or result.status)

    return r


def _presence_usage(engine, device_id: str) -> dict:
    """How this device participates in presence: for which persons it's a primary
    or supporting device, plus its own presence-candidate flag."""
    primary_for: list[str] = []
    supporting_for: list[str] = []
    for state in engine.presence.states():
        if device_id in state.primary_device_ids:
            primary_for.append(state.person_id)
        if device_id in state.supporting_device_ids:
            supporting_for.append(state.person_id)
    dev = engine.live.device(device_id)
    return {
        "presence_candidate": bool(dev and dev.presence_candidate),
        "primary_for": primary_for,
        "supporting_for": supporting_for,
    }
