"""HTTP routes. Each module exposes ``build_router(engine) -> APIRouter`` so the
route handlers can reach the shared NetworkEngine without globals."""

from __future__ import annotations

from fastapi import APIRouter

from . import (
    routes_alerts,
    routes_devices,
    routes_events,
    routes_health,
    routes_internet,
    routes_metrics,
    routes_presence,
    routes_summary,
    routes_wifi,
)


def build_api(engine) -> APIRouter:
    router = APIRouter()
    for mod in (
        routes_summary, routes_devices, routes_events, routes_alerts,
        routes_presence, routes_health, routes_metrics,
        routes_internet, routes_wifi,
    ):
        router.include_router(mod.build_router(engine))
    return router
