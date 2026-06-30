"""FastAPI wrapper: the CatOS Network Intelligence domain service.

Endpoints (mounted under BASE_PATH when set, reached via /svc/network/... in CatOS):
    GET  /health                 liveness + per-source status + reachability
    GET  /summary                compact dashboard rollup
    GET  /devices                normalized device inventory (filterable)
    GET  /devices/{id}           one device
    PATCH /devices/{id}          safe user-metadata edits (name/role/trust/...)
    POST /devices/{id}/wake      Wake-on-LAN (known/trusted devices only)
    GET  /events                 recent network events (filterable)
    GET  /events/stream          SSE live event stream
    GET  /alerts                 open warning/critical events
    POST /alerts/{id}/ack        acknowledge/resolve an alert
    GET  /presence               person-level derived presence
    GET  /metrics/recent         recent metric samples for charts

A background poller (see polling.NetworkEngine) refreshes every POLL_INTERVAL
seconds. Without a real source configured it runs in mock mode so the API and the
CatOS Network page are useful immediately.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI

from .api import build_api
from .config import settings
from .events import broker
from .polling import NetworkEngine
from .sources import build_adapters

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("networkservice")

engine = NetworkEngine(settings, build_adapters(settings))


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    broker.bind_loop(asyncio.get_running_loop())
    await engine.start()
    # Prime the snapshot once on boot so the first request isn't empty.
    with contextlib.suppress(Exception):
        await engine.poll_once()
    try:
        yield
    finally:
        await engine.stop()


app = FastAPI(title="networkservice", version="1.0.0", lifespan=lifespan)
app.include_router(build_api(engine), prefix=settings.base_path)
