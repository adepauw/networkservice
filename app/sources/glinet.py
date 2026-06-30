"""GL.iNet source adapter — SKELETON for the Flint 2 (GL-MT6000).

GL.iNet firmware exposes its own JSON-RPC API (``/rpc``) with a token login, in
addition to the OpenWrt ubus layer underneath. This adapter targets the GL.iNet
API where it's richer (client list with vendor + WiFi signal, internet status,
WireGuard/Tailscale peers) and can fall back to OpenWrt ubus for the rest.

Status: skeleton. The login + RPC calls are stubbed and clearly marked. The
normalization shape is in place so wiring the real Flint 2 is a contained change.

What we still need from the live router to finish this (documented in README):
    * GL.iNet firmware version (API differs between 3.x and 4.x).
    * Whether the JSON-RPC `/rpc` API is enabled, and the admin password
      (supplied via WOL/GLINET_PASSWORD env, never committed).
    * The exact client-list payload shape (field names for signal/band/vendor).
    * Whether WireGuard/Tailscale peer status is exposed via the API.

Security note: read-only observation. Wake-on-LAN (a benign magic packet to a
*known trusted* device) is the only outbound action, and it lives in the service
layer, gated on trust — not here.
"""

from __future__ import annotations

import logging
import os

import httpx

from ..models import SourceSnapshot
from .base import NetworkSourceAdapter

log = logging.getLogger("networkservice.sources.glinet")


class GlinetAdapter(NetworkSourceAdapter):
    source_type = "glinet"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        self._password = os.environ.get(opts.get("password_env", "GLINET_PASSWORD"),
                                        opts.get("password", ""))
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url or "http://192.168.8.1",
            timeout=self.settings.request_timeout,
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def _login(self) -> str:
        """GL.iNet token login.

        TODO(real): GL.iNet 4.x uses a challenge/response login against
        ``/rpc`` (method ``challenge`` then ``login`` with a hashed password).
        Cache and reuse the token; re-login on an auth-expired error.
        """
        raise NotImplementedError("GL.iNet login not yet wired — see TODO + README")

    async def _rpc(self, method: str, params: dict | None = None) -> dict:
        """One GL.iNet JSON-RPC call. TODO(real): POST to /rpc with the sid."""
        raise NotImplementedError("GL.iNet RPC not yet wired — see TODO")

    async def _poll(self) -> SourceSnapshot:
        if not self.config.base_url:
            return SourceSnapshot(source_id=self.id, capabilities=[])
        # TODO(real): call clients/list, internet/status, system/status, wireguard
        # peers; normalize to NetworkDevice/metrics; report fulfilled capabilities.
        # Raises until wired -> base class degrades the source and serves cache.
        raise NotImplementedError("GL.iNet poll not yet wired — running in mock mode")
