"""VPN source adapters — Tailscale, WireGuard, and GL.iNet/OpenWrt VPN seams.

Each turns a VPN backend's peer list into a normalized ``SourceVpnData`` on the
snapshot. As with the DNS adapters, an unconfigured/mock instance serves realistic
peers so the VPN card is demoable; a real ``base_url``/socket path runs the live
fetch (Tailscale is wired against ``tailscale status --json``; WireGuard parses
``wg show``; GL.iNet/OpenWrt are skeletons).

Read-only: these adapters only *observe* tunnel state — they never bring a tunnel
up/down or change peer config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from ..models import SourceSnapshot, SourceVpnData, VpnPeer
from .base import NetworkSourceAdapter

log = logging.getLogger("networkservice.sources.vpn")

_MOCK_PEERS = [
    ("alex-macbook", "Alex MacBook", "100.64.0.2", 0),
    ("phone-alex", "Alex iPhone", "100.64.0.3", 30),
    ("vps-amsterdam", "VPS Amsterdam", "100.64.0.9", 5),
]


def _mock_vpn(source_type: str, offset: float) -> SourceVpnData:
    now = time.time()
    peers: list[VpnPeer] = []
    for i, (pid, name, ip, age_min) in enumerate(_MOCK_PEERS):
        # the last mock peer drifts to stale/disconnected so transitions fire.
        last_hs = now - age_min * 60 - offset
        status = "connected" if age_min * 60 + offset < 600 else "stale"
        peers.append(VpnPeer(
            id=pid, display_name=name, source=None, type=source_type,  # type: ignore[arg-type]
            status=status, ip_addresses=[ip], last_seen_at=last_hs,
            last_handshake_at=last_hs, rx_bytes=1_000_000 * (i + 1),
            tx_bytes=500_000 * (i + 1),
        ))
    online = any(p.status == "connected" for p in peers)
    return SourceVpnData(status="online" if online else "degraded", peers=peers)


class _VpnAdapterBase(NetworkSourceAdapter):
    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        self._mock = bool(opts.get("mock")) or not config.base_url
        self._tick = 0

    async def _poll(self) -> SourceSnapshot:
        self._tick += 1
        if self._mock:
            data = _mock_vpn(self.source_type, offset=self._tick * 15)
            for p in data.peers:
                p.source = self.id
            return SourceSnapshot(source_id=self.id, vpn=data, capabilities=["vpnPeers"])
        data = await self._fetch_live()
        for p in data.peers:
            p.source = self.id
        return SourceSnapshot(source_id=self.id, vpn=data, capabilities=["vpnPeers"])

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - real path
        raise NotImplementedError


class TailscaleSourceAdapter(_VpnAdapterBase):
    """Tailscale. Live path shells out to ``tailscale status --json`` (read-only)
    and maps the peer map into VpnPeer rows."""

    source_type = "tailscale"

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - needs tailscaled
        binary = (self.config.options or {}).get("binary", "tailscale")
        proc = await asyncio.create_subprocess_exec(
            binary, "status", "--json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        data = json.loads(out.decode() or "{}")
        peers: list[VpnPeer] = []
        for _key, p in (data.get("Peer") or {}).items():
            last_hs = _parse_ts(p.get("LastHandshake"))
            peers.append(VpnPeer(
                id=p.get("ID") or p.get("HostName", "peer"),
                display_name=p.get("HostName") or p.get("DNSName", "peer"),
                type="tailscale", status="connected" if p.get("Online") else "disconnected",
                ip_addresses=p.get("TailscaleIPs", []),
                last_handshake_at=last_hs, last_seen_at=last_hs,
                rx_bytes=p.get("RxBytes"), tx_bytes=p.get("TxBytes"),
            ))
        return SourceVpnData(status="online" if data.get("Self", {}).get("Online") else "degraded",
                             peers=peers)


class WireGuardSourceAdapter(_VpnAdapterBase):
    """WireGuard. Skeleton: parse ``wg show <iface> dump`` (read-only) into peers."""

    source_type = "wireguard"

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - real path TODO
        # TODO(real): run `wg show <iface> dump`, parse the tab-separated peer rows
        #   (pubkey, endpoint, allowed-ips, latest-handshake, rx, tx) and map them
        #   into VpnPeer. status = online if at least one recent handshake.
        raise NotImplementedError("WireGuard live parse not yet wired — see TODO")


class GlinetVpnSourceAdapter(_VpnAdapterBase):
    """GL.iNet VPN (WireGuard/OpenVPN server on the Flint). Skeleton — uses the
    GL.iNet RPC the router adapter already authenticates against."""

    source_type = "glinet_vpn"

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - real path TODO
        # TODO(real): reuse the GL.iNet JSON-RPC session (see sources/glinet.py) and
        #   call the wireguard-server/openvpn-server client-list method.
        raise NotImplementedError("GL.iNet VPN live API not yet wired — see TODO")


class OpenWrtVpnSourceAdapter(_VpnAdapterBase):
    """OpenWrt VPN peers via ubus/wg. Skeleton."""

    source_type = "openwrt_vpn"

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - real path TODO
        # TODO(real): ubus `call wireguard status` or shell `wg show` over SSH.
        raise NotImplementedError("OpenWrt VPN live API not yet wired — see TODO")


def _parse_ts(value: Any) -> float | None:  # pragma: no cover - helper for live path
    if not value or value in ("0001-01-01T00:00:00Z",):
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None
