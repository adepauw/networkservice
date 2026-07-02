"""VPN source adapters — Tailscale, WireGuard, and GL.iNet/OpenWrt VPN seams.

Each turns a VPN backend's peer list into a normalized ``SourceVpnData`` on the
snapshot. As with the DNS adapters, an unconfigured/mock instance serves realistic
peers so the VPN card is demoable; a real config runs the live fetch (Tailscale
shells out to ``tailscale status --json``; WireGuard parses ``wg show <iface>
dump``; GL.iNet reads the Flint's ``wg-server``/``ovpn-server`` status over the
same authenticated JSON-RPC the router adapter uses; OpenWrt stays a skeleton).

Read-only: these adapters only *observe* tunnel state — they never bring a tunnel
up/down or change peer config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

from ..models import SourceSnapshot, SourceVpnData, VpnPeer
from .base import NetworkSourceAdapter
from .glinet import GlinetRpcClient

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


def parse_wg_dump(text: str, stale_seconds: int) -> SourceVpnData:
    """Parse ``wg show <iface> dump`` output (tab-separated, stable format).

    The first line describes the interface itself; every further line is a peer:
    pubkey, preshared-key, endpoint, allowed-ips, latest-handshake, rx, tx,
    keepalive. A peer with a recent handshake is connected; an old handshake is
    stale; no handshake ever = disconnected.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    peers: list[VpnPeer] = []
    t = time.time()
    for ln in lines[1:]:
        cols = ln.split("\t")
        if len(cols) < 8:
            continue
        pubkey, _psk, endpoint, allowed_ips, handshake, rx, tx, _keepalive = cols[:8]
        try:
            hs: float | None = float(handshake) or None  # "0" = never handshaken
        except ValueError:
            hs = None
        if hs is not None and (t - hs) <= stale_seconds:
            status = "connected"
        elif hs is not None:
            status = "stale"
        else:
            status = "disconnected"
        peers.append(VpnPeer(
            id=pubkey[:16], type="wireguard", status=status,  # type: ignore[arg-type]
            display_name=endpoint if endpoint not in ("", "(none)") else pubkey[:12],
            ip_addresses=[ip.split("/")[0] for ip in allowed_ips.split(",")
                          if ip and ip != "(none)"],
            last_handshake_at=hs, last_seen_at=hs,
            rx_bytes=float(rx) if rx.isdigit() else None,
            tx_bytes=float(tx) if tx.isdigit() else None,
            metadata={"endpoint": endpoint},
        ))
    online = any(p.status == "connected" for p in peers)
    return SourceVpnData(
        status="online" if online else ("degraded" if peers else "unknown"),
        peers=peers)


class WireGuardSourceAdapter(_VpnAdapterBase):
    """WireGuard on the local host. Runs ``wg show <iface> dump`` (read-only;
    ``options.binary`` / ``options.interface`` configurable) and parses the
    tab-separated peer rows."""

    source_type = "wireguard"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        # a local binary needs no base_url; live when an interface is configured.
        self._mock = bool(opts.get("mock")) or not opts.get("interface")

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - needs wg binary
        opts = self.config.options or {}
        binary = opts.get("binary", "wg")
        iface = opts.get("interface", "wg0")
        proc = await asyncio.create_subprocess_exec(
            binary, "show", iface, "dump",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"wg show {iface} dump: {err.decode().strip() or 'failed'}")
        return parse_wg_dump(out.decode(), self.settings.vpn_peer_stale_seconds)


def _glinet_peer(raw: dict) -> VpnPeer:
    """Map one ``wg-server.get_status`` peer row. Field names vary slightly
    across 4.x firmwares, so the common candidates are read defensively."""
    name = str(raw.get("name") or raw.get("alias") or raw.get("client_name")
               or (raw.get("public_key") or "")[:12] or "peer")
    hs_raw = raw.get("latest_handshake") or raw.get("last_handshake_time")
    try:
        hs: float | None = float(hs_raw) if hs_raw else None
    except (TypeError, ValueError):
        hs = None
    online = bool(raw.get("online")) or (hs is not None and time.time() - hs < 300)

    def _num(v: Any) -> float | None:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    return VpnPeer(
        id=str(raw.get("id") or raw.get("public_key") or name),
        display_name=name, type="glinet_vpn",
        status="connected" if online else "disconnected",
        ip_addresses=[str(raw[k]).split("/")[0]
                      for k in ("ip", "address", "address_v4") if raw.get(k)],
        last_handshake_at=hs, last_seen_at=hs,
        rx_bytes=_num(raw.get("rx_bytes") or raw.get("rx")),
        tx_bytes=_num(raw.get("tx_bytes") or raw.get("tx")),
    )


class GlinetVpnSourceAdapter(_VpnAdapterBase):
    """GL.iNet VPN servers (WireGuard/OpenVPN) on the Flint 2, over the same
    authenticated JSON-RPC flow the router adapter uses (own session).

    Reads only ``wg-server.get_status`` / ``ovpn-server.get_status`` — peer list
    plus a running flag, shapes verified against a live Flint 2. Deliberately
    never ``get_config``: that call echoes the server's *private key*.
    """

    source_type = "glinet_vpn"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        self._username = opts.get("username", "root")
        self._password = os.environ.get(
            opts.get("password_env", "GLINET_PASSWORD"), opts.get("password", ""))
        self._rpc: GlinetRpcClient | None = None
        # the router URL has a sane default, so live mode keys off credentials.
        self._mock = bool(opts.get("mock")) or not (self.config.base_url or self._password)

    async def start(self) -> None:
        if not self._mock:
            self._rpc = GlinetRpcClient(self.config.base_url, self._username,
                                        self._password, self.settings.request_timeout,
                                        label=self.id)
            await self._rpc.open()

    async def stop(self) -> None:
        if self._rpc is not None:
            await self._rpc.close()

    async def _fetch_live(self) -> SourceVpnData:  # pragma: no cover - needs the router
        assert self._rpc is not None
        wg = await self._rpc.call("wg-server", "get_status")
        running = int((wg.get("server") or {}).get("status") or 0) == 1
        peers = [_glinet_peer(raw) for raw in wg.get("peers") or []]
        try:
            ovpn = await self._rpc.call("ovpn-server", "get_status")
            running = running or int(ovpn.get("status") or 0) == 1
        except Exception as exc:  # noqa: BLE001 — OpenVPN module may be absent
            log.debug("ovpn-server.get_status failed: %s", exc)
        return SourceVpnData(status="online" if running else "offline", peers=peers)


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
