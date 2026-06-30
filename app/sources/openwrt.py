"""OpenWrt source adapter — SKELETON.

Talks to an OpenWrt router over the ``ubus`` HTTP-RPC interface (and optionally
SSH for things ubus doesn't expose). The GL.iNet Flint 2 (GL-MT6000) runs OpenWrt
underneath its own firmware, so this adapter is the lower-level seam;
``GlinetAdapter`` layers the GL.iNet login flow on top.

This is intentionally a skeleton: the real device calls are stubbed and marked
clearly. It already wires the *shape* — capability-gated fetches, fault tolerance,
normalization into ``SourceSnapshot`` — so dropping in real ubus calls is a local
change with nothing else to rewire.

Data sources to wire in (capability -> source):
    dhcpLeases        -> /tmp/dhcp.leases  (dnsmasq) or `luci-rpc getDHCPLeases`
    arpTable          -> ubus `ip neigh` / /proc/net/arp
    wifiAssociations  -> ubus call iwinfo assoclist / hostapd
    interfaceCounters -> ubus call network.device status
    routerHealth      -> ubus call system info  (uptime, load, mem)
    firewallSummary   -> ubus call luci.firewall / nftables ruleset summary
    dnsStats          -> dnsmasq metrics (if exported)

Credentials are read from the source ``options`` (referencing env-var names) or
env directly — never inlined. See config.example.json.

Security note: this adapter only *reads*. Even the optional SSH path is for
read-only inspection commands. No active/offensive operations live here.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from ..models import NetworkDevice, NetworkInterface, SourceSnapshot
from .base import NetworkSourceAdapter

log = logging.getLogger("networkservice.sources.openwrt")


class OpenWrtAdapter(NetworkSourceAdapter):
    source_type = "openwrt"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        self._ubus_session: str | None = None
        # Password may be given directly or via an env-var name (preferred).
        opts = config.options or {}
        self._username = opts.get("username", "root")
        self._password = os.environ.get(opts.get("password_env", ""), opts.get("password", ""))
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=self.settings.request_timeout)

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    # --- ubus plumbing (skeleton) --------------------------------------------
    async def _login(self) -> str:
        """Authenticate to ubus and cache a session id.

        TODO(real): POST to {base_url}/ubus with the `session login` call and the
        configured credentials; cache the returned ubus_rpc_session. Re-login on
        an `Access denied` response.
        """
        raise NotImplementedError("OpenWrt ubus login not yet wired — see TODO")

    async def _ubus(self, obj: str, method: str, params: dict[str, Any] | None = None) -> dict:
        """One ubus call. TODO(real): JSON-RPC `call` against {base_url}/ubus."""
        raise NotImplementedError("OpenWrt ubus call not yet wired — see TODO")

    # --- normalization helpers (ready for real data) -------------------------
    @staticmethod
    def _devices_from_leases(leases: list[dict], assoc: dict[str, dict]) -> list[NetworkDevice]:
        """Merge DHCP leases with WiFi association data into NetworkDevice list.

        `leases`: [{mac, ip, hostname, ...}]
        `assoc`:  {mac: {signal, tx_rate, rx_rate, band, ssid, ...}}
        This is pure and unit-testable; the real adapter just feeds it live data.
        """
        out: list[NetworkDevice] = []
        for lease in leases:
            mac = (lease.get("mac") or lease.get("macaddr") or "").lower()
            if not mac:
                continue
            wifi = assoc.get(mac)
            iface = None
            if wifi is not None:
                iface = NetworkInterface(
                    device_id=mac, mac_address=mac, ip_address=lease.get("ip"),
                    connection_type="wifi", ssid=wifi.get("ssid"),
                    rssi=wifi.get("signal"), band=wifi.get("band", "unknown"),
                    channel=wifi.get("channel"),
                    tx_rate_mbps=wifi.get("tx_rate"), rx_rate_mbps=wifi.get("rx_rate"),
                )
            out.append(NetworkDevice(
                id=f"dev_{mac.replace(':', '')}",
                host_name=lease.get("hostname"),
                mac_address=mac,
                ip_addresses=[lease["ip"]] if lease.get("ip") else [],
                is_online=True,
                interfaces=[iface] if iface else [
                    NetworkInterface(device_id=mac, mac_address=mac,
                                     ip_address=lease.get("ip"), connection_type="ethernet"),
                ],
            ))
        return out

    async def _poll(self) -> SourceSnapshot:
        if not self.config.base_url:
            # Unconfigured: report nothing, but don't error the whole loop.
            return SourceSnapshot(source_id=self.id, capabilities=[])

        # TODO(real): replace the stubbed calls below with live ubus/SSH fetches,
        # gated on configured capabilities. Until then this raises, the base class
        # catches it, marks the source degraded/error and serves last-known data.
        fulfilled: list[str] = []
        leases: list[dict] = []
        assoc: dict[str, dict] = {}

        if self.supports("dhcpLeases"):
            leases = await self._ubus("luci-rpc", "getDHCPLeases")  # TODO real shape
            fulfilled.append("dhcpLeases")
        if self.supports("wifiAssociations"):
            assoc = await self._ubus("iwinfo", "assoclist")  # TODO real shape
            fulfilled.append("wifiAssociations")

        devices = self._devices_from_leases(leases, assoc)
        return SourceSnapshot(
            source_id=self.id, devices=devices, capabilities=fulfilled,
        )
