"""GL.iNet source adapter — live implementation for the Flint 2 (GL-MT6000).

GL.iNet firmware 4.x exposes a JSON-RPC API (ubus-over-RPC). On this Flint 2 the
admin/API listens on **https://192.168.8.1:4443** (HTTP/80 is closed). Auth is a
challenge/response:

    1. POST /rpc challenge {username}            -> {salt, nonce, alg, hash-method}
    2. cipher = md5_crypt(password, "$<alg>$<salt>")   (Unix MD5-crypt)
       hash   = sha256("<user>:<cipher>:<nonce>")
    3. POST /rpc login {username, hash}          -> {sid}
    4. POST /rpc call [sid, <object>, <method>, {args}]   (ubus call)

Data used:
    clients.get_list  -> connected/known clients (mac, ip, ipv6, name, alias,
                         iface 2.4G/5G/cable/*_Guest, online, blocked, traffic)
    wifi.get_status   -> per-band channel (RSSI is not exposed per client here)
    system.get_status -> router health: CPU temperature, load average, memory,
                         uptime (probed live against a Flint 2; confirmed shape
                         below). We deliberately only read the ``system`` key —
                         the same call's ``wifi`` key echoes plaintext WiFi
                         passwords and ``service`` lists enabled addons, neither
                         of which this adapter stores or forwards.

RSSI/signal is not available from this API, so wifi.signalPoor can't fire from
this source — reported honestly via capabilities (no `wifiSignal`). The engine's
own internet/DNS checks cover connectivity; a successful login implies the router
is reachable (router_online=True).

``system.get_status.system`` has no true CPU-utilization percentage (only a
temperature reading and a 1/5/15-min load average) — ``router.cpuPercent`` is
left unset rather than faked from load average against an unknown core count.

Read-only. The only outbound action anywhere in the service is Wake-on-LAN to a
known/trusted device, which lives in the service layer — not here.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

import httpx

from ..models import NetworkDevice, NetworkInterface, NetworkMetric, SourceSnapshot, now
from ..services import identity
from .base import NetworkSourceAdapter

log = logging.getLogger("networkservice.sources.glinet")

# GL.iNet `iface` value -> (connection_type, band, is_guest)
_IFACE_MAP: dict[str, tuple[str, str, bool]] = {
    "2.4G": ("wifi", "2.4ghz", False),
    "2.4G_Guest": ("wifi", "2.4ghz", True),
    "5G": ("wifi", "5ghz", False),
    "5G_Guest": ("wifi", "5ghz", True),
    "6G": ("wifi", "6ghz", False),
    "6G_Guest": ("wifi", "6ghz", True),
    "cable": ("ethernet", "wired", False),
}


def _md5_crypt(password: str, salt: str, alg: int) -> str:
    """Unix MD5-crypt of the password with the challenge salt.

    Uses the stdlib ``crypt`` module (present on Python 3.11, which is the pinned
    container base image; removed in 3.13). If unavailable the adapter degrades to
    the last snapshot rather than crashing the poll loop.
    """
    import crypt  # noqa: PLC0415 — local import so a 3.13+ host degrades gracefully

    return crypt.crypt(password, f"${alg}${salt}")


class GlinetAdapter(NetworkSourceAdapter):
    source_type = "glinet"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        opts = config.options or {}
        self._username = opts.get("username", "root")
        self._password = os.environ.get(
            opts.get("password_env", "GLINET_PASSWORD"), opts.get("password", "")
        )
        self._sid: str | None = None
        self._client: httpx.AsyncClient | None = None
        self._rpc_id = 0

    async def start(self) -> None:
        base = self.config.base_url or "https://192.168.8.1:4443"
        # Self-signed cert on the router LAN UI → verify=False (LAN-only, trusted host).
        self._client = httpx.AsyncClient(
            base_url=base, timeout=self.settings.request_timeout, verify=False
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    # --- JSON-RPC plumbing ----------------------------------------------------
    async def _rpc(self, method: str, params: Any) -> dict:
        assert self._client is not None
        self._rpc_id += 1
        resp = await self._client.post(
            "/rpc", json={"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params}
        )
        resp.raise_for_status()
        return resp.json()

    async def _login(self) -> str:
        if not self._password:
            raise RuntimeError("GLINET_PASSWORD not set for source %s" % self.id)
        ch = (await self._rpc("challenge", {"username": self._username}))["result"]
        cipher = _md5_crypt(self._password, ch["salt"], ch["alg"])
        digest = hashlib.sha256(f"{self._username}:{cipher}:{ch['nonce']}".encode()).hexdigest()
        result = (await self._rpc("login", {"username": self._username, "hash": digest})).get("result", {})
        sid = result.get("sid")
        if not sid:
            raise RuntimeError("GL.iNet login failed (no sid)")
        self._sid = sid
        return sid

    async def _call(self, obj: str, method: str, params: dict | None = None) -> dict:
        """One ubus call, re-logging in once if the session expired."""
        if self._sid is None:
            await self._login()
        body = await self._rpc("call", [self._sid, obj, method, params or {}])
        err = body.get("error")
        if err and ("denied" in str(err.get("message", "")).lower() or err.get("code") in (-32002, 401, 403)):
            await self._login()
            body = await self._rpc("call", [self._sid, obj, method, params or {}])
        if body.get("error"):
            raise RuntimeError(f"{obj}.{method}: {body['error']}")
        return body.get("result", {})

    # --- normalization --------------------------------------------------------
    def _device_from_client(self, c: dict, channels: dict[str, int]) -> tuple[NetworkDevice, list[NetworkMetric]]:
        mac = identity.normalize_mac(c.get("mac"))
        iface = str(c.get("iface") or "")
        conn, band, is_guest = _IFACE_MAP.get(iface, ("unknown", "unknown", False))
        online = bool(c.get("online"))
        ip = c.get("ip") or None
        channel = channels.get(band)

        interfaces: list[NetworkInterface] = []
        if online and mac:
            interfaces.append(NetworkInterface(
                device_id=f"dev_{mac.replace(':', '')}", mac_address=mac, ip_address=ip,
                connection_type=conn, band=band, interface_name=iface or None, channel=channel,
            ))

        trust = "blocked" if c.get("blocked") else ("guest" if is_guest else "unknown")
        role = "guest_device" if is_guest else "unknown"
        alias = (c.get("alias") or "").strip() or None

        dev = NetworkDevice(
            id=f"dev_{mac.replace(':', '')}" if mac else (c.get("name") or "dev_unknown"),
            display_name=alias,
            host_name=(c.get("name") or "").strip() or None,
            mac_address=mac,
            ip_addresses=[ip] if ip else [],
            ipv6_addresses=[a for a in (c.get("ipv6") or []) if a],
            device_type="unknown",
            role=role,  # type: ignore[arg-type]
            trust_level=trust,  # type: ignore[arg-type]
            is_online=online,
            source_ids=[self.id],
            interfaces=interfaces,
            metadata={"glinet_class": c.get("class"), "guest": is_guest},
        )

        metrics: list[NetworkMetric] = []
        t = now()
        for field, mtype in (("total_rx", "device.rxBytes"), ("total_tx", "device.txBytes")):
            try:
                val = float(c.get(field))
            except (TypeError, ValueError):
                continue
            metrics.append(NetworkMetric(
                id=f"m_{mtype}_{dev.id}_{int(t)}", type=mtype, scope="device",
                device_id=dev.id, value=val, unit="bytes", source=self.id, sampled_at=t))
        return dev, metrics

    def _router_metrics(self, sys_status: dict, out: list[NetworkMetric]) -> float | None:
        """Extract router health metrics from ``system.get_status.system``.

        Best-effort/honest: only emits a metric for a field that's actually
        present. ``memory_total``/``memory_free`` give a real memory percent;
        there's no true CPU-utilization figure on this API, only temperature
        and load average, so ``router.cpuPercent`` stays unset.
        """
        t = now()

        def emit(mtype: str, value: Any, unit: str | None) -> None:
            if value is None:
                return
            out.append(NetworkMetric(
                id=f"m_{mtype}_{self.id}_{int(t)}", type=mtype, scope="router",
                value=float(value), unit=unit, source=self.id, sampled_at=t))

        mem_total = sys_status.get("memory_total")
        mem_free = sys_status.get("memory_free")
        if isinstance(mem_total, (int, float)) and mem_total and isinstance(mem_free, (int, float)):
            emit("router.memoryPercent", (1 - mem_free / mem_total) * 100, "percent")

        uptime = sys_status.get("uptime")
        emit("router.uptimeSeconds", uptime, "seconds")

        temp = (sys_status.get("cpu") or {}).get("temperature")
        emit("router.cpuTemperatureC", temp, "celsius")

        load = sys_status.get("load_average")
        if isinstance(load, list) and load:
            emit("router.loadAverage1m", load[0], None)

        return float(uptime) if isinstance(uptime, (int, float)) else None

    async def _poll(self) -> SourceSnapshot:
        if not self.config.base_url and not self._password:
            return SourceSnapshot(source_id=self.id, capabilities=[])

        clients = (await self._call("clients", "get_list")).get("clients", [])

        # per-band channel (best-effort; failure here must not drop the device list)
        channels: dict[str, int] = {}
        try:
            for radio in (await self._call("wifi", "get_status")).get("res", []):
                b = radio.get("band")
                ch = radio.get("channel")
                if b == "2g" and ch:
                    channels["2.4ghz"] = ch
                elif b == "5g" and ch:
                    channels["5ghz"] = ch
                elif b == "6g" and ch:
                    channels["6ghz"] = ch
        except Exception as exc:  # noqa: BLE001
            log.debug("wifi.get_status failed: %s", exc)

        router_uptime_seconds: float | None = None
        router_metrics: list[NetworkMetric] = []
        try:
            sys_status = (await self._call("system", "get_status")).get("system", {})
            router_uptime_seconds = self._router_metrics(sys_status, router_metrics)
        except Exception as exc:  # noqa: BLE001
            log.debug("system.get_status failed: %s", exc)

        devices: list[NetworkDevice] = []
        metrics: list[NetworkMetric] = []
        for c in clients:
            dev, dmetrics = self._device_from_client(c, channels)
            devices.append(dev)
            metrics.extend(dmetrics)

        online_wifi = sum(1 for d in devices if d.is_online and d.interfaces
                          and d.interfaces[0].connection_type == "wifi")
        metrics.append(NetworkMetric(
            id=f"m_wc_{int(now())}", type="wifi.clientCount", scope="wifi",
            value=online_wifi, unit="clients", source=self.id))
        metrics.extend(router_metrics)

        # ARP view (ip->mac) for the defensive ARP-spoof / MAC-conflict detector.
        arp = [{"ip": d.ip_addresses[0], "mac": d.mac_address}
               for d in devices if d.ip_addresses and d.mac_address]

        return SourceSnapshot(
            source_id=self.id,
            devices=devices,
            metrics=metrics,
            router_online=True,  # a successful authenticated poll implies reachability
            router_uptime_seconds=router_uptime_seconds,
            security_signals={"arp": arp},
            capabilities=["dhcpLeases", "wifiAssociations", "interfaceCounters", "routerHealth"],
        )
