"""Mock source — a realistic, *evolving* home network.

Rich enough to make the API and the CatOS Network page genuinely useful with no
router configured. It models a believable household: phones, laptops, a NAS/server,
a Hue bridge, a Nuki lock, a doorbell camera, weak-WiFi IoT, an offline known
device, plus the occasional unknown device joining. State drifts a little each
poll (RSSI wander, the unknown device coming and going, throughput) so events,
presence transitions and the threat detector all have something to react to.

It can also emit *defensive* security signals (a simulated deauth burst, a rogue
SSID, an ARP anomaly) so the threat-detection path is exercisable end to end. It
never performs anything — these are observations the security service interprets.
"""

from __future__ import annotations

import random
import time

from ..models import (
    NetworkDevice,
    NetworkInterface,
    NetworkMetric,
    SourceSnapshot,
    now,
)
from .base import NetworkSourceAdapter


def _iface(device_id: str, mac: str, ip: str, **kw) -> NetworkInterface:
    return NetworkInterface(device_id=device_id, mac_address=mac, ip_address=ip, **kw)


class MockNetworkSourceAdapter(NetworkSourceAdapter):
    source_type = "mock"

    def __init__(self, config, settings) -> None:
        super().__init__(config, settings)
        self._tick = 0
        self._rng = random.Random(42)
        self._unknown_present = False
        self._boot = time.time()

    async def _poll(self) -> SourceSnapshot:
        self._tick += 1
        t = now()
        devices: list[NetworkDevice] = []
        metrics: list[NetworkMetric] = []

        # --- infrastructure ---------------------------------------------------
        devices.append(NetworkDevice(
            id="dev_router", host_name="flint2", display_name="Flint 2",
            mac_address="94:83:c4:00:00:01", ip_addresses=["192.168.8.1"],
            vendor="GL Technologies", device_type="router", role="infrastructure",
            trust_level="trusted", is_known=True, is_online=True,
            source_ids=[self.id],
            interfaces=[_iface("dev_router", "94:83:c4:00:00:01", "192.168.8.1",
                               connection_type="ethernet", band="wired")],
        ))
        devices.append(NetworkDevice(
            id="dev_nas", host_name="phobos", display_name="Phobos NAS",
            mac_address="00:11:22:33:44:55", ip_addresses=["192.168.8.10"],
            vendor="Intel", device_type="nas", role="server",
            trust_level="trusted", is_known=True, is_online=True,
            presence_candidate=False, automation_candidate=True, source_ids=[self.id],
            interfaces=[_iface("dev_nas", "00:11:22:33:44:55", "192.168.8.10",
                               connection_type="ethernet", band="wired",
                               rx_rate_mbps=940, tx_rate_mbps=940)],
        ))

        # --- smart home -------------------------------------------------------
        devices.append(NetworkDevice(
            id="dev_hue", host_name="hue-bridge", display_name="Hue Bridge",
            mac_address="00:17:88:aa:bb:cc", ip_addresses=["192.168.8.50"],
            vendor="Signify (Philips Hue)", device_type="bridge", role="smart_home",
            trust_level="trusted", is_known=True, is_online=True, source_ids=[self.id],
            interfaces=[_iface("dev_hue", "00:17:88:aa:bb:cc", "192.168.8.50",
                               connection_type="ethernet", band="wired")],
        ))
        devices.append(NetworkDevice(
            id="dev_nuki", host_name="nuki-bridge", display_name="Nuki Slot",
            mac_address="54:d2:72:11:22:33", ip_addresses=["192.168.8.51"],
            vendor="Nuki Home Solutions", device_type="smart_lock", role="smart_home",
            trust_level="trusted", is_known=True, is_online=True, source_ids=[self.id],
            interfaces=[_iface("dev_nuki", "54:d2:72:11:22:33", "192.168.8.51",
                               connection_type="wifi", band="2.4ghz", channel=6,
                               ssid="catnet", rssi=-58)],
        ))
        devices.append(NetworkDevice(
            id="dev_doorbell", host_name="doorbell", display_name="Deurbel Camera",
            mac_address="b0:c5:54:44:55:66", ip_addresses=["192.168.8.52"],
            vendor="Hikvision", device_type="camera", role="smart_home",
            trust_level="known", is_known=True, is_online=True, source_ids=[self.id],
            interfaces=[_iface("dev_doorbell", "b0:c5:54:44:55:66", "192.168.8.52",
                               connection_type="wifi", band="2.4ghz", channel=6,
                               ssid="catnet", rssi=-67)],
        ))

        # --- resident devices (presence candidates) ---------------------------
        # Primary phone — always home in the mock, with a little RSSI wander.
        phone_rssi = -52 + self._rng.randint(-6, 6)
        devices.append(NetworkDevice(
            id="dev_phone_alex", host_name="alex-iphone", display_name="Alex iPhone",
            mac_address="a4:83:e7:77:88:99", ip_addresses=["192.168.8.20"],
            vendor="Apple", device_type="phone", role="resident_device",
            trust_level="trusted", is_known=True, is_online=True,
            presence_candidate=True, owner="alex", source_ids=[self.id],
            interfaces=[_iface("dev_phone_alex", "a4:83:e7:77:88:99", "192.168.8.20",
                               connection_type="wifi", band="5ghz", channel=44,
                               ssid="catnet", rssi=phone_rssi,
                               tx_rate_mbps=480, rx_rate_mbps=620)],
        ))
        # Laptop — supporting device, goes offline on odd ticks to exercise grace.
        laptop_online = self._tick % 4 != 0
        devices.append(NetworkDevice(
            id="dev_laptop_alex", host_name="alex-mbp", display_name="Alex MacBook",
            mac_address="f0:18:98:ab:cd:ef", ip_addresses=["192.168.8.21"],
            vendor="Apple", device_type="laptop", role="workstation",
            trust_level="trusted", is_known=True, is_online=laptop_online,
            presence_candidate=False, owner="alex", source_ids=[self.id],
            interfaces=[_iface("dev_laptop_alex", "f0:18:98:ab:cd:ef", "192.168.8.21",
                               connection_type="wifi", band="5ghz", channel=44,
                               ssid="catnet", rssi=-61)] if laptop_online else [],
        ))

        # --- weak-WiFi IoT (drives wifi.signalPoor) ---------------------------
        iot_rssi = -78 + self._rng.randint(-4, 2)
        devices.append(NetworkDevice(
            id="dev_iot_sensor", host_name="esp-garage", display_name="Garage Sensor",
            mac_address="dc:4f:22:de:ad:01", ip_addresses=["192.168.8.80"],
            vendor="Espressif", device_type="iot", role="smart_home",
            trust_level="known", is_known=True, is_online=True, source_ids=[self.id],
            interfaces=[_iface("dev_iot_sensor", "dc:4f:22:de:ad:01", "192.168.8.80",
                               connection_type="wifi", band="2.4ghz", channel=11,
                               ssid="catnet", rssi=iot_rssi)],
        ))

        # --- a known device that is currently offline -------------------------
        devices.append(NetworkDevice(
            id="dev_tv", host_name="living-tv", display_name="Woonkamer TV",
            mac_address="ac:bc:32:01:02:03", ip_addresses=["192.168.8.30"],
            vendor="LG Electronics", device_type="tv", role="media",
            trust_level="known", is_known=True, is_online=False, source_ids=[self.id],
        ))

        # --- an unknown device that comes and goes (drives unknownJoined) -----
        # Flips roughly every 6 ticks.
        if self._tick % 6 == 0:
            self._unknown_present = not self._unknown_present
        if self._unknown_present:
            devices.append(NetworkDevice(
                id="dev_unknown_1", host_name="android-2f1a",
                mac_address="3e:9a:71:5c:1d:2f",  # locally-administered (random MAC)
                ip_addresses=["192.168.8.142"],
                vendor=None, device_type="phone", role="unknown",
                trust_level="unknown", is_known=False, is_online=True,
                source_ids=[self.id],
                interfaces=[_iface("dev_unknown_1", "3e:9a:71:5c:1d:2f", "192.168.8.142",
                                   connection_type="wifi", band="5ghz", channel=44,
                                   ssid="catnet", rssi=-70)],
            ))

        # --- metrics ----------------------------------------------------------
        uptime = t - self._boot + 3600 * 72  # pretend the router's been up a while
        metrics.append(NetworkMetric(id=f"m_lat_{self._tick}", type="internet.latencyMs",
                                      scope="internet", value=round(8 + self._rng.random() * 10, 1),
                                      unit="ms", source=self.id))
        metrics.append(NetworkMetric(id=f"m_dl_{self._tick}", type="internet.downloadMbps",
                                      scope="internet", value=round(480 + self._rng.random() * 60, 0),
                                      unit="Mbps", source=self.id))
        metrics.append(NetworkMetric(id=f"m_ul_{self._tick}", type="internet.uploadMbps",
                                      scope="internet", value=round(48 + self._rng.random() * 8, 0),
                                      unit="Mbps", source=self.id))
        metrics.append(NetworkMetric(id=f"m_cpu_{self._tick}", type="router.cpuPercent",
                                      scope="router", value=round(6 + self._rng.random() * 20, 0),
                                      unit="%", source=self.id))
        metrics.append(NetworkMetric(id=f"m_mem_{self._tick}", type="router.memoryPercent",
                                      scope="router", value=round(34 + self._rng.random() * 10, 0),
                                      unit="%", source=self.id))
        metrics.append(NetworkMetric(id=f"m_up_{self._tick}", type="router.uptimeSeconds",
                                      scope="router", value=round(uptime), unit="s", source=self.id))
        clients = sum(1 for d in devices if d.is_online and d.interfaces
                      and d.interfaces[0].connection_type == "wifi")
        metrics.append(NetworkMetric(id=f"m_wc_{self._tick}", type="wifi.clientCount",
                                     scope="wifi", value=clients, unit="clients", source=self.id))
        # per-device throughput so the traffic insights cards have data. rx is the
        # heavier direction; a couple of devices (NAS backup, a phone upload) push
        # enough up to occasionally trip the unusual-upload threshold.
        for d in devices:
            if not d.is_online:
                continue
            # key metrics by the canonical mac-based id the inventory will assign
            # (dev_<machex>), matching the live adapters — otherwise per-device
            # traffic can't be tied back to the merged device.
            canonical = f"dev_{d.mac_address.replace(':', '')}" if d.mac_address else d.id
            rx = round(self._rng.random() * 5_000_000)
            up_heavy = d.device_type in ("nas", "server")
            tx = round(self._rng.random() * (2_500_000 if up_heavy else 400_000))
            metrics.append(NetworkMetric(
                id=f"m_rx_{canonical}_{self._tick}", type="device.rxBytes", scope="device",
                device_id=canonical, value=rx, unit="bytes", source=self.id))
            metrics.append(NetworkMetric(
                id=f"m_tx_{canonical}_{self._tick}", type="device.txBytes", scope="device",
                device_id=canonical, value=tx, unit="bytes", source=self.id))

        # --- defensive security signals (detection inputs only) ---------------
        signals: dict = {}
        # Occasionally simulate a deauth burst against the WiFi so the detector fires.
        if self._tick % 11 == 0:
            signals["deauth_frames_last_interval"] = 140
            signals["deauth_target_bssid"] = "94:83:c4:00:00:02"
        # Occasionally surface a rogue SSID mimicking ours (evil-twin fingerprint).
        if self._tick % 13 == 0:
            signals["nearby_ssids"] = [
                {"ssid": "catnet", "bssid": "94:83:c4:00:00:02", "rssi": -44, "known": True},
                {"ssid": "catnet", "bssid": "de:ad:be:ef:00:01", "rssi": -39, "known": False},
            ]
        # ARP table (used for ARP-spoof / MAC-conflict detection).
        signals["arp"] = [
            {"ip": d.ip_addresses[0], "mac": d.mac_address}
            for d in devices if d.ip_addresses and d.mac_address
        ]
        # Open inbound ports the firewall currently exposes (port-exposure deltas).
        signals["open_ports"] = [] if self._tick % 17 else [{"proto": "tcp", "port": 32400}]

        return SourceSnapshot(
            source_id=self.id,
            devices=devices,
            metrics=metrics,
            router_online=True,
            router_uptime_seconds=uptime,
            internet_online=True,
            dns_online=True,
            firewall_summary={"default_input": "DROP", "open_ports": signals["open_ports"]},
            security_signals=signals,
            capabilities=list(self.config.capabilities),
        )
