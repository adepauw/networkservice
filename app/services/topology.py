"""Topology — a simple, grouped view of the network, not a graph engine.

We bucket every device into one connectivity/role group (router, wired, the three
WiFi bands, guest, vpn, infrastructure, smart_home, unknown, offline) and hang a
light star of links off the router. That's enough for CatOS to answer "how are my
devices grouped" and to filter the device list by group — without a heavy
force-directed graph the mobile UI doesn't need yet.
"""

from __future__ import annotations

from ..config import Settings
from ..models import (
    NetworkDevice,
    NetworkTopology,
    TopologyGroup,
    TopologyGroupId,
    TopologyLink,
    TopologyNode,
    VpnPeer,
)

GROUP_LABELS: dict[str, str] = {
    "router": "Router",
    "wired": "Bekabeld",
    "wifi_2_4": "WiFi 2.4 GHz",
    "wifi_5": "WiFi 5 GHz",
    "wifi_6": "WiFi 6 GHz",
    "guest": "Gasten",
    "vpn": "VPN",
    "infrastructure": "Infrastructuur",
    "smart_home": "Smart home",
    "unknown": "Onbekend",
    "offline": "Offline",
}

# stable render/order of the groups in the UI.
GROUP_ORDER: list[TopologyGroupId] = [
    "router", "wired", "wifi_5", "wifi_6", "wifi_2_4", "guest", "vpn",
    "smart_home", "infrastructure", "unknown", "offline",
]

_BAND_GROUP: dict[str, TopologyGroupId] = {
    "2.4ghz": "wifi_2_4", "5ghz": "wifi_5", "6ghz": "wifi_6",
}


def _group_for(device: NetworkDevice) -> TopologyGroupId:
    iface = device.interfaces[0] if device.interfaces else None
    if not device.is_online:
        return "offline"
    if device.device_type == "router" or device.role == "infrastructure" and device.device_type in ("router", "access_point"):
        return "router"
    if device.trust_level == "guest" or device.role == "guest_device":
        return "guest"
    conn = iface.connection_type if iface else "unknown"
    if conn == "vpn":
        return "vpn"
    if conn == "ethernet":
        return "wired"
    if conn == "wifi":
        return _BAND_GROUP.get(iface.band if iface else "unknown", "unknown")
    if device.role == "smart_home":
        return "smart_home"
    if device.role == "infrastructure":
        return "infrastructure"
    return "unknown"


class TopologyService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build(self, devices: list[NetworkDevice],
              vpn_peers: list[VpnPeer] | None = None) -> NetworkTopology:
        buckets: dict[TopologyGroupId, list[TopologyNode]] = {g: [] for g in GROUP_ORDER}
        router_id: str | None = None
        for d in devices:
            group = _group_for(d)
            iface = d.interfaces[0] if d.interfaces else None
            node = TopologyNode(
                id=f"node_{d.id}", device_id=d.id, display_name=d.name,
                device_type=d.device_type, role=d.role, trust_level=d.trust_level,
                status="online" if d.is_online else "offline",
                group=group,
                connection_type=iface.connection_type if iface else "unknown",
            )
            if group == "router" and router_id is None:
                router_id = node.id
            buckets[group].append(node)

        # add VPN peers that aren't already a known device as synthetic nodes.
        known_device_ids = {d.id for d in devices}
        for peer in (vpn_peers or []):
            if peer.device_id and peer.device_id in known_device_ids:
                continue
            buckets["vpn"].append(TopologyNode(
                id=f"node_vpn_{peer.id}", device_id=peer.device_id,
                display_name=peer.display_name, device_type="unknown",
                role="unknown", trust_level="known",
                status="online" if peer.status in ("connected", "online") else "offline",
                group="vpn", connection_type="vpn",
                metadata={"vpn_peer": True, "source": peer.source},
            ))

        groups: list[TopologyGroup] = []
        links: list[TopologyLink] = []
        for gid in GROUP_ORDER:
            nodes = buckets[gid]
            if not nodes and gid not in ("router", "wired"):
                continue
            groups.append(TopologyGroup(id=gid, label=GROUP_LABELS[gid],
                                        device_count=len(nodes), nodes=nodes))
            if router_id and gid != "router":
                for node in nodes:
                    node.parent_id = router_id
                    links.append(TopologyLink(
                        source_id=router_id, target_id=node.id,
                        type="vpn" if gid == "vpn" else (
                            "wired" if gid == "wired" else "wifi" if gid.startswith("wifi") else "uplink"),
                    ))

        counts = {g.id: g.device_count for g in groups}
        return NetworkTopology(groups=groups, links=links, counts=counts,
                               metadata={"router_node_id": router_id})
