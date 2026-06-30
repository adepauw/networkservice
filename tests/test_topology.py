"""Topology grouping — devices fall into the right buckets with correct counts."""

from __future__ import annotations

from app.config import Settings
from app.models import NetworkDevice, NetworkInterface
from app.services.topology import TopologyService


def _dev(did, dtype="unknown", role="unknown", trust="known", online=True,
         conn="unknown", band="unknown", guest=False) -> NetworkDevice:
    iface = NetworkInterface(device_id=did, connection_type=conn, band=band)
    return NetworkDevice(
        id=did, mac_address=f"00:00:00:00:00:{did[-2:]}",
        device_type=dtype, role=role, trust_level=("guest" if guest else trust),
        is_known=True, is_online=online, interfaces=[iface])


def test_topology_groups_devices_correctly():
    devices = [
        _dev("dev_router", dtype="router", role="infrastructure", conn="ethernet", band="wired"),
        _dev("dev_nas", role="server", conn="ethernet", band="wired"),
        _dev("dev_phone", conn="wifi", band="5ghz"),
        _dev("dev_sensor", role="smart_home", conn="wifi", band="2.4ghz"),
        _dev("dev_guest", guest=True, conn="wifi", band="5ghz"),
        _dev("dev_off", online=False),
    ]
    topo = TopologyService(Settings()).build(devices)
    counts = topo.counts
    assert counts.get("router", 0) == 1
    assert counts.get("wired", 0) == 1  # NAS (router lands in router group)
    assert counts.get("wifi_5", 0) == 1  # phone
    assert counts.get("wifi_2_4", 0) == 1  # sensor
    assert counts.get("guest", 0) == 1
    assert counts.get("offline", 0) == 1


def test_topology_counts_unknown_and_links_to_router():
    devices = [
        _dev("dev_router", dtype="router", role="infrastructure", conn="ethernet", band="wired"),
        _dev("dev_mystery", conn="unknown"),
    ]
    topo = TopologyService(Settings()).build(devices)
    assert topo.counts.get("unknown", 0) == 1
    # every non-router node links back to the router node
    router_node = next(n for g in topo.groups if g.id == "router" for n in g.nodes)
    assert all(l.source_id == router_node.id for l in topo.links)
    assert topo.links  # at least the mystery device is linked
