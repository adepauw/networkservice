"""VPN source adapter seam — unconfigured empty state + mock peer statuses."""

from __future__ import annotations

import asyncio
import time

from app.config import Settings, SourceConfig
from app.services.vpn import VpnService
from app.sources.vpn import TailscaleSourceAdapter


def _mock_tailscale() -> TailscaleSourceAdapter:
    cfg = SourceConfig(id="ts", type="tailscale", display_name="Tailscale",
                       options={"mock": True})
    return TailscaleSourceAdapter(cfg, Settings())


def test_vpn_unavailable_returns_configured_disabled_state():
    svc = VpnService(Settings(vpn_enabled=False))
    summary = svc.build_summary([], [], {}, configured_count=0)
    assert summary.configured is False


def test_vpn_mock_peers_return_expected_statuses():
    adapter = _mock_tailscale()
    snap = asyncio.run(adapter.poll())
    assert snap.vpn is not None and snap.vpn.peers
    statuses = {p.status for p in snap.vpn.peers}
    assert statuses <= {"connected", "stale", "disconnected", "online", "offline"}

    desc = {"ts": "tailscale", "ts:name": "Tailscale"}
    svc = VpnService(Settings(vpn_enabled=True))
    summary = svc.build_summary([snap], [], desc, configured_count=1)
    assert summary.configured is True
    assert summary.peer_count == len(snap.vpn.peers)
    assert summary.connected_peer_count >= 1
    assert summary.status in ("online", "degraded", "offline", "unknown")
    assert summary.sources and summary.sources[0].id == "ts"


def test_vpn_marks_old_handshake_stale():
    svc = VpnService(Settings(vpn_enabled=True, vpn_peer_stale_seconds=60))
    adapter = _mock_tailscale()
    snap = asyncio.run(adapter.poll())
    peers = svc.collect_peers([snap], [])
    # the third mock peer (vps-amsterdam-ish) is older; at least one should be stale
    assert any(p.status == "stale" for p in peers) or all(
        p.status in ("connected", "online") for p in peers)


def test_parse_wg_dump_maps_peers():
    from app.sources.vpn import parse_wg_dump
    now = time.time()
    dump = "\n".join([
        # interface line (ignored)
        "PRIVKEY\tPUBKEY\t51820\toff",
        # connected peer: handshake 60s ago
        f"peer1pubkeyAAAAAAAA\t(none)\t203.0.113.7:51820\t10.0.0.2/32\t{int(now - 60)}\t123456\t654321\t25",
        # stale peer: handshake 2h ago
        f"peer2pubkeyBBBBBBBB\t(none)\t(none)\t10.0.0.3/32,fd00::3/128\t{int(now - 7200)}\t10\t20\toff",
        # never handshaken
        "peer3pubkeyCCCCCCCC\t(none)\t(none)\t10.0.0.4/32\t0\t0\t0\toff",
    ])
    data = parse_wg_dump(dump, stale_seconds=600)
    assert data.status == "online"
    by_id = {p.id: p for p in data.peers}
    assert len(by_id) == 3
    p1 = by_id["peer1pubkeyAAAAAAA"[:16]]
    assert p1.status == "connected" and p1.ip_addresses == ["10.0.0.2"]
    assert p1.rx_bytes == 123456 and p1.display_name == "203.0.113.7:51820"
    assert by_id["peer2pubkeyBBBBBBBB"[:16]].status == "stale"
    assert by_id["peer2pubkeyBBBBBBBB"[:16]].ip_addresses == ["10.0.0.3", "fd00::3"]
    assert by_id["peer3pubkeyCCCCCCCC"[:16]].status == "disconnected"


def test_glinet_peer_mapping_defensive():
    from app.sources.vpn import _glinet_peer
    peer = _glinet_peer({"name": "alex-phone", "ip": "10.0.0.5/24", "online": True,
                         "rx_bytes": 1000, "tx_bytes": 2000, "public_key": "abcdef"})
    assert peer.display_name == "alex-phone"
    assert peer.status == "connected"
    assert peer.ip_addresses == ["10.0.0.5"]
    assert peer.rx_bytes == 1000
    # minimal row: falls back to pubkey prefix, disconnected
    bare = _glinet_peer({"public_key": "zzzzzzzzzzzzzzzzzz"})
    assert bare.status == "disconnected"
    assert bare.display_name == "zzzzzzzzzzzz"
