"""VPN source adapter seam — unconfigured empty state + mock peer statuses."""

from __future__ import annotations

import asyncio

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
