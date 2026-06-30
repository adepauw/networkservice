"""VPN rollup — aggregates peers/status from any configured VPN source (Tailscale,
WireGuard, GL.iNet/OpenWrt VPN) into one ``VpnSummary`` plus the flat peer list.

Like DNS, this is source-pluggable and honest: with no VPN source configured the
summary comes back ``configured=False`` / ``unconfigured`` so the UI shows
"Geen VPN-bron geconfigureerd". A peer that hasn't handshaken within
``vpn_peer_stale_seconds`` is marked ``stale`` rather than silently "connected".
"""

from __future__ import annotations

from ..config import Settings
from ..models import (
    NetworkDevice,
    SourceSnapshot,
    VpnPeer,
    VpnSourceStatus,
    VpnStatus,
    VpnSummary,
    now,
)


def _is_connected(peer: VpnPeer) -> bool:
    return peer.status in ("connected", "online")


class VpnService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _mark_stale(self, peer: VpnPeer) -> VpnPeer:
        """A peer whose last handshake is older than the stale window is downgraded
        from connected → stale (so we don't over-claim a live tunnel)."""
        if peer.status not in ("connected", "online"):
            return peer
        ref = peer.last_handshake_at or peer.last_seen_at
        if ref is not None and (now() - ref) > self.settings.vpn_peer_stale_seconds:
            stale = peer.model_copy(deep=True)
            stale.status = "stale"
            return stale
        return peer

    def collect_peers(self, snapshots: list[SourceSnapshot],
                      devices: list[NetworkDevice]) -> list[VpnPeer]:
        peers: list[VpnPeer] = []
        by_mac = {(d.mac_address or "").lower(): d for d in devices if d.mac_address}
        for snap in snapshots:
            if snap.vpn is None:
                continue
            for peer in snap.vpn.peers:
                peer = self._mark_stale(peer)
                if peer.device_id is None:
                    mac = str(peer.metadata.get("mac") or "").lower()
                    if mac in by_mac:
                        peer = peer.model_copy(update={"device_id": by_mac[mac].id})
                peers.append(peer)
        return peers

    def source_statuses(self, snapshots: list[SourceSnapshot],
                        descriptions: dict[str, str]) -> list[VpnSourceStatus]:
        out: list[VpnSourceStatus] = []
        for snap in snapshots:
            if snap.vpn is None:
                continue
            peers = [self._mark_stale(p) for p in snap.vpn.peers]
            connected = sum(1 for p in peers if _is_connected(p))
            out.append(VpnSourceStatus(
                id=snap.source_id,
                type=descriptions.get(snap.source_id, "unknown"),  # type: ignore[arg-type]
                display_name=descriptions.get(f"{snap.source_id}:name", snap.source_id),
                status=snap.vpn.status,
                peer_count=len(peers), connected_peer_count=connected,
                last_success_at=now(),
            ))
        return out

    def build_summary(self, snapshots: list[SourceSnapshot], devices: list[NetworkDevice],
                      descriptions: dict[str, str],
                      configured_count: int) -> VpnSummary:
        contributing = [s for s in snapshots if s.vpn is not None]
        if not self.settings.vpn_enabled and configured_count == 0:
            return VpnSummary(configured=False, status="unknown",
                              metadata={"reason": "no VPN source configured"})
        if not contributing:
            status: VpnStatus = "degraded" if configured_count else "unknown"
            return VpnSummary(configured=configured_count > 0, status=status)

        peers = self.collect_peers(snapshots, devices)
        sources = self.source_statuses(snapshots, descriptions)
        connected = sum(1 for p in peers if _is_connected(p))
        # overall status: worst of the sources, but online if any source is online
        # with at least one connected peer.
        if any(s.status == "online" for s in sources) and connected > 0:
            status = "online"
        elif any(s.status in ("online", "degraded") for s in sources):
            status = "degraded"
        elif sources:
            status = "offline"
        else:
            status = "unknown"
        return VpnSummary(
            configured=True, status=status,
            peer_count=len(peers), connected_peer_count=connected,
            sources=sources, last_change_at=None, history_available=False,
        )
