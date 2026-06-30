# Network — Sprint 3: "Network becomes powerful"

Sprint 1 made the network domain *useful* (devices, presence, unknown-device
flow). Sprint 2 made it *diagnostic* (internet/WiFi/router health). Sprint 3 makes
it a genuine smart-home intelligence layer: it can wake trusted machines, show who
used the most traffic, report whether DNS protection is working, surface VPN
status and peers, and group the network into a simple topology — all while staying
defensive, source-pluggable and honest about what data is and isn't available.

Built on top of the existing service — nothing from Sprint 1/2 was rebuilt.

CatOS can now answer:

```
Can I wake my trusted desktop/NAS/server?
Which devices used the most traffic recently?
Is DNS protection working? Which devices generate many DNS queries? Are blocks happening?
Is VPN/Tailscale/WireGuard healthy? Which peers are connected?
How are devices grouped across WiFi, wired, guest, VPN and infrastructure?
Is there a simple network topology overview?
Can the rule engine react to DNS, traffic and VPN state?
```

---

## 1. Wake-on-LAN polish

`app/services/wol.py` now carries an explicit **eligibility model** so the UI only
ever offers Wake for a device that can actually be woken, and returns a structured
`WakeResult` so the outcome is unambiguous.

A device is wakeable only when **all** hold:

```
device is known (not unknown/guest/ignored)
trust_level is trusted or known
MAC address is known
role ∈ wol_allowed_roles  OR  device_type ∈ wol_allowed_device_types
Wake-on-LAN is enabled
```

Defaults: roles `workstation, server, media, infrastructure`; types
`desktop, server, nas, laptop, tv`. Phones, IoT sensors, cameras and guests are
never wake targets.

### Result model

```
WakeResult: device_id, attempted_at, target_mac, broadcast_address,
            status, message, metadata
status ∈ sent | unsupported | forbidden | failed | unknown
```

### Endpoints

```
POST /devices/{id}/wake          → 200 {ok, result} on sent; 403 forbidden /
                                     501 unsupported / 502 failed otherwise
GET  /devices/{id}/wake/status   → {eligibility: {can_wake, reason, target_mac, ...}}
```

`/wake/status` returns 200 even for an ineligible-but-known device (with
`can_wake:false` and a Dutch `reason`); 404 only for a truly unknown id.

### Events (timeline, no alerts by default)

```
device.wakeRequested   device.wakeSent   device.wakeFailed
```

Example:

```json
POST /devices/dev_00112233445566/wake
{ "ok": true, "result": {
    "device_id": "dev_00112233445566", "status": "sent",
    "target_mac": "00:11:22:33:44:55", "broadcast_address": "255.255.255.255",
    "message": "Wake-on-LAN verzonden" } }
```

---

## 2. Traffic insights

`app/services/traffic.py` builds a pragmatic rollup from whatever byte counters the
sources already provide (`device.rxBytes` / `device.txBytes` per-poll deltas, plus
the internet up/down metrics). No NetFlow; no fabricated history.

```
TrafficSummary: sampled_at, total_rx_bytes, total_tx_bytes,
  current_download_bps, current_upload_bps,
  top_download_devices[], top_upload_devices[], unusual_devices[],
  period, history_available, source, metadata
TrafficDeviceStats: device_id, display_name, rx_bytes, tx_bytes,
  download_bps, upload_bps, total_bytes, period, rank, is_unusual
```

A device is flagged `is_unusual` only when it crosses a conservative threshold
(default 50 Mbps sustained download, 10 Mbps sustained upload) — normal
streaming/downloads stay quiet. If a source can't break traffic down per device,
the summary comes back with empty top lists and an honest `metadata.reason`.

### Endpoints

```
GET /traffic/summary?period=now|hour|day&limit=10
GET /traffic/devices?period=…&limit=50
GET /traffic/devices/{device_id}
GET /traffic/history?limit=&since=
```

Only `period=now` (→ `current`) carries real data today; `hour`/`day` are accepted
and labelled honestly without fabricated aggregation.

### Events (conservative — info severity, timeline only)

```
traffic.highUsage       (hysteretic: one event per high-usage spell)
traffic.unusualUpload
traffic.spike           (reserved)
```

---

## 3. DNS / AdGuard / Pi-hole source adapter

DNS analytics is a **source-pluggable seam**, not hardcoded into the router.

* Adapters: `AdGuardSourceAdapter` (live AdGuard control API wired),
  `PiHoleSourceAdapter` (skeleton + TODOs), `DnsSourceAdapter` (generic). All in
  `app/sources/dns.py`. Each serves a realistic **mock** when `options.mock` is set
  or no `base_url` is configured — so the DNS card is demoable without credentials.
* Aggregation: `app/services/dns.py` folds every DNS source into one `DnsSummary`.

```
DnsSummary: sampled_at, configured, query_count, blocked_count, blocked_percent,
  top_devices[], top_domains[], top_blocked_domains[], protection_status,
  sources[], history_available
DnsDeviceStats: device_id, display_name, query_count, blocked_count,
  blocked_percent, top_domains, top_blocked_domains, last_query_at, is_noisy
protection_status ∈ active | degraded | unconfigured | unknown
```

**Privacy:** in the default `summary` privacy mode only aggregate per-device counts
and the source's own top-N domain rankings are surfaced — never a full query log.
Suspicious-domain detection is deliberately conservative.

When no DNS source is configured the summary is `configured:false` /
`protection_status:unconfigured` so the UI shows "Geen DNS-bron geconfigureerd".

### Endpoints

```
GET /dns/summary   GET /dns/devices   GET /dns/devices/{id}
GET /dns/blocked   GET /dns/history
```

### Events

```
dns.protectionActive   dns.protectionDegraded(warning)   dns.protectionRecovered
dns.blockedSpike(warning)   dns.deviceNoisy   dns.suspiciousDomain
```

---

## 4. VPN / Tailscale / WireGuard status

VPN monitoring is the same pluggable-source concept (`app/sources/vpn.py`):

* Adapters: `TailscaleSourceAdapter` (live `tailscale status --json` wired),
  `WireGuardSourceAdapter`, `GlinetVpnSourceAdapter`, `OpenWrtVpnSourceAdapter`
  (skeletons + TODOs). Mock peers when `options.mock`/no `base_url`.
* Aggregation: `app/services/vpn.py` → `VpnSummary` + flat peer list. A peer whose
  last handshake is older than `vpn_peer_stale_seconds` (default 600) is downgraded
  to `stale` rather than over-claiming a live tunnel.

```
VpnSummary: sampled_at, configured, status, peer_count, connected_peer_count,
  sources[], last_change_at, history_available
VpnPeer: id, display_name, source, type, status, ip_addresses,
  last_seen_at, last_handshake_at, rx_bytes, tx_bytes, device_id
status ∈ online | degraded | offline | unknown
peer.status ∈ connected | disconnected | stale | online | offline | unknown
```

### Endpoints

```
GET /vpn/summary   GET /vpn/peers   GET /vpn/peers/{id}   GET /vpn/history
```

### Events

```
vpn.peerConnected   vpn.peerDisconnected   vpn.peerStale
vpn.sourceDegraded(warning)   vpn.sourceRecovered
```

---

## 5. Basic topology view

`app/services/topology.py` buckets every device into one connectivity/role group
and hangs a light star of links off the router — enough to answer "how are my
devices grouped" and to filter the device list, without a heavy graph.

```
groups: router, wired, wifi_2_4, wifi_5, wifi_6, guest, vpn,
        infrastructure, smart_home, unknown, offline
TopologyNode: id, device_id, display_name, device_type, role, trust_level,
  status, group, connection_type, parent_id
TopologyLink: source_id, target_id, type, quality
```

### Endpoint

```
GET /topology
{ "available": true,
  "groups": [ { "id": "wifi_5", "label": "WiFi 5 GHz", "device_count": 14, "nodes": [...] } ],
  "links": [...], "counts": { "router": 1, "wifi_5": 14, ... } }
```

---

## 6. catosservice integration

The existing generic relay does most of the work:

* **Dashboard** — `networkservice /summary` now carries compact `traffic`, `dns`,
  `vpn` and `topology` blocks, folded into `dashboard.network.summary`
  (`NetworkCard`) with no extra round-trips.
* **Timeline** — `NetworkEventMonitor` already relays every networkservice event
  (minus a churn denylist) into the house timeline, so all the new wake/traffic/
  dns/vpn events appear automatically.
* **Alerts** — open warning/critical networkservice events become catosservice
  alerts and resolve on recovery. Severity is chosen at emit time so only the
  significant Sprint 3 events alert (see below); info-level traffic/peer events stay
  timeline-only to avoid fatigue.
* **Rule facts** — `facts.network.{traffic,dns,vpn,topology}` exposed to the engine.

### Conservative alert mapping (by emitted severity)

```
dns.protectionDegraded   → alert (warning)
dns.blockedSpike         → alert (warning, only when % jumps past threshold)
vpn.sourceDegraded       → alert (warning)
traffic.unusualUpload    → timeline only (info)
traffic.highUsage        → timeline only (info)
vpn.peerConnected/Stale  → timeline only (info)
```

### Rule-engine facts

```
network.traffic.currentDownloadBps   network.traffic.currentUploadBps
network.traffic.topDevice            network.traffic.highUsageActive
network.dns.protectionStatus         network.dns.blockedCount
network.dns.blockedPercent           network.dns.deviceNoisy
network.vpn.status                   network.vpn.connectedPeerCount
network.vpn.peerConnected
network.topology.unknownCount        network.topology.guestCount
```

(`network.device.canWake` is per-device and lives on `GET /devices/{id}/wake/status`,
not in the aggregate facts.)

---

## 7. CatOS UI

`catos/src/services/networkClient.ts` gains typed functions for every new endpoint
(`wakeNetworkDevice`, `getWakeStatus`, `getTraffic*`, `getDns*`, `getVpn*`,
`getNetworkTopology`). The Network page adds compact **Traffic**, **DNS
bescherming**, **VPN** and **Topologie** cards (with graceful Dutch empty states),
and Device Detail shows a Wake action **only when eligible** (driven by
`/wake/status`) plus a per-device traffic stats card. All Sprint 1/2 cards are
intact.

Empty states:

```
Geen per-toestel verkeersdata beschikbaar via deze bron
Geen DNS-bron geconfigureerd
Geen VPN-bron geconfigureerd
Topologie niet beschikbaar
<wake reason>   (e.g. "Toesteltype ondersteunt Wake-on-LAN niet")
```

---

## 8. Configuration

New config blocks (env or `config.json`; see `config/config.example.json`):

```json
{
  "wake_on_lan": { "enabled": true, "broadcast_address": "255.255.255.255",
    "allowed_roles": ["workstation","server","media","infrastructure"],
    "allowed_device_types": ["desktop","server","nas","laptop","tv"] },
  "traffic": { "enabled": true, "history_limit": 1000,
    "high_usage_threshold_bps": 50000000, "unusual_upload_threshold_bps": 10000000 },
  "dns": { "enabled": false, "privacy_mode": "summary", "sources": [ … ] },
  "vpn": { "enabled": false, "sources": [ … ] },
  "topology": { "enabled": true }
}
```

DNS/VPN sources may be declared either in the top-level `sources` array or in
`dns.sources` / `vpn.sources` — both are folded into one adapter pipeline. Secrets
are referenced by env-var name (`password_env` / `token_env`), never inlined.

Env equivalents: `WOL_ENABLED`, `WOL_BROADCAST`, `TRAFFIC_ENABLED`,
`TRAFFIC_HIGH_USAGE_BPS`, `TRAFFIC_UNUSUAL_UPLOAD_BPS`, `DNS_ENABLED`,
`DNS_PRIVACY_MODE`, `DNS_BLOCKED_SPIKE_PERCENT`, `DNS_NOISY_DEVICE_QUERIES`,
`VPN_ENABLED`, `VPN_PEER_STALE_SECONDS`, `TOPOLOGY_ENABLED`.

---

## Known limitations

* Traffic is built from per-poll byte deltas; `hour`/`day` periods are not yet
  aggregated (labelled honestly). DNS/VPN history endpoints return empty
  (`history_available:false`) — no ring buffer retained yet.
* Pi-hole, WireGuard, GL.iNet/OpenWrt VPN adapters are skeletons (clear TODOs);
  AdGuard and Tailscale have live paths but are exercised here via mock.
* Topology is grouped, not a true graph; links are a router star.
* `wifi.signalPoor` still can't fire from the GL.iNet source (no per-client RSSI).

## Recommended Sprint 4

Real GL.iNet/OpenWrt adapter completion · real AdGuard Home integration · real
Tailscale integration · traffic/DNS/VPN history retention + charts · per-device
DNS/VPN detail on Device Detail · network automation polish · advanced
notification preferences · device onboarding workflow · network settings UI ·
security review screen.
