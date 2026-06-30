# networkservice — CatOS Network Intelligence

A Python/FastAPI domain service that gives CatOS a normalized, first-class view of
the home network, next to Hue, Airco, Nuki, Doorbell, Power, Environment, Heating,
Afval and Phobos. It answers questions like *who is home*, *which devices are
online/unknown*, *is the internet healthy*, *which devices have poor WiFi*, and
*did something suspicious just appear on my network* — and streams the events that
drive CatOS notifications.

It is **source-pluggable**. The first real source is a GL.iNet Flint 2
(GL-MT6000) on OpenWrt firmware; AdGuard/Pi-hole, Tailscale, Phobos/hostservice,
mDNS/SSDP discovery and others can be added as adapters later. Out of the box it
runs in **mock mode** with a realistic household so the API and the CatOS Network
page are useful immediately — no router credentials required.

- **Port:** `8103` (next free slot after the other CatOS services, 8093–8102).
- **Proxy name:** `network` → reached from the app as `/svc/network/...`.

## What it does (and doesn't)

This service is built for **visibility, diagnostics, automation and defensive
security**: reading router/device state, passive observation, DHCP/ARP/neighbour
tracking, WiFi association visibility, traffic counters, connectivity health,
device inventory, alerting on unknown devices, firewall-summary, safe local
discovery, optional low-rate LAN scanning (config-gated), and Wake-on-LAN for
*known, trusted* devices.

It also **detects and warns about attacks** without ever performing them. The
`security` service watches for the fingerprints of common LAN/WiFi attacks and
raises alerts:

| Threat | What we detect | We do **not** |
| --- | --- | --- |
| Deauth / disassoc flood | spike in deauth frames reported by the WiFi source | transmit deauth frames |
| Evil-twin / rogue AP | a nearby BSSID broadcasting *our* SSID that isn't a known AP | stand up a rogue AP |
| ARP spoofing / MITM | an IP suddenly remapping to a new MAC | poison ARP / intercept traffic |
| MAC spoofing | a trusted MAC appearing with a different fingerprint | spoof MACs |
| Port-exposure change | a new inbound port opened on the firewall | scan/exploit |
| Suspicious unknown device | an unknown device joining (escalated if it trips the above) | — |

There is deliberately **no offensive capability** in this service: no deauth, no
credential capture, no payload capture, no MITM, no exploit scanning. Detection
and protection only.

## API

All endpoints are reached through the CatOS app proxy as `/svc/network/...`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | liveness + per-source status + router/internet/DNS reachability |
| GET | `/summary` | compact dashboard rollup (counts, presence, internet/router/WiFi, alerts, top traffic) |
| GET | `/devices` | device inventory; filters: `online`, `known`, `ignored`, `type`, `role` |
| GET | `/devices/{id}` | **device detail**: device + interfaces + recent events + recent metrics + presence usage + source attribution |
| PATCH | `/devices/{id}` | safe user metadata only (name/type/role/trust/owner/tags/notes/presence/automation/ignored/is_known) |
| POST | `/devices/{id}/mark-known` | classify as known (trusted inventory) |
| POST | `/devices/{id}/mark-guest` | classify as a guest device |
| POST | `/devices/{id}/ignore` | ignore the device — no more unknown-device alerts |
| POST | `/devices/{id}/assign-owner` | assign an owner (`{"owner": "..."}`) |
| POST | `/devices/{id}/wake` | Wake-on-LAN — **known/trusted devices with a MAC only** |
| GET | `/events` | recent events; filters: `severity`, `type`, `device_id`, `unresolved` |
| GET | `/events/stream` | **SSE** live event stream |
| GET | `/alerts` | open warning/critical events |
| POST | `/alerts/{id}/ack` | acknowledge/resolve an alert |
| GET | `/presence` | person-level derived presence (home/away/probably_*) with confidence + evidence |
| GET | `/metrics/recent` | recent metric samples for charts; optional `type` filter |
| GET | `/internet/status` | current internet/WAN health verdict (status/quality + latency/jitter/loss/DNS) |
| GET | `/internet/history` | recent internet health samples; `limit`, `since` |
| GET | `/diagnostics/internet` | verbose internet diagnostics: snapshot + thresholds + per-source status |
| GET | `/wifi/summary` | WiFi quality rollup (status, weak/critical counts, bands, recommendations) |
| GET | `/wifi/clients` | per-device WiFi quality (worst signal first) |
| GET | `/wifi/clients/{id}` | one WiFi client's quality |
| GET | `/wifi/history` | recent aggregate WiFi samples; `limit`, `since` |
| GET | `/health/history` | rolling network-health samples for charts; `limit`, `since` |

`PATCH /devices/{id}` rejects any field that isn't user-owned (source-derived
state like `ip`, `is_online`, `vendor` is never writable) and validates enum
fields (`device_type`/`role`/`trust_level`) with a 422 on a bad value. The
convenience endpoints funnel through the same validation/persistence path.
Metadata is keyed by MAC and persisted in SQLite, so it survives IP/hostname
churn and restarts. An **ignored** device stays visible (grouped under
*Genegeerd*) but never raises an unknown-device alert.

## Run it

### Docker (homelab)

```bash
docker compose up -d --build
curl -s localhost:8103/health | jq
```

Defaults to mock mode. To use a real router, drop a `config/config.json` (see
below), set `NETWORK_MOCK=0`, and supply secrets via the environment.

### Local dev

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8103
```

### Tests

```bash
pip install pytest
NETWORK_DB_PATH=./data/test.db python -m pytest -q
```

Covered: MAC-based identity & merge (IP change doesn't duplicate a device),
user-metadata survival, offline grace, unknown-device first-seen alerting,
ignored/known devices raising **no** unknown-device alert, `PATCH` rejecting
source-owned/invalid fields, the convenience endpoints, device-detail shape
(events + interfaces), presence debounce (no instant flip to away), presence
events firing only on a real status change, the defensive threat detectors, and
an end-to-end API smoke test in mock mode.

## Configuration

Scalars come from the environment (sensible homelab defaults). Sources, secrets
and persons come from `NETWORK_CONFIG` (a JSON file, **gitignored** under
`config/`). Copy `config/config.example.json` to `config/config.json` and edit.

| Env | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8103` | listen port |
| `NETWORK_MOCK` | `1` | mock mode (auto-on if no real source is configured) |
| `POLL_INTERVAL` | `30` | seconds between polls |
| `OFFLINE_GRACE` | `300` | seconds a known device must be unseen before `device.offline` |
| `PRESENCE_AWAY_GRACE` | `900` | seconds before a person flips to `away` (longer than device offline) |
| `UNKNOWN_ALERT_COOLDOWN` | `3600` | per-MAC cooldown for the unknown-device alert |
| `EVENT_DEDUPE_COOLDOWN` | `600` | generic per-event dedupe window |
| `POOR_RSSI_DBM` / `POOR_RSSI_SAMPLES` | `-75` / `3` | poor-WiFi threshold + consecutive samples |
| `INTERNET_FAIL_SAMPLES` | `3` | failed checks before `internet.offline` (legacy) |
| `INTERNET_CHECK_ENABLED` | `1` | run the active internet diagnostic pipeline |
| `INTERNET_FAILURE_THRESHOLD` / `INTERNET_RECOVERY_THRESHOLD` | `3` / `2` | offline / recovered debounce |
| `DNS_FAILURE_THRESHOLD` | `2` | DNS failures before `dns.degraded` |
| `LATENCY_DEGRADED_MS` / `LATENCY_FAILURE_SAMPLES` | `100` / `3` | latency-high threshold + samples |
| `JITTER_DEGRADED_MS` | `50` | jitter-high threshold |
| `PACKET_LOSS_DEGRADED_PERCENT` / `PACKET_LOSS_FAILURE_SAMPLES` | `5` / `3` | packet-loss threshold + samples |
| `WIFI_CRITICAL_RSSI_DBM` | `-82` | critical-WiFi boundary (below = critical) |
| `WIFI_POOR_SAMPLE_THRESHOLD` / `WIFI_RECOVERY_SAMPLE_THRESHOLD` | `3` / `2` | WiFi poor / recovered debounce |
| `HEALTH_HISTORY_LIMIT` | `1000` | health-history ring-buffer size |

The full `diagnostics` block can also live in `config.json` (see
`config/config.example.json`) — those keys override the env defaults.
| `GLINET_PASSWORD` | — | router password, referenced by name from config (**never commit**) |
| `WOL_ENABLED` / `WOL_BROADCAST` | `1` / `255.255.255.255` | Wake-on-LAN |

**Secrets:** never inline a password in `config.json`. Reference an env-var name
(`options.password_env`) and supply it via the environment. `config/config.json`
and `data/` are gitignored.

## Architecture

```
sources/                 services/                 api/
  base.py  (interface)     identity.py  (merge)      routes_summary.py
  mock.py  (rich demo)     inventory.py (transitions)routes_devices.py
  openwrt.py (skeleton)    presence.py  (people)     routes_events.py  (+ SSE)
  glinet.py  (skeleton)    metrics.py   (wifi/traffic)routes_alerts.py
                           security.py  (threat det.) routes_presence.py
polling.py NetworkEngine   summary.py   (rollup)      routes_health.py
  ties it together         wol.py       (WoL)         routes_metrics.py
```

Each **poll tick** (`NetworkEngine.poll_once`): poll sources → merge devices by
identity → reconcile transitions → record metrics + WiFi health → resolve
presence → run defensive security checks → check internet/DNS → rebuild summary →
fan out SSE. Every event passes a dedupe/cooldown gate so a sustained condition
emits once, not once per poll.

**Storage:** live snapshot in memory; user device metadata in SQLite (keyed by
MAC); events/metrics in bounded in-memory ring buffers.

### Adding a source adapter

1. Subclass `NetworkSourceAdapter` (see `sources/base.py`); implement `_poll()`
   returning a normalized `SourceSnapshot`. Be fault-tolerant (never raise on a
   transient upstream error) and capability-honest (report only what you actually
   fetched).
2. Register it in `sources/__init__.py._REGISTRY`.
3. Add a source entry to `config.json` with its `type`, `base_url`,
   `capabilities` and `options`.

Capabilities are explicit strings: `dhcpLeases`, `arpTable`, `wifiAssociations`,
`interfaceCounters`, `routerHealth`, `firewallSummary`, `dnsStats`, `vpnPeers`,
`speedTest`, `wakeOnLan`. A source advertises what it supports; the engine fetches
only those.

## GL.iNet / OpenWrt integration status

`sources/glinet.py` is **live** (GL.iNet firmware 4.x, e.g. the Flint 2 /
GL-MT6000). It logs in over the JSON-RPC API and reads the connected-client list:

- **Endpoint:** `https://192.168.8.1:4443/rpc` (this Flint 2 moved the admin/API
  off port 80/443 to 4443; self-signed cert → `verify=False`, LAN-only).
- **Auth:** challenge → `md5_crypt(password, "$1$<salt>")` →
  `sha256("<user>:<cipher>:<nonce>")` → login → `sid`; re-login on session expiry.
- **Data:** `clients.get_list` (mac, ip, ipv6, name, alias, iface
  `2.4G`/`5G`/`cable`/`*_Guest`, online, blocked, traffic counters) +
  `wifi.get_status` (per-band channel). Emits device rx/tx byte metrics and an ARP
  view for the defensive detector.
- **Known limitation:** this API does not expose **per-client RSSI**, so
  `wifi.signalPoor` can't fire from this source (capability honestly omitted).
  `crypt` (stdlib) is used for MD5-crypt — present on the pinned 3.11 container
  image (removed in Python 3.13).

Configure it via `config.json` (`type: glinet`, `base_url`, `options.password_env`)
and supply the password through the environment (`GLINET_PASSWORD`) — never
committed. With a real source configured and `NETWORK_MOCK=0`, mock mode is off.

`sources/openwrt.py` remains a **skeleton** (lower-level `ubus`/SSH path) for
sources that don't speak the GL.iNet API. Still optional/future:

- WireGuard/Tailscale peer status (for `vpn.peerConnected/Disconnected` events).
- Router CPU/mem/uptime (the GL.iNet `system.info` method name differs; not yet
  mapped — connectivity health is covered by the engine's own internet/DNS checks).

## How CatOS consumes it

- **App proxy:** `catos/server/src/index.ts` and `vite.config.ts` map
  `network → 8103`, so the app calls `/svc/network/...`.
- **Typed client:** `catos/src/services/networkClient.ts`.
- **UI:** `catos/src/pages/NetworkPage.tsx` (route `/netwerk`, label *Netwerk*) +
  a compact Home dashboard tile.
- **Orchestrator:** `catosservice` registers `network` as an upstream, includes it
  in `/api/system/health`, folds its summary into the house dashboard
  (`dashboard.network`), and exposes `facts.network.*` to the rule engine
  (internet status, router status, WiFi health, online/unknown counts, presence,
  active alerts) so rules like *"if an unknown device joins, alert"* or *"if a
  resident phone joins WiFi, mark probably home"* can be built.
```
