# Network — Sprint 2: "Network becomes diagnostic"

Sprint 1 made the network domain *useful* (devices, presence, unknown-device
flow). Sprint 2 makes it *diagnostic*: CatOS can now answer whether the internet
is healthy, whether the router/DNS are up, whether latency/jitter/packet-loss are
normal, whether WiFi quality is good and which devices are weak — and whether the
network has been unstable over time. The orchestrator turns the important signals
into alerts and rule-engine facts.

Built on top of the existing service — nothing from Sprint 1 was rebuilt.

---

## 1. Internet Health Monitor

`networkservice/app/services/internet.py` runs a small, safe diagnostic pipeline
each poll and produces an `InternetHealthStatus`:

```
status            online | degraded | offline | unknown
quality           excellent | good | fair | poor | unknown
router_reachable  gateway_reachable  dns_ok  external_reachable
latency_ms  jitter_ms  packet_loss_percent
wan_ip  wan_ip_changed  ipv6_available
degraded_reasons[]  checked_at  source
```

### Checks

* **router/gateway** — from the source snapshot (the router adapter already knows).
* **DNS** — `getaddrinfo` of a stable domain in a worker thread.
* **external reachability + latency/jitter/loss** — N TCP handshakes (default 4)
  to stable anycast hosts:443 (unprivileged ICMP stand-in). mean = latency,
  stdev = jitter, failed fraction = packet loss.

When a source already reports internet/DNS health (mock, or a router exposing WAN
status) those are trusted and the real probes are skipped — so mock mode stays
fully populated and network-free.

### Degradation rules (all configurable, conservative)

```
internet offline      3 consecutive failed external checks
internet recovered    2 consecutive healthy checks (resolves offline/degraded)
dns degraded          2 consecutive DNS failures
latency degraded      latency > 100 ms for 3 samples
packet loss degraded  loss > 5% for 3 samples
jitter degraded       jitter > 50 ms
```

Recovery is debounced separately from failure: a single good blip during an
outage does not flap the state back to online.

### Events

```
internet.online  internet.offline  internet.degraded  internet.recovered
internet.latencyHigh  internet.packetLossHigh  internet.jitterHigh
dns.degraded  dns.recovered  wan.ipChanged
router.unreachable  router.recovered
```

All flow through the engine's dedupe/cooldown gate; recovery events resolve the
open alert they clear.

### Endpoints

```
GET /internet/status        current snapshot
GET /internet/history        recent internet samples (limit, since)
GET /diagnostics/internet    verbose: snapshot + thresholds + source status
```

---

## 2. WiFi Quality Coach

`networkservice/app/services/wifi.py` buckets each WiFi client by RSSI and rolls
the network up into a `WifiQualitySummary` with recommendations.

### Client quality buckets

```
>= -55 dBm   excellent
-56..-67     good
-68..-74     fair
-75..-82     poor          (<= WIFI_POOR_RSSI_DBM)
below -82    critical      (<  WIFI_CRITICAL_RSSI_DBM)
no RSSI      unknown
```

### Events (debounced, only on change / threshold crossing)

```
wifi.signalPoor          3 poor/critical samples for a device
wifi.signalCritical      3 critical samples
wifi.signalRecovered     2 healthy samples (resolves the poor alert)
wifi.tooManyWeakClients  >= 3 weak clients
wifi.clientQualityChanged a device's committed quality bucket changed
```

Ignored devices are excluded entirely (no alerts, not counted). Sources without
per-client RSSI degrade gracefully: clients are counted, quality is `unknown`,
and the recommendation is *"Geen WiFi-signaaldata beschikbaar via deze bron"*
instead of false alarms.

### Recommendations (conservative, human-readable)

```
Garage Sensor heeft zwak WiFi-signaal (2.4 GHz)
Camera tuin heeft kritiek WiFi-signaal — staat waarschijnlijk te ver van de router
Veel toestellen zitten op 2.4 GHz
```

### Endpoints

```
GET /wifi/summary            rollup (status, counts, bands, recommendations)
GET /wifi/clients            per-device quality (worst first)
GET /wifi/clients/{id}       one client
GET /wifi/history            recent aggregate WiFi samples
```

---

## 3. Network Health History

A bounded in-memory ring buffer (`HEALTH_HISTORY_LIMIT`, default 1000) of
`NetworkHealthSample` rows, one per poll:

```
sampled_at  internet_status  internet_quality  latency_ms  jitter_ms
packet_loss_percent  dns_ok  router_status  wifi_status  wifi_weak_client_count
online_device_count  unknown_device_count  source_statuses
```

```
GET /health/history          rolling samples (limit, since)
```

`/summary` gained trend hints + an overall score:

```json
"trends": {
  "internet_recently_unstable": false,
  "internet_last_outage_at": null,
  "wifi_weak_clients": 1,
  "wifi_quality_trend": "stable",
  "network_health_score": 96
},
"network_health_score": 96
```

`network_health_score` starts at 100 and subtracts for offline/degraded internet,
degraded reasons, weak/critical WiFi clients and active alerts.

---

## 4. Orchestrator alerts (catosservice)

`NetworkEventMonitor` (Sprint 1) now **syncs** network alerts instead of only
adding them: each tick it reads networkservice `/alerts` (open warning/critical
events) and `AlertService.syncNetworkAlerts` upserts them and **resolves** any
previously-active network alert that is no longer present upstream. Because
`internet.recovered` / `dns.recovered` / `wifi.signalRecovered` resolve the open
event in networkservice, the matching catosservice alert resolves automatically.

Dedupe keys: `network:<type>:<deviceId|id>`.

**Role-aware severity:** poor/critical WiFi on a sensitive-role device
(camera, smart_lock, infrastructure, server, smart_home) is escalated to
`critical`; on ordinary devices it stays `warning`; ignored devices never alert
(networkservice excludes them).

The dashboard `network` card and `facts.network.*` gained the diagnostic fields
(see below).

---

## 5. Rule-engine facts

`facts.network` now exposes, sourced from the enriched `/summary`:

```
network.internetStatus   network.internetQuality   network.latencyMs
network.packetLossPercent   network.dnsOk
network.routerStatus
network.wifiStatus   network.weakClientCount   network.criticalClientCount
network.onlineDevices   network.unknownDevices   network.presenceHome
network.activeAlerts   network.healthScore   network.recentlyUnstable
```

Three **disabled-by-default** seed rules demonstrate automation over these facts
(`net-internet-offline`, `net-internet-degraded`, `net-wifi-weak`). They're
disabled because `NetworkEventMonitor` already raises these conditions as alerts;
enable one only if you want a rule-engine-owned alert with its own cooldown.

---

## 6. CatOS Network UI

`catos/src/pages/NetworkPage.tsx` is now diagnostics-first:

* **Netwerk gezond/instabiel/aandacht** — overall verdict + score, internet/WiFi
  status, device + alert counts.
* **Internet** — status, quality, latency, jitter, packet loss, DNS, router,
  degraded reasons, last outage.
* **WiFi kwaliteit** — status, client/weak/critical counts, band distribution,
  recommendations.
* **Zwakste toestellen** — poor/critical clients, tap → Sprint 1 device detail.
* **Recente incidenten** — diagnostic events (internet/dns/router/wifi/unknown).
* **Diagnostiek** — collapsible technical detail (checks enabled, last poll, last
  error, per-source health).

Plus the Sprint 1 cards (presence, security, unknown devices, grouped devices,
traffic). Loading / unavailable / empty states are handled per card.

The Home dashboard **NetworkTile** now leads with a health headline
(*"Netwerk gezond"*, *"Netwerk traag"*, *"Internet offline"*, *"WiFi aandacht"*)
rather than a raw device count.

### Client (`catos/src/services/networkClient.ts`)

```
getInternetStatus()   getInternetHistory(opts)   getNetworkDiagnostics()
getWifiSummary()   getWifiClients()   getWifiClient(id)   getWifiHistory(opts)
getNetworkHealthHistory(opts)
```

The app/edge proxy is a wildcard (`/svc/:name/*`), so all new subpaths route
without server changes.

---

## New events (networkservice)

```
internet.recovered  internet.latencyHigh  internet.packetLossHigh
internet.jitterHigh  dns.recovered  wan.ipChanged
router.unreachable  router.recovered
wifi.signalCritical  wifi.signalRecovered  wifi.tooManyWeakClients
wifi.clientQualityChanged
```

## New/changed catosservice alerts & facts

* recovery now resolves network alerts (`syncNetworkAlerts`);
* role-aware WiFi alert severity;
* dashboard `network` card + `facts.network.*` carry internet quality, latency,
  packet loss, DNS, WiFi status, weak/critical counts, health score, instability;
* three disabled network seed rules.

---

## How to run

```bash
cd networkservice
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8103
curl -s localhost:8103/internet/status | jq
curl -s localhost:8103/wifi/summary | jq

# tests
NETWORK_DB_PATH=./data/test.db python -m pytest -q     # 42 tests

cd ../catosservice && npm ci && npm run build && npm test
cd ../catos && npm test && npx tsc -b && npm run lint
```

## How to test internet diagnostics

* Unit: `tests/test_internet.py` drives `InternetHealthMonitor.evaluate` with
  source-reported hints to assert the debounced offline/recovered transitions,
  DNS threshold, latency/packet-loss thresholds and router up/down.
* Live (mock): `GET /internet/status` returns `online`/`excellent`; force a
  degraded state by setting `INTERNET_CHECK_ENABLED=1` with no real internet, or
  by injecting `packet_loss_percent`/`latency_ms` via a source.
* Verbose: `GET /diagnostics/internet` shows the thresholds + per-source status.

## How to test WiFi diagnostics

* Unit: `tests/test_wifi.py` covers the RSSI buckets, debounced poor/recovered,
  ignored-device exclusion, critical events and summary counts.
* Live (mock): the mock household includes a weak garage sensor (~-77 dBm);
  `GET /wifi/summary` shows it as a weak client with a recommendation, and
  `GET /wifi/clients` lists per-device quality worst-first.

## Assumptions

* Latency/jitter/packet-loss use TCP handshakes (no raw-socket ICMP); fine as a
  reachability/latency proxy in an unprivileged container.
* In mock mode the source reports internet/DNS, so the real probes don't run —
  diagnostics are populated from the reported values + the mock latency metric.
* WAN IP / IPv6 are surfaced only if a source reports them (`snapshot.raw.wan_ip`);
  the GL.iNet adapter doesn't yet, so they're usually null.

## Known limitations

* No real ICMP ping or per-hop traceroute (TCP-connect latency only).
* GL.iNet source still exposes no per-client RSSI, so WiFi quality from that
  source is `unknown` (mock mode demonstrates the full path).
* Health history is in-memory only (lost on restart); persistence is intentionally
  deferred.
* Disabled network seed rules are illustrative; enabling one alongside
  `NetworkEventMonitor` will double up that alert.
* catosservice tests need a native `better-sqlite3` build (can't run on a Node
  version without a prebuild); `tsc` build + the networkservice/app suites are
  green.

## Recommended Sprint 3

```
Wake-on-LAN polish
traffic insights (per-device bandwidth history)
DNS / AdGuard / Pi-hole source adapter (real DNS health + blocking stats)
VPN / Tailscale source adapter (peer status, vpn.peer* events)
basic topology view
```
