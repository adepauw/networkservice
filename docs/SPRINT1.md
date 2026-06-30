# Network — Sprint 1: "Network becomes useful"

This sprint turns the Network domain from a status/mock page into something
useful in daily CatOS use: unknown devices are visible and actionable, devices
can be named and classified, presence is person-level with confidence, and
network events flow into the house timeline and alerts.

It builds on the already-shipped Network Intelligence service (`networkservice`)
and its CatOS surface — nothing was rebuilt from scratch.

---

## 1. Device Registry v2

User-owned metadata is persisted in SQLite, keyed by **MAC address**, so it
survives IP/hostname churn, source refreshes and service restarts. The live
device snapshot stays in memory and is rebuilt every poll; metadata is overlaid
on top.

### Persisted, user-editable fields

```
display_name   device_type   role          trust_level   owner
tags           notes         presence_candidate           automation_candidate
ignored        is_known
```

`ignored` and `is_known` are new in Sprint 1. `ignored` is also derived from the
legacy `trust_level == "ignored"` sentinel for backward compatibility. `is_known`
is an optional explicit override; when unset it is derived from `trust_level`
(`trusted`/`known`/`guest` ⇒ known).

### Identity rules (unchanged, verified)

- **MAC** is the strongest key; canonical id is `dev_<machex>`.
- **IP** is weak (DHCP) and never an identity key — an IP change does not create
  a duplicate device.
- **Hostname** helps naming but isn't stable.
- **Randomized (locally-administered) MACs** are flagged
  (`metadata.randomized_mac`) but not aggressively merged.
- Unknown devices are never auto-trusted; ignored devices don't raise alerts;
  infrastructure is distinguishable by `role`.

### Full device fields exposed by the API

```
id  display_name  host_name  mac_address  ip_addresses  ipv6_addresses  vendor
device_type  role  trust_level  owner  is_known  is_online  ignored
first_seen_at  last_seen_at  last_changed_at  source_ids  tags  notes
presence_candidate  automation_candidate  interfaces  metadata
```

---

## 2. Unknown device flow

### Detection

On a device appearing *after* the cold-start baseline poll:

- `device.firstSeen` (info) — always.
- `device.unknownJoined` (warning; **info** for guests) — only when the device
  is not known **and** not ignored.
- `device.randomizedMacSuspected` (info) — when the MAC is locally-administered.

The unknown-device alert payload carries everything CatOS needs to render the
card and recommend an action:

```
device_id  name  vendor  host_name  ip_address  connection_type  band
first_seen_at  last_seen_at  randomized  advice
```

### Dedupe / no spam

- **Unknown-device alert cooldown:** 1 hour per MAC (`UNKNOWN_ALERT_COOLDOWN`).
- **Generic event dedupe:** 10 minutes (`EVENT_DEDUPE_COOLDOWN`).
- **Ignored devices:** no unknown-device alerts.
- **Known devices:** no unknown-device alerts.
- **Guest devices:** lower severity (info).

Repeated polling of the same unknown device produces a single alert per cooldown
window.

---

## 3. Presence v2

Person-level presence derived from configured persons and their devices.

### Model

```
person_id  display_name  status  confidence
primary_device_ids  supporting_device_ids
last_arrived_at  last_left_at  last_changed_at  evidence[]
```

Statuses: `home`, `probably_home`, `probably_away`, `away`, `unknown`.

### Scoring & grace

- primary device online: **+0.75**
- supporting device online: **+0.25**
- recently-seen primary device (within the away-grace window): **+0.4** partial
  credit → keeps the person `probably_home` during a brief WiFi blip instead of
  flapping to away.
- ignored / non-presence-candidate / guest devices contribute **0**.

Grace: device offline grace 5 min (`OFFLINE_GRACE`); presence away grace 15 min
(`PRESENCE_AWAY_GRACE`). A person only flips to `away` after all their devices
have been gone past the away grace.

### Events (emitted only on a real status change)

```
presence.personArrived       (home)
presence.personLeft          (away)
presence.personProbablyHome  (probably_home)
presence.personProbablyAway  (probably_away)
```

### Configuring persons

Persons live in `config/config.json` (`NETWORK_CONFIG`), gitignored. No real
personal data is hardcoded. Device ids are the canonical `dev_<machex>` ids.

```json
{
  "persons": [
    {
      "person_id": "person_demo",
      "display_name": "Demo Person",
      "primary_device_ids": ["dev_a483e7778899"],
      "supporting_device_ids": ["dev_f01898abcdef"]
    }
  ]
}
```

In mock mode with no configured persons, a demo person is injected so the
presence API/UI is populated.

---

## 4. Network timeline & alerts (catosservice)

`networkservice` emits clean, deduped, structured events. `catosservice` relays
them into the house surface via a new `NetworkEventMonitor`
(`catosservice/src/networkEvents.ts`), wired into the scheduler tick next to
`ServiceEventMonitor`:

- **Timeline:** new network events are appended to the durable house timeline
  (`source: "network"`, id `network:<eventId>`, idempotent upsert). The first
  tick is a silent baseline so a restart doesn't replay history. A small denylist
  (`device.ipChanged`, `device.vendorChanged`, `device.randomizedMacSuspected`)
  keeps low-value churn out.
- **Alerts:** open network alerts (`GET /alerts`) become catosservice alerts,
  deduped by `network:<type>:<deviceId>` so a sustained condition stays a single
  active alert. Unknown-device events surface here.
- **Health:** `network` was already in `SERVICE_NAMES`, `/api/system/health` and
  the dashboard `network` card / rule `facts.network.*`.

Severity maps `success → info` for the house timeline/alert model.

---

## 5. CatOS Network page + Device Detail

`catos/src/pages/NetworkPage.tsx` (route `/netwerk`, label **Netwerk**):

- **Overview** — internet status, router health, online/unknown/known counts,
  WiFi health, presence-home, active alerts.
- **Aanwezigheid** — per-person status, confidence and evidence summary.
- **Beveiliging** — defensive security alerts (when present), with ack.
- **Onbekende apparaten** — compact cards ("Onbekend toestel gevonden") with
  vendor / hostname / IP / connection type / first-seen and the actions
  **Bekend maken · Gast · Negeren · Details** (pending + error states).
- **Apparaten** — the full inventory grouped into *Onbekend, Bewoners, Gasten,
  Smart home, Infrastructuur, Media, Servers, Offline, Genegeerd*; each row links
  to the device detail.
- **WiFi kwaliteit**, **Meeste verkeer**, **Recente gebeurtenissen**.

`catos/src/pages/DeviceDetailPage.tsx` (route `/netwerk/device/:deviceId`):

- header (name, online, vendor, type, trust, ignored, WiFi RSSI);
- actions: Bekend maken / Gast / Negeren (toggle) / Wakker maken (known/trusted);
- rename; classification (type, role, trust, owner, presence- and
  automation-candidate toggles, presence-usage summary); notes + tags;
- network facts (hostname, MAC, IPs, connection, SSID/band, signal, seen times);
- recent per-device events.

Shared Dutch labels and the grouping live in `catos/src/lib/network.ts`.

### Loading / error / empty states

The page renders a degraded banner when networkservice is unreachable, a loading
placeholder while priming, and empty states ("Geen onbekende apparaten online",
"Nog geen apparaten gezien", "Geen gebeurtenissen", per-device update errors).

---

## 6. Typed client

`catos/src/services/networkClient.ts` — all calls go through `/svc/network/*`,
no raw fetch in pages:

```
getNetworkSummary  getNetworkDevices(filters)  getNetworkDevice(id)
getNetworkDeviceDetail(id)  updateNetworkDevice(id, patch)
markNetworkDeviceKnown(id)  markNetworkDeviceGuest(id)  ignoreNetworkDevice(id)
assignNetworkDeviceOwner(id, owner)  wakeNetworkDevice(id)
getNetworkEvents(filters)  getNetworkAlerts  ackNetworkAlert(id)
getPresence  getNetworkHealth  getRecentNetworkMetrics(type)
```

---

## 7. Dashboard widget

Already supported: `catosservice/src/dashboard.ts` exposes a `network` card
(internet/router status, online/unknown counts, WiFi health, presence-home,
active alerts) consumed by the CatOS Home dashboard. No new hacks were needed.

---

## New / changed endpoints (networkservice)

| Method | Path | Change |
| --- | --- | --- |
| GET | `/devices` | new `ignored` filter |
| GET | `/devices/{id}` | now returns device + interfaces + events + metrics + presence_usage + sources |
| PATCH | `/devices/{id}` | accepts `ignored`, `is_known`; validates enums (422) |
| POST | `/devices/{id}/mark-known` | **new** |
| POST | `/devices/{id}/mark-guest` | **new** |
| POST | `/devices/{id}/ignore` | **new** |
| POST | `/devices/{id}/assign-owner` | **new** |

New event types: `device.randomizedMacSuspected`,
`presence.personProbablyHome`, `presence.personProbablyAway`.

---

## How to run

```bash
# networkservice (mock mode — no router needed)
cd networkservice
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8103
curl -s localhost:8103/summary | jq

# tests
pip install pytest
NETWORK_DB_PATH=./data/test.db python -m pytest -q

# catosservice
cd catosservice && npm ci && npm run build && npm test

# catos app
cd catos && npm run dev      # type-check: tsc -b   lint: npm run lint   tests: npm test
```

## How to test the flow

1. Start `networkservice` (mock mode) — the mock household includes an unknown
   device that joins/leaves every ~6 polls.
2. Open CatOS → **Netwerk**. The unknown device appears in *Onbekende apparaten*.
3. Tap **Bekend maken** / **Gast** / **Negeren** — the card updates (pending →
   resolved). Ignored devices stop alerting.
4. Tap **Details** → rename, set role/trust/owner, toggle presence/automation.
   Reload / restart the service: the metadata persists.
5. Watch the CatOS timeline (catosservice): unknown-device and presence events
   appear; the same condition does not spam.

## Assumptions

- Mock mode is the default test surface; a real GL.iNet source is optional.
- Presence persons are configured via JSON; a full person-management UI is out of
  scope for Sprint 1 (device owner + presence-candidate are editable per-device).
- catosservice relays network alerts as **separate** house alerts; acking in
  CatOS-network (via networkservice) and in the house alerts are independent.

## Known limitations

- The GL.iNet source does not expose per-client RSSI, so `wifi.signalPoor` can't
  fire from that source (mock mode does).
- Network alerts relayed into catosservice don't auto-resolve when the upstream
  alert clears (they're acked manually), unlike the dashboard-derived alerts.
- `NetworkEventMonitor` baselines on its first tick after start, so events that
  occurred while catosservice was down are not back-filled into the timeline.
- catosservice tests require a native `better-sqlite3` build; on bleeding-edge
  Node versions without a prebuild they can't run locally (the suite + `tsc`
  build are otherwise green).

## Recommended Sprint 2

- Internet Health Monitor (latency/jitter/outage history).
- WiFi Quality Coach (per-device RSSI trends, channel/band advice).
- Network health history (persisted metrics, charts).
- Richer `catosservice` rule facts (per-event triggers for unknown-device /
  presence rules).
- Network alerts polish (auto-resolve relayed alerts, severity tuning).
