"""State store: in-memory snapshot + SQLite-backed user metadata.

Three tiers, matching the pragmatic pattern of the sibling services:

* **Live snapshot** (in memory) — the current device list, presence, sources,
  summary. Rebuilt every poll, never persisted. Lost on restart and that's fine;
  the next poll repopulates it in seconds.
* **User metadata** (SQLite) — the human-owned slice of a device (display name,
  role, trust, owner, tags, notes, presence/automation flags), keyed by MAC so it
  survives IP/hostname churn and restarts. This is the only thing worth keeping.
* **Ring buffers** (in memory) — recent events and metrics for the timeline and
  simple charts, capped so memory stays bounded. We deliberately do *not* build a
  big event store yet.

SQLite calls are blocking, so callers run them via ``asyncio.to_thread``. One
short-lived WAL connection per op — simpler and contention-free at this rate.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections import deque
from typing import Optional

from .models import (
    DeviceMetadata,
    DnsSummary,
    InternetHealthStatus,
    NetworkDevice,
    NetworkEvent,
    NetworkHealthSample,
    NetworkMetric,
    NetworkSource,
    NetworkTopology,
    PresenceState,
    TrafficSample,
    TrafficSummary,
    VpnPeer,
    VpnSummary,
    WifiQualitySummary,
)

log = logging.getLogger("networkservice.store")


class MetadataStore:
    """SQLite persistence for the user-owned device metadata (keyed by MAC)."""

    def __init__(self, path: str) -> None:
        self._path = path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_metadata (
                    mac_address          TEXT PRIMARY KEY,
                    display_name         TEXT,
                    device_type          TEXT,
                    role                 TEXT,
                    trust_level          TEXT,
                    owner                TEXT,
                    tags                 TEXT,
                    notes                TEXT,
                    presence_candidate   INTEGER DEFAULT 0,
                    automation_candidate INTEGER DEFAULT 0,
                    ignored              INTEGER DEFAULT 0,
                    is_known             INTEGER,
                    first_seen_at        REAL,
                    updated_at           REAL
                )
                """
            )
            # additive migration for installs created before ignored/is_known
            # existed — sqlite has no "add column if not exists", so probe first.
            cols = {r[1] for r in conn.execute("PRAGMA table_info(device_metadata)")}
            if "ignored" not in cols:
                conn.execute("ALTER TABLE device_metadata ADD COLUMN ignored INTEGER DEFAULT 0")
            if "is_known" not in cols:
                conn.execute("ALTER TABLE device_metadata ADD COLUMN is_known INTEGER")

    def all(self) -> dict[str, DeviceMetadata]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM device_metadata").fetchall()
        out: dict[str, DeviceMetadata] = {}
        for r in rows:
            out[r["mac_address"]] = DeviceMetadata(
                mac_address=r["mac_address"],
                display_name=r["display_name"],
                device_type=r["device_type"],
                role=r["role"],
                trust_level=r["trust_level"],
                owner=r["owner"],
                tags=json.loads(r["tags"]) if r["tags"] else [],
                notes=r["notes"],
                presence_candidate=bool(r["presence_candidate"]),
                automation_candidate=bool(r["automation_candidate"]),
                ignored=bool(r["ignored"]),
                is_known=None if r["is_known"] is None else bool(r["is_known"]),
                first_seen_at=r["first_seen_at"],
                updated_at=r["updated_at"],
            )
        return out

    def upsert(self, meta: DeviceMetadata) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO device_metadata (
                    mac_address, display_name, device_type, role, trust_level,
                    owner, tags, notes, presence_candidate, automation_candidate,
                    ignored, is_known, first_seen_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    display_name=excluded.display_name,
                    device_type=excluded.device_type,
                    role=excluded.role,
                    trust_level=excluded.trust_level,
                    owner=excluded.owner,
                    tags=excluded.tags,
                    notes=excluded.notes,
                    presence_candidate=excluded.presence_candidate,
                    automation_candidate=excluded.automation_candidate,
                    ignored=excluded.ignored,
                    is_known=excluded.is_known,
                    first_seen_at=COALESCE(device_metadata.first_seen_at, excluded.first_seen_at),
                    updated_at=excluded.updated_at
                """,
                (
                    meta.mac_address, meta.display_name, meta.device_type, meta.role,
                    meta.trust_level, meta.owner, json.dumps(meta.tags), meta.notes,
                    int(meta.presence_candidate), int(meta.automation_candidate),
                    int(meta.ignored),
                    None if meta.is_known is None else int(meta.is_known),
                    meta.first_seen_at, meta.updated_at,
                ),
            )


class LiveStore:
    """In-memory current snapshot + bounded event/metric ring buffers."""

    def __init__(self, event_buffer: int, metric_buffer: int, history_limit: int = 1000) -> None:
        self.devices: dict[str, NetworkDevice] = {}
        self.presence: dict[str, PresenceState] = {}
        self.sources: dict[str, NetworkSource] = {}
        self.summary: dict = {}
        self.events: deque[NetworkEvent] = deque(maxlen=event_buffer)
        self.metrics: deque[NetworkMetric] = deque(maxlen=metric_buffer)
        # health snapshot maintained by the poller
        self.router_online: Optional[bool] = None
        self.internet_online: Optional[bool] = None
        self.dns_online: Optional[bool] = None
        self.last_poll_at: Optional[float] = None
        self.last_error: Optional[str] = None
        # Sprint 2 diagnostics: latest internet/WiFi verdicts + a rolling
        # health-history ring buffer (bounded; in memory only).
        self.internet_health: Optional[InternetHealthStatus] = None
        self.wifi_quality: Optional[WifiQualitySummary] = None
        self.health_history: deque[NetworkHealthSample] = deque(maxlen=history_limit)
        # Sprint 3: traffic / DNS / VPN / topology latest snapshots + traffic ring.
        self.traffic_summary: Optional[TrafficSummary] = None
        self.dns_summary: Optional[DnsSummary] = None
        self.vpn_summary: Optional[VpnSummary] = None
        self.vpn_peers: list[VpnPeer] = []
        self.topology: Optional[NetworkTopology] = None
        self.traffic_history: deque[TrafficSample] = deque(maxlen=history_limit)

    # --- devices --------------------------------------------------------------
    def set_devices(self, devices: list[NetworkDevice]) -> None:
        self.devices = {d.id: d for d in devices}

    def device(self, device_id: str) -> Optional[NetworkDevice]:
        return self.devices.get(device_id)

    def device_list(self) -> list[NetworkDevice]:
        return list(self.devices.values())

    # --- events ---------------------------------------------------------------
    def append_event(self, event: NetworkEvent) -> None:
        self.events.appendleft(event)

    def event_list(self) -> list[NetworkEvent]:
        return list(self.events)

    def find_open_event(self, dedupe_key: str) -> Optional[NetworkEvent]:
        for ev in self.events:
            if ev.dedupe_key == dedupe_key and ev.is_open:
                return ev
        return None

    def alerts(self) -> list[NetworkEvent]:
        return [e for e in self.events if e.is_alert and e.is_open]

    # --- metrics --------------------------------------------------------------
    def append_metric(self, metric: NetworkMetric) -> None:
        self.metrics.appendleft(metric)

    def recent_metrics(self, limit: int = 200) -> list[NetworkMetric]:
        out: list[NetworkMetric] = []
        for m in self.metrics:
            out.append(m)
            if len(out) >= limit:
                break
        return out

    # --- health history -------------------------------------------------------
    def append_health_sample(self, sample: NetworkHealthSample) -> None:
        self.health_history.appendleft(sample)

    def health_samples(self, limit: int = 200, since: float | None = None) -> list[NetworkHealthSample]:
        out: list[NetworkHealthSample] = []
        for s in self.health_history:
            if since is not None and s.sampled_at < since:
                break
            out.append(s)
            if len(out) >= limit:
                break
        return out

    # --- traffic history ------------------------------------------------------
    def append_traffic_sample(self, sample: TrafficSample) -> None:
        self.traffic_history.appendleft(sample)

    def traffic_samples(self, limit: int = 200, since: float | None = None) -> list[TrafficSample]:
        out: list[TrafficSample] = []
        for s in self.traffic_history:
            if since is not None and s.sampled_at < since:
                break
            out.append(s)
            if len(out) >= limit:
                break
        return out
