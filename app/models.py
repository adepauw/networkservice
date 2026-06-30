"""Normalized domain model for the home network.

Everything the service exposes is one of these Pydantic models. Raw, vendor-shaped
data from a source adapter is normalized into these before it ever reaches the
store, the API or CatOS — so the rest of the system never sees OpenWrt/ubus/Hue
specifics.

Security posture: this model is built for *visibility and defense*. The security
event/metric types below describe **detection** of hostile activity on the LAN
(deauth floods, ARP/MAC spoofing, rogue access points, new exposed ports). The
service never performs those actions — it watches for their fingerprints and
alerts. There is deliberately no model for offensive capability.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def now() -> float:
    return time.time()


# --- enumerations ------------------------------------------------------------

DeviceType = Literal[
    "phone", "tablet", "laptop", "desktop", "server", "router", "access_point",
    "iot", "camera", "speaker", "tv", "printer", "smart_lock", "bridge", "nas",
    "wearable", "unknown",
]

DeviceRole = Literal[
    "resident_device", "guest_device", "infrastructure", "smart_home", "media",
    "workstation", "server", "unknown",
]

TrustLevel = Literal["trusted", "known", "guest", "unknown", "blocked", "ignored"]

ConnectionType = Literal["wifi", "ethernet", "vpn", "unknown"]

Band = Literal["2.4ghz", "5ghz", "6ghz", "wired", "unknown"]

Severity = Literal["info", "success", "warning", "critical"]

PresenceStatus = Literal["home", "away", "probably_home", "probably_away", "unknown"]

SourceType = Literal[
    "glinet", "openwrt", "adguard", "pihole", "tailscale", "phobos", "mdns",
    "ssdp", "manual", "mock", "unknown",
]

SourceStatus = Literal["ok", "degraded", "error", "disabled", "unknown"]


class EventType(str, Enum):
    DEVICE_FIRST_SEEN = "device.firstSeen"
    DEVICE_ONLINE = "device.online"
    DEVICE_OFFLINE = "device.offline"
    DEVICE_RENAMED = "device.renamed"
    DEVICE_IP_CHANGED = "device.ipChanged"
    DEVICE_MAC_CONFLICT = "device.macConflict"
    DEVICE_VENDOR_CHANGED = "device.vendorChanged"
    DEVICE_UNKNOWN_JOINED = "device.unknownJoined"
    DEVICE_RANDOMIZED_MAC_SUSPECTED = "device.randomizedMacSuspected"
    WIFI_SIGNAL_POOR = "wifi.signalPoor"
    WIFI_RECONNECTED = "wifi.reconnected"
    INTERNET_ONLINE = "internet.online"
    INTERNET_OFFLINE = "internet.offline"
    INTERNET_DEGRADED = "internet.degraded"
    DNS_DEGRADED = "dns.degraded"
    ROUTER_REBOOTED = "router.rebooted"
    ROUTER_CONFIG_CHANGED = "router.configChanged"
    VPN_PEER_CONNECTED = "vpn.peerConnected"
    VPN_PEER_DISCONNECTED = "vpn.peerDisconnected"
    PRESENCE_PERSON_ARRIVED = "presence.personArrived"
    PRESENCE_PERSON_LEFT = "presence.personLeft"
    PRESENCE_PERSON_PROBABLY_HOME = "presence.personProbablyHome"
    PRESENCE_PERSON_PROBABLY_AWAY = "presence.personProbablyAway"
    SOURCE_DEGRADED = "source.degraded"
    SOURCE_RECOVERED = "source.recovered"
    # --- defensive threat detection (detection only, never offence) ----------
    SECURITY_SUSPICIOUS_DEVICE = "security.suspiciousDevice"
    SECURITY_PORT_EXPOSURE_CHANGED = "security.portExposureChanged"
    SECURITY_DEAUTH_DETECTED = "security.deauthDetected"
    SECURITY_ARP_SPOOF_SUSPECTED = "security.arpSpoofSuspected"
    SECURITY_ROGUE_AP_DETECTED = "security.rogueApDetected"
    SECURITY_MAC_SPOOF_SUSPECTED = "security.macSpoofSuspected"


# --- core models -------------------------------------------------------------

class NetworkInterface(BaseModel):
    device_id: str
    connection_type: ConnectionType = "unknown"
    interface_name: Optional[str] = None
    ssid: Optional[str] = None
    band: Band = "unknown"
    channel: Optional[int] = None
    rssi: Optional[int] = None  # dBm
    signal_quality: Optional[int] = None  # 0-100
    tx_rate_mbps: Optional[float] = None
    rx_rate_mbps: Optional[float] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    connected_since: Optional[float] = None
    last_seen_at: float = Field(default_factory=now)


class NetworkDevice(BaseModel):
    id: str
    display_name: Optional[str] = None
    host_name: Optional[str] = None
    mac_address: Optional[str] = None
    ip_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    vendor: Optional[str] = None
    device_type: DeviceType = "unknown"
    role: DeviceRole = "unknown"
    trust_level: TrustLevel = "unknown"
    owner: Optional[str] = None
    is_known: bool = False
    is_online: bool = False
    # user has explicitly told us to stop caring about this device. ignored
    # devices never raise unknown-device alerts and drop out of the "unknown"
    # counts, but stay visible (under "Genegeerd") so the user can un-ignore.
    ignored: bool = False
    first_seen_at: float = Field(default_factory=now)
    last_seen_at: float = Field(default_factory=now)
    last_changed_at: float = Field(default_factory=now)
    source_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
    presence_candidate: bool = False
    automation_candidate: bool = False
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.display_name or self.host_name or self.mac_address or self.id


# Fields a user is allowed to PATCH. Anything else is rejected — source-derived
# state (ip, online, vendor, last_seen) is never user-writable.
USER_EDITABLE_FIELDS = {
    "display_name", "role", "trust_level", "owner", "tags", "notes",
    "presence_candidate", "automation_candidate", "device_type",
    "ignored", "is_known",
}


class DeviceMetadata(BaseModel):
    """The persisted, user-owned slice of a device. Keyed by MAC (stable id)."""

    mac_address: str
    display_name: Optional[str] = None
    device_type: Optional[DeviceType] = None
    role: Optional[DeviceRole] = None
    trust_level: Optional[TrustLevel] = None
    owner: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
    presence_candidate: bool = False
    automation_candidate: bool = False
    ignored: bool = False
    # None = derive is_known from trust_level; True/False = explicit override.
    is_known: Optional[bool] = None
    first_seen_at: Optional[float] = None
    updated_at: float = Field(default_factory=now)


class NetworkEvent(BaseModel):
    id: str
    type: str
    severity: Severity = "info"
    title: str
    message: Optional[str] = None
    device_id: Optional[str] = None
    source: Optional[str] = None
    occurred_at: float = Field(default_factory=now)
    resolved_at: Optional[float] = None
    acknowledged_at: Optional[float] = None
    dedupe_key: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_alert(self) -> bool:
        return self.severity in ("warning", "critical")

    @property
    def is_open(self) -> bool:
        return self.resolved_at is None


class NetworkMetric(BaseModel):
    id: str
    type: str
    scope: Literal["internet", "router", "wifi", "dns", "device"] = "router"
    device_id: Optional[str] = None
    value: float
    unit: Optional[str] = None
    sampled_at: float = Field(default_factory=now)
    source: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PresenceEvidence(BaseModel):
    device_id: str
    reason: str
    weight: float


class PresenceState(BaseModel):
    person_id: str
    display_name: str
    status: PresenceStatus = "unknown"
    confidence: float = 0.0
    primary_device_ids: list[str] = Field(default_factory=list)
    supporting_device_ids: list[str] = Field(default_factory=list)
    last_arrived_at: Optional[float] = None
    last_left_at: Optional[float] = None
    last_changed_at: float = Field(default_factory=now)
    evidence: list[PresenceEvidence] = Field(default_factory=list)


class NetworkSource(BaseModel):
    id: str
    type: SourceType = "unknown"
    display_name: str
    status: SourceStatus = "unknown"
    last_poll_at: Optional[float] = None
    last_success_at: Optional[float] = None
    last_error_at: Optional[float] = None
    error_message: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- adapter output ----------------------------------------------------------

class SourceSnapshot(BaseModel):
    """One poll's worth of normalized data from a single source adapter.

    Adapters return this; the inventory service merges snapshots from all sources
    into the canonical device list. Every field is optional so a source that only
    knows about, say, DHCP leases doesn't have to fabricate WiFi or router data.
    """

    source_id: str
    devices: list[NetworkDevice] = Field(default_factory=list)
    metrics: list[NetworkMetric] = Field(default_factory=list)
    # Router/internet/dns health observed by this source (best-effort).
    router_online: Optional[bool] = None
    router_uptime_seconds: Optional[float] = None
    internet_online: Optional[bool] = None
    dns_online: Optional[bool] = None
    firewall_summary: Optional[dict[str, Any]] = None
    # Security signals the source observed this tick (deauth counters, rogue
    # SSIDs, open-port sets). The security service interprets these into events.
    security_signals: dict[str, Any] = Field(default_factory=dict)
    # Capabilities actually fulfilled this poll (subset of configured).
    capabilities: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
