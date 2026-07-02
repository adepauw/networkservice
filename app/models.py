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

# diagnostics enumerations (Sprint 2)
InternetStatus = Literal["online", "degraded", "offline", "unknown"]
HealthQuality = Literal["excellent", "good", "fair", "poor", "unknown"]
WifiStatus = Literal["good", "fair", "poor", "critical", "unknown"]
ClientQuality = Literal["excellent", "good", "fair", "poor", "critical", "unknown"]

SourceType = Literal[
    "glinet", "openwrt", "adguard", "pihole", "dns", "tailscale", "wireguard",
    "glinet_vpn", "openwrt_vpn", "phobos", "mdns", "ssdp", "manual", "mock",
    "unknown",
]

SourceStatus = Literal["ok", "degraded", "error", "disabled", "unknown"]

# Sprint 3 enumerations
WakeStatus = Literal["sent", "unsupported", "forbidden", "failed", "unknown"]
DnsProtectionStatus = Literal["active", "degraded", "unconfigured", "unknown"]
VpnStatus = Literal["online", "degraded", "offline", "unknown"]
VpnPeerStatus = Literal["connected", "disconnected", "stale", "online", "offline", "unknown"]
TopologyGroupId = Literal[
    "router", "wired", "wifi_2_4", "wifi_5", "wifi_6", "guest", "vpn",
    "infrastructure", "smart_home", "unknown", "offline",
]


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
    WIFI_SIGNAL_CRITICAL = "wifi.signalCritical"
    WIFI_SIGNAL_RECOVERED = "wifi.signalRecovered"
    WIFI_TOO_MANY_WEAK_CLIENTS = "wifi.tooManyWeakClients"
    WIFI_WEAK_CLIENTS_RECOVERED = "wifi.weakClientsRecovered"
    WIFI_CLIENT_QUALITY_CHANGED = "wifi.clientQualityChanged"
    WIFI_RECONNECTED = "wifi.reconnected"
    INTERNET_ONLINE = "internet.online"
    INTERNET_OFFLINE = "internet.offline"
    INTERNET_DEGRADED = "internet.degraded"
    INTERNET_RECOVERED = "internet.recovered"
    INTERNET_LATENCY_HIGH = "internet.latencyHigh"
    INTERNET_PACKET_LOSS_HIGH = "internet.packetLossHigh"
    INTERNET_JITTER_HIGH = "internet.jitterHigh"
    DNS_DEGRADED = "dns.degraded"
    DNS_RECOVERED = "dns.recovered"
    WAN_IP_CHANGED = "wan.ipChanged"
    ROUTER_UNREACHABLE = "router.unreachable"
    ROUTER_RECOVERED = "router.recovered"
    ROUTER_REBOOTED = "router.rebooted"
    ROUTER_CONFIG_CHANGED = "router.configChanged"
    VPN_PEER_CONNECTED = "vpn.peerConnected"
    VPN_PEER_DISCONNECTED = "vpn.peerDisconnected"
    VPN_PEER_STALE = "vpn.peerStale"
    VPN_SOURCE_DEGRADED = "vpn.sourceDegraded"
    VPN_SOURCE_RECOVERED = "vpn.sourceRecovered"
    # --- Sprint 3: Wake-on-LAN ----------------------------------------------
    DEVICE_WAKE_REQUESTED = "device.wakeRequested"
    DEVICE_WAKE_SENT = "device.wakeSent"
    DEVICE_WAKE_FAILED = "device.wakeFailed"
    # --- Sprint 3: traffic insights -----------------------------------------
    TRAFFIC_HIGH_USAGE = "traffic.highUsage"
    TRAFFIC_UNUSUAL_UPLOAD = "traffic.unusualUpload"
    TRAFFIC_SPIKE = "traffic.spike"
    # --- Sprint 3: DNS protection -------------------------------------------
    DNS_PROTECTION_ACTIVE = "dns.protectionActive"
    DNS_PROTECTION_DEGRADED = "dns.protectionDegraded"
    DNS_PROTECTION_RECOVERED = "dns.protectionRecovered"
    DNS_BLOCKED_SPIKE = "dns.blockedSpike"
    DNS_DEVICE_NOISY = "dns.deviceNoisy"
    DNS_SUSPICIOUS_DOMAIN = "dns.suspiciousDomain"
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


class InternetHealthStatus(BaseModel):
    """Current internet/WAN health snapshot — the output of the diagnostic pipeline.

    Built from a handful of safe, low-rate checks (gateway reachability, DNS
    resolution, external HTTPS reachability + latency/jitter/loss). Any optional
    check that can't run is simply omitted; one missing check never fails the whole
    status. ``degraded_reasons`` explains *why* the verdict isn't ``online``.
    """

    status: InternetStatus = "unknown"
    quality: HealthQuality = "unknown"
    checked_at: float = Field(default_factory=now)
    router_reachable: Optional[bool] = None
    gateway_reachable: Optional[bool] = None
    dns_ok: Optional[bool] = None
    external_reachable: Optional[bool] = None
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_percent: Optional[float] = None
    wan_ip: Optional[str] = None
    wan_ip_changed: bool = False
    ipv6_available: Optional[bool] = None
    degraded_reasons: list[str] = Field(default_factory=list)
    source: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WifiClientQuality(BaseModel):
    """Per-device WiFi quality — RSSI bucketed into an actionable verdict."""

    device_id: str
    name: str
    quality: ClientQuality = "unknown"
    rssi: Optional[int] = None
    signal_quality: Optional[int] = None
    band: Band = "unknown"
    channel: Optional[int] = None
    ssid: Optional[str] = None
    tx_rate_mbps: Optional[float] = None
    rx_rate_mbps: Optional[float] = None
    last_seen_at: Optional[float] = None
    role: DeviceRole = "unknown"
    recommendation: Optional[str] = None


class WifiQualitySummary(BaseModel):
    """Compact, CatOS-friendly rollup of WiFi quality across all clients."""

    status: WifiStatus = "unknown"
    quality: HealthQuality = "unknown"
    checked_at: float = Field(default_factory=now)
    client_count: int = 0
    weak_client_count: int = 0
    critical_client_count: int = 0
    bands: dict[str, int] = Field(default_factory=dict)
    channels: dict[str, int] = Field(default_factory=dict)
    worst_clients: list[WifiClientQuality] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkHealthSample(BaseModel):
    """One row in the rolling health-history ring buffer — a flattened snapshot
    of the most useful diagnostic signals at a point in time, shaped for sparklines."""

    id: str
    sampled_at: float = Field(default_factory=now)
    internet_status: InternetStatus = "unknown"
    internet_quality: HealthQuality = "unknown"
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_percent: Optional[float] = None
    dns_ok: Optional[bool] = None
    router_status: str = "unknown"
    wifi_status: WifiStatus = "unknown"
    wifi_weak_client_count: int = 0
    online_device_count: int = 0
    unknown_device_count: int = 0
    source_statuses: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


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


# --- Sprint 3: Wake-on-LAN ---------------------------------------------------

class WakeResult(BaseModel):
    """Structured outcome of a Wake-on-LAN attempt. ``status`` is the contract the
    UI keys off; ``message`` is a human, Dutch-friendly explanation."""

    device_id: str
    attempted_at: float = Field(default_factory=now)
    target_mac: Optional[str] = None
    broadcast_address: Optional[str] = None
    status: WakeStatus = "unknown"
    message: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WakeEligibility(BaseModel):
    """Whether a device may be woken, and why not when it can't — drives the UI's
    conditional Wake action and the GET /devices/{id}/wake/status endpoint."""

    device_id: str
    can_wake: bool = False
    reason: Optional[str] = None
    target_mac: Optional[str] = None
    broadcast_address: Optional[str] = None
    wol_enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Sprint 3: traffic insights ----------------------------------------------

class TrafficDeviceStats(BaseModel):
    device_id: str
    display_name: str
    rx_bytes: float = 0.0
    tx_bytes: float = 0.0
    download_bps: Optional[float] = None
    upload_bps: Optional[float] = None
    total_bytes: float = 0.0
    period: str = "current"
    rank: int = 0
    is_unusual: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrafficSummary(BaseModel):
    sampled_at: float = Field(default_factory=now)
    total_rx_bytes: float = 0.0
    total_tx_bytes: float = 0.0
    current_download_bps: Optional[float] = None
    current_upload_bps: Optional[float] = None
    top_download_devices: list[TrafficDeviceStats] = Field(default_factory=list)
    top_upload_devices: list[TrafficDeviceStats] = Field(default_factory=list)
    unusual_devices: list[TrafficDeviceStats] = Field(default_factory=list)
    period: str = "current"
    history_available: bool = False
    source: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrafficSample(BaseModel):
    id: str
    sampled_at: float = Field(default_factory=now)
    total_rx_bytes: float = 0.0
    total_tx_bytes: float = 0.0
    current_download_bps: Optional[float] = None
    current_upload_bps: Optional[float] = None
    top_device_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrafficTrend(BaseModel):
    direction: Literal["rising", "falling", "stable", "unknown"] = "unknown"
    window_seconds: int = 0
    average_download_bps: Optional[float] = None
    average_upload_bps: Optional[float] = None


# --- Sprint 3: DNS protection ------------------------------------------------

class DnsDeviceStats(BaseModel):
    device_id: Optional[str] = None
    display_name: str
    query_count: int = 0
    blocked_count: int = 0
    blocked_percent: float = 0.0
    top_domains: list[str] = Field(default_factory=list)
    top_blocked_domains: list[str] = Field(default_factory=list)
    last_query_at: Optional[float] = None
    is_noisy: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DnsBlockedEvent(BaseModel):
    sampled_at: float = Field(default_factory=now)
    domain: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    reason: Optional[str] = None
    source: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DnsSourceStatus(BaseModel):
    id: str
    type: SourceType = "unknown"
    display_name: str
    status: SourceStatus = "unknown"
    protection_enabled: bool = False
    last_success_at: Optional[float] = None
    error_message: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DnsSummary(BaseModel):
    sampled_at: float = Field(default_factory=now)
    configured: bool = False
    query_count: int = 0
    blocked_count: int = 0
    blocked_percent: float = 0.0
    top_devices: list[DnsDeviceStats] = Field(default_factory=list)
    top_domains: list[str] = Field(default_factory=list)
    top_blocked_domains: list[str] = Field(default_factory=list)
    protection_status: DnsProtectionStatus = "unconfigured"
    sources: list[DnsSourceStatus] = Field(default_factory=list)
    source: Optional[str] = None
    history_available: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Sprint 3: VPN -----------------------------------------------------------

class VpnPeer(BaseModel):
    id: str
    display_name: str
    source: Optional[str] = None
    type: SourceType = "unknown"
    status: VpnPeerStatus = "unknown"
    ip_addresses: list[str] = Field(default_factory=list)
    last_seen_at: Optional[float] = None
    last_handshake_at: Optional[float] = None
    rx_bytes: Optional[float] = None
    tx_bytes: Optional[float] = None
    device_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VpnSourceStatus(BaseModel):
    id: str
    type: SourceType = "unknown"
    display_name: str
    status: VpnStatus = "unknown"
    peer_count: int = 0
    connected_peer_count: int = 0
    last_success_at: Optional[float] = None
    error_message: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VpnSummary(BaseModel):
    sampled_at: float = Field(default_factory=now)
    configured: bool = False
    status: VpnStatus = "unknown"
    peer_count: int = 0
    connected_peer_count: int = 0
    sources: list[VpnSourceStatus] = Field(default_factory=list)
    last_change_at: Optional[float] = None
    history_available: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Sprint 3: topology ------------------------------------------------------

class TopologyNode(BaseModel):
    id: str
    device_id: Optional[str] = None
    display_name: str
    device_type: DeviceType = "unknown"
    role: DeviceRole = "unknown"
    trust_level: TrustLevel = "unknown"
    status: Literal["online", "offline", "unknown"] = "unknown"
    group: TopologyGroupId = "unknown"
    connection_type: ConnectionType = "unknown"
    parent_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyLink(BaseModel):
    source_id: str
    target_id: str
    type: Literal["wired", "wifi", "vpn", "uplink", "unknown"] = "unknown"
    quality: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyGroup(BaseModel):
    id: TopologyGroupId
    label: str
    device_count: int = 0
    nodes: list[TopologyNode] = Field(default_factory=list)


class NetworkTopology(BaseModel):
    generated_at: float = Field(default_factory=now)
    groups: list[TopologyGroup] = Field(default_factory=list)
    links: list[TopologyLink] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- adapter output ----------------------------------------------------------

class SourceDnsData(BaseModel):
    """Normalized DNS analytics one source observed this poll."""

    protection_enabled: bool = True
    query_count: int = 0
    blocked_count: int = 0
    devices: list[DnsDeviceStats] = Field(default_factory=list)
    top_domains: list[str] = Field(default_factory=list)
    top_blocked_domains: list[str] = Field(default_factory=list)
    blocked_events: list[DnsBlockedEvent] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceVpnData(BaseModel):
    """Normalized VPN state one source observed this poll."""

    status: VpnStatus = "unknown"
    peers: list[VpnPeer] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    # Sprint 3: DNS analytics + VPN peers this source observed (best-effort).
    dns: Optional[SourceDnsData] = None
    vpn: Optional[SourceVpnData] = None
    # Capabilities actually fulfilled this poll (subset of configured).
    capabilities: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
