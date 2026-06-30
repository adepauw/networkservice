"""Runtime configuration, read once from the environment + an optional local file.

networkservice is the CatOS **Network Intelligence** domain service. It keeps a
normalized view of the home network (devices, presence, health, events, metrics)
by polling one or more *sources*. The first real source is a GL.iNet Flint 2
(GL-MT6000) on OpenWrt firmware, but the source list is pluggable — see
``app/sources``.

Like the sibling Python services (hueservice, powerservice, …) every value has a
homelab-sensible default so the container runs with zero config. Without a
configured real source the service runs in **mock mode** (``NETWORK_MOCK=1``,
the default) so the API and the CatOS UI are useful immediately.

Source definitions and secrets (router passwords, API tokens) come from
``NETWORK_CONFIG`` (a JSON file, gitignored under ``config/``) and/or env vars —
never commit real secrets. See ``config/config.example.json``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("networkservice.config")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SourceConfig:
    """One configured network source (a router, a DNS sink, a discovery probe)."""

    id: str
    type: str
    display_name: str
    enabled: bool = True
    base_url: str = ""
    # Capabilities the source is *expected* to provide. The adapter reports the
    # capabilities it actually fulfilled at runtime; this is the configured wish.
    capabilities: list[str] = field(default_factory=list)
    # Adapter-specific bag (username, password env name, ssh host, ...). Secrets
    # should be referenced by env-var name where possible, not inlined.
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Settings:
    # Port the FastAPI wrapper listens on. 8103 = next free slot after the
    # existing CatOS services (8093-8102, catosservice is 8102).
    port: int = _int("PORT", 8103)
    # Public path prefix when behind an NPM custom location (e.g. "/network").
    # Empty = served at the root. Mirrors the sibling services.
    base_path: str = os.environ.get("BASE_PATH", "").rstrip("/")

    # --- Poll + grace timings (all configurable; see polling.py) --------------
    poll_interval_seconds: int = _int("POLL_INTERVAL", 30)
    # A known device must be unseen this long before we emit device.offline.
    offline_grace_seconds: int = _int("OFFLINE_GRACE", 300)
    # Presence uses a *longer* grace than raw device offline so a phone that
    # briefly drops WiFi doesn't flip a person to "away".
    presence_away_grace_seconds: int = _int("PRESENCE_AWAY_GRACE", 900)
    # Per-MAC cooldown before re-alerting on the same unknown device.
    unknown_device_alert_cooldown_seconds: int = _int("UNKNOWN_ALERT_COOLDOWN", 3600)
    # Generic dedupe window so repeated identical events don't spam the timeline.
    event_dedupe_cooldown_seconds: int = _int("EVENT_DEDUPE_COOLDOWN", 600)

    # --- WiFi / internet thresholds ------------------------------------------
    poor_rssi_dbm: int = _int("POOR_RSSI_DBM", -75)
    poor_rssi_samples: int = _int("POOR_RSSI_SAMPLES", 3)
    internet_fail_samples: int = _int("INTERNET_FAIL_SAMPLES", 3)
    # Hosts the connectivity check pings (first reachable = internet up).
    internet_check_hosts: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    dns_check_host: str = os.environ.get("DNS_CHECK_HOST", "cloudflare.com")

    # --- Sprint 2: diagnostic thresholds (Internet Health + WiFi Coach) -------
    # All overridable via the config file's "diagnostics" object or env. Kept
    # conservative: a major alert needs repeated failures, recovery needs repeated
    # healthy samples, so the network has to be genuinely (un)healthy to flip.
    internet_check_enabled: bool = _bool("INTERNET_CHECK_ENABLED", True)
    internet_failure_threshold: int = _int("INTERNET_FAILURE_THRESHOLD", 3)
    internet_recovery_threshold: int = _int("INTERNET_RECOVERY_THRESHOLD", 2)
    dns_failure_threshold: int = _int("DNS_FAILURE_THRESHOLD", 2)
    dns_recovery_threshold: int = _int("DNS_RECOVERY_THRESHOLD", 2)
    latency_degraded_ms: float = _float("LATENCY_DEGRADED_MS", 100.0)
    latency_failure_samples: int = _int("LATENCY_FAILURE_SAMPLES", 3)
    jitter_degraded_ms: float = _float("JITTER_DEGRADED_MS", 50.0)
    packet_loss_degraded_percent: float = _float("PACKET_LOSS_DEGRADED_PERCENT", 5.0)
    packet_loss_failure_samples: int = _int("PACKET_LOSS_FAILURE_SAMPLES", 3)
    # number of latency probes per poll (also the packet-loss/jitter sample set).
    latency_probe_count: int = _int("LATENCY_PROBE_COUNT", 4)
    # WiFi quality buckets (dBm). poor <= poor_rssi_dbm; critical <= critical.
    wifi_critical_rssi_dbm: int = _int("WIFI_CRITICAL_RSSI_DBM", -82)
    wifi_poor_sample_threshold: int = _int("WIFI_POOR_SAMPLE_THRESHOLD", 3)
    wifi_recovery_sample_threshold: int = _int("WIFI_RECOVERY_SAMPLE_THRESHOLD", 2)
    # raise wifi.tooManyWeakClients once this many clients are weak/critical.
    wifi_too_many_weak_clients: int = _int("WIFI_TOO_MANY_WEAK_CLIENTS", 3)
    health_history_limit: int = _int("HEALTH_HISTORY_LIMIT", 1000)

    request_timeout: float = _float("NETWORK_TIMEOUT", 5.0)

    # --- Storage --------------------------------------------------------------
    # SQLite holds *user metadata* for known devices (display name, role, trust,
    # owner, tags, notes) so it survives IP/hostname churn and restarts. Live
    # device state stays in memory. Events/metrics are in-memory ring buffers.
    db_path: str = os.environ.get("NETWORK_DB_PATH", "/app/data/networkservice.db")
    event_buffer_size: int = _int("EVENT_BUFFER", 500)
    metric_buffer_size: int = _int("METRIC_BUFFER", 2000)

    # --- Sources --------------------------------------------------------------
    mock: bool = _bool("NETWORK_MOCK", True)
    config_path: str = os.environ.get("NETWORK_CONFIG", "/app/config/config.json")
    sources: list[SourceConfig] = field(default_factory=list)
    # Demo persons for the presence resolver (mock mode). Real persons come from
    # the config file. Never hardcode real personal data here.
    persons: list[dict[str, Any]] = field(default_factory=list)

    # Wake-on-LAN broadcast address (LAN broadcast). Empty disables WoL.
    wol_broadcast: str = os.environ.get("WOL_BROADCAST", "255.255.255.255")
    wol_enabled: bool = _bool("WOL_ENABLED", True)
    # Roles/types a device must carry to be eligible for Wake-on-LAN. A device is
    # wakeable if its role is in allowed_roles OR its device_type is in
    # allowed_device_types (plus the trust/known/MAC gates). Overridable via the
    # config file's "wake_on_lan" block.
    wol_allowed_roles: tuple[str, ...] = ("workstation", "server", "media", "infrastructure")
    wol_allowed_device_types: tuple[str, ...] = ("desktop", "server", "nas", "laptop", "tv")

    # --- Sprint 3: traffic insights ------------------------------------------
    traffic_enabled: bool = _bool("TRAFFIC_ENABLED", True)
    traffic_history_limit: int = _int("TRAFFIC_HISTORY_LIMIT", 1000)
    # conservative defaults: ~50 Mbps sustained download = "high usage";
    # ~10 Mbps sustained upload from one device = "unusual upload".
    traffic_high_usage_threshold_bps: float = _float("TRAFFIC_HIGH_USAGE_BPS", 50_000_000)
    traffic_unusual_upload_threshold_bps: float = _float("TRAFFIC_UNUSUAL_UPLOAD_BPS", 10_000_000)

    # --- Sprint 3: DNS protection --------------------------------------------
    dns_enabled: bool = _bool("DNS_ENABLED", False)
    # "summary" keeps per-device DNS data aggregate-only (no full query logs).
    dns_privacy_mode: str = os.environ.get("DNS_PRIVACY_MODE", "summary")
    # raise dns.blockedSpike once blocked-% jumps this many points above baseline.
    dns_blocked_spike_percent: float = _float("DNS_BLOCKED_SPIKE_PERCENT", 25.0)
    dns_noisy_device_queries: int = _int("DNS_NOISY_DEVICE_QUERIES", 5000)

    # --- Sprint 3: VPN --------------------------------------------------------
    vpn_enabled: bool = _bool("VPN_ENABLED", False)
    # peers unseen this long are reported "stale" (vpn.peerStale).
    vpn_peer_stale_seconds: int = _int("VPN_PEER_STALE_SECONDS", 600)

    # --- Sprint 3: topology ---------------------------------------------------
    topology_enabled: bool = _bool("TOPOLOGY_ENABLED", True)


def _load_file(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Failed to read config file %s: %s", path, exc)
        return {}


def _parse_sources(raw: list[dict[str, Any]]) -> list[SourceConfig]:
    out: list[SourceConfig] = []
    for item in raw:
        try:
            out.append(
                SourceConfig(
                    id=str(item["id"]),
                    type=str(item.get("type", "unknown")),
                    display_name=str(item.get("display_name", item["id"])),
                    enabled=bool(item.get("enabled", True)),
                    base_url=str(item.get("base_url", "")),
                    capabilities=list(item.get("capabilities", [])),
                    options=dict(item.get("options", {})),
                )
            )
        except (KeyError, TypeError) as exc:
            log.warning("Skipping malformed source entry %r: %s", item, exc)
    return out


def load_settings() -> Settings:
    """Build Settings from env + the optional JSON config file.

    Env wins for the simple scalars (already baked into the dataclass defaults);
    the file supplies the richer ``sources`` / ``persons`` structures and can
    override the poll/grace scalars too.
    """
    base = Settings()
    file_cfg = _load_file(base.config_path)

    # Sources live in the top-level "sources" array; DNS/VPN sources may also be
    # declared in their own blocks (dns.sources / vpn.sources) for readability.
    # We fold them all into one adapter pipeline.
    raw_sources = list(file_cfg.get("sources", []))
    raw_sources += list(file_cfg.get("dns", {}).get("sources", []))
    raw_sources += list(file_cfg.get("vpn", {}).get("sources", []))
    sources = _parse_sources(raw_sources)
    persons = list(file_cfg.get("persons", []))

    # Mock mode with no configured persons → inject a demo person so the presence
    # API/UI is populated. The ids are the *canonical* dev_<machex> ids the
    # inventory assigns (device_id_for), matching the mock adapter's MACs:
    #   dev_phone_alex  mac a4:83:e7:77:88:99 → dev_a483e7778899
    #   dev_laptop_alex mac f0:18:98:ab:cd:ef → dev_f01898abcdef
    if base.mock and not persons:
        persons = [{
            "person_id": "person_demo",
            "display_name": "Demo Person",
            "primary_device_ids": ["dev_a483e7778899"],
            "supporting_device_ids": ["dev_f01898abcdef"],
        }]

    # If nothing is configured and mock mode is on, the mock source is injected
    # by the source registry — we leave `sources` empty here.
    overrides: dict[str, Any] = {}
    for key in (
        "poll_interval_seconds",
        "offline_grace_seconds",
        "presence_away_grace_seconds",
        "unknown_device_alert_cooldown_seconds",
        "event_dedupe_cooldown_seconds",
    ):
        if key in file_cfg:
            overrides[key] = int(file_cfg[key])

    # diagnostics thresholds (Sprint 2). file keys mirror the Settings field names
    # (minus the "internet_"/"wifi_" prefixes where the example uses short names),
    # so map the documented config block onto the dataclass fields.
    diag = file_cfg.get("diagnostics", {})
    _diag_map = {
        "internet_check_enabled": ("internet_check_enabled", bool),
        "internet_failure_threshold": ("internet_failure_threshold", int),
        "internet_recovery_threshold": ("internet_recovery_threshold", int),
        "dns_failure_threshold": ("dns_failure_threshold", int),
        "dns_recovery_threshold": ("dns_recovery_threshold", int),
        "latency_degraded_ms": ("latency_degraded_ms", float),
        "latency_failure_samples": ("latency_failure_samples", int),
        "jitter_degraded_ms": ("jitter_degraded_ms", float),
        "packet_loss_degraded_percent": ("packet_loss_degraded_percent", float),
        "packet_loss_failure_samples": ("packet_loss_failure_samples", int),
        "wifi_poor_rssi_dbm": ("poor_rssi_dbm", int),
        "wifi_critical_rssi_dbm": ("wifi_critical_rssi_dbm", int),
        "wifi_poor_sample_threshold": ("wifi_poor_sample_threshold", int),
        "wifi_recovery_sample_threshold": ("wifi_recovery_sample_threshold", int),
        "health_history_limit": ("health_history_limit", int),
    }
    for file_key, (field_name, caster) in _diag_map.items():
        if file_key in diag:
            overrides[field_name] = caster(diag[file_key])

    # Sprint 3 config blocks (wake_on_lan / traffic / dns / vpn / topology).
    wol = file_cfg.get("wake_on_lan", {})
    if "enabled" in wol:
        overrides["wol_enabled"] = bool(wol["enabled"])
    if "broadcast_address" in wol:
        overrides["wol_broadcast"] = str(wol["broadcast_address"])
    if "allowed_roles" in wol:
        overrides["wol_allowed_roles"] = tuple(wol["allowed_roles"])
    if "allowed_device_types" in wol:
        overrides["wol_allowed_device_types"] = tuple(wol["allowed_device_types"])

    traffic = file_cfg.get("traffic", {})
    _traffic_map = {
        "enabled": ("traffic_enabled", bool),
        "history_limit": ("traffic_history_limit", int),
        "high_usage_threshold_bps": ("traffic_high_usage_threshold_bps", float),
        "unusual_upload_threshold_bps": ("traffic_unusual_upload_threshold_bps", float),
    }
    for file_key, (field_name, caster) in _traffic_map.items():
        if file_key in traffic:
            overrides[field_name] = caster(traffic[file_key])

    dns = file_cfg.get("dns", {})
    if "enabled" in dns:
        overrides["dns_enabled"] = bool(dns["enabled"])
    if "privacy_mode" in dns:
        overrides["dns_privacy_mode"] = str(dns["privacy_mode"])

    vpn = file_cfg.get("vpn", {})
    if "enabled" in vpn:
        overrides["vpn_enabled"] = bool(vpn["enabled"])

    topo = file_cfg.get("topology", {})
    if "enabled" in topo:
        overrides["topology_enabled"] = bool(topo["enabled"])

    return Settings(
        **overrides,
        sources=sources,
        persons=persons,
    )


settings = load_settings()
