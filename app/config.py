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

    sources = _parse_sources(file_cfg.get("sources", []))
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

    return Settings(
        **overrides,
        sources=sources,
        persons=persons,
    )


settings = load_settings()
