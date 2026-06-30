"""Device identity + merge.

The hard part of network intelligence: deciding that two observations are the
*same* device. Rules, strongest to weakest:

* **MAC address** is the strongest stable key. Canonical id = ``dev_<mac>``.
* **Hostname** is useful for naming but not stable (devices rename, collide).
* **IP address** is weak and changes constantly (DHCP) — never an identity key.
* **Randomized MACs** (locally-administered bit set) are handled: they still key a
  device, but we flag them so presence/trust logic can be cautious.
* A device may appear from **multiple sources** and hold **multiple IPs** — we
  union those rather than creating duplicates.
* **User metadata** is keyed by MAC so it rides through IP/hostname churn.

This module is pure (no I/O) so it's trivially unit-testable.
"""

from __future__ import annotations

from ..models import DeviceMetadata, NetworkDevice, now


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    return cleaned or None


def is_randomized_mac(mac: str | None) -> bool:
    """True if the MAC is locally-administered (the 'random MAC' privacy bit).

    The second-least-significant bit of the first octet being set marks a
    locally-administered address — what iOS/Android use for per-SSID random MACs.
    """
    mac = normalize_mac(mac)
    if not mac or ":" not in mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0b10)


def device_id_for(device: NetworkDevice) -> str:
    mac = normalize_mac(device.mac_address)
    if mac:
        return f"dev_{mac.replace(':', '')}"
    if device.host_name:
        return f"dev_host_{device.host_name.lower()}"
    return device.id


def merge_devices(into: NetworkDevice, incoming: NetworkDevice) -> NetworkDevice:
    """Fold a fresh observation into the existing canonical device (same identity).

    Source-derived facts (ip, online, vendor, signal) come from `incoming`; long-
    lived facts (first_seen) and the union of ips/sources/tags are preserved.
    """
    merged = into.model_copy(deep=True)
    merged.is_online = into.is_online or incoming.is_online
    # Union IPs, newest first, de-duplicated.
    for ip in incoming.ip_addresses:
        if ip and ip not in merged.ip_addresses:
            merged.ip_addresses.insert(0, ip)
    for ip in incoming.ipv6_addresses:
        if ip and ip not in merged.ipv6_addresses:
            merged.ipv6_addresses.insert(0, ip)
    if incoming.host_name and not merged.host_name:
        merged.host_name = incoming.host_name
    if incoming.vendor and not merged.vendor:
        merged.vendor = incoming.vendor
    # Interfaces: prefer the freshest non-empty set.
    if incoming.interfaces:
        merged.interfaces = incoming.interfaces
    for sid in incoming.source_ids:
        if sid not in merged.source_ids:
            merged.source_ids.append(sid)
    merged.last_seen_at = max(into.last_seen_at, incoming.last_seen_at)
    merged.first_seen_at = min(into.first_seen_at, incoming.first_seen_at)
    return merged


def apply_metadata(device: NetworkDevice, meta: DeviceMetadata | None) -> NetworkDevice:
    """Overlay the persisted, user-owned slice onto a source-derived device."""
    if meta is None:
        # No saved metadata -> it's an unknown/unmanaged device.
        device.is_known = device.trust_level in ("trusted", "known")
        return device
    d = device.model_copy(deep=True)
    if meta.display_name:
        d.display_name = meta.display_name
    if meta.device_type:
        d.device_type = meta.device_type
    if meta.role:
        d.role = meta.role
    if meta.trust_level:
        d.trust_level = meta.trust_level
    if meta.owner:
        d.owner = meta.owner
    if meta.tags:
        d.tags = meta.tags
    if meta.notes:
        d.notes = meta.notes
    d.presence_candidate = meta.presence_candidate
    d.automation_candidate = meta.automation_candidate
    if meta.first_seen_at:
        d.first_seen_at = meta.first_seen_at
    # "Known" = the user has saved metadata and not marked it unknown/blocked.
    d.is_known = d.trust_level in ("trusted", "known", "guest")
    if is_randomized_mac(d.mac_address):
        d.metadata["randomized_mac"] = True
    return d


def classify(device: NetworkDevice) -> NetworkDevice:
    """Best-effort device_type/role inference from vendor + hostname heuristics.

    Only fills *unknown* fields — never overrides user-set or source-set values.
    Conservative on purpose: a wrong guess is worse than 'unknown'.
    """
    if device.device_type != "unknown" and device.role != "unknown":
        return device
    vendor = (device.vendor or "").lower()
    host = (device.host_name or "").lower()
    hints: list[tuple[tuple[str, ...], str, str]] = [
        (("apple",), "phone", "resident_device"),
        (("espressif", "tuya", "sonoff"), "iot", "smart_home"),
        (("signify", "philips hue"), "bridge", "smart_home"),
        (("nuki",), "smart_lock", "smart_home"),
        (("hikvision", "reolink", "dahua"), "camera", "smart_home"),
        (("sonos",), "speaker", "media"),
        (("lg electronics", "samsung", "vizio"), "tv", "media"),
        (("synology", "qnap"), "nas", "server"),
        (("gl technologies", "tp-link", "netgear", "ubiquiti"), "router", "infrastructure"),
    ]
    for needles, dtype, role in hints:
        if any(n in vendor for n in needles) or any(n in host for n in needles):
            if device.device_type == "unknown":
                device.device_type = dtype  # type: ignore[assignment]
            if device.role == "unknown":
                device.role = role  # type: ignore[assignment]
            break
    return device
