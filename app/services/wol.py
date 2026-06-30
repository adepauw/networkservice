"""Wake-on-LAN — the one benign outbound action this service performs.

A magic packet (6×0xFF + the target MAC ×16) sent as a UDP broadcast. Gated to
*known/trusted, suitable* devices with a MAC. This is the protective opposite of
the offensive toolkit: it only ever helps a device you own wake up.

Sprint 3 adds an explicit eligibility model so the UI only ever offers Wake for a
device that can actually be woken, and a structured ``WakeResult`` so the outcome
is unambiguous (sent / unsupported / forbidden / failed).
"""

from __future__ import annotations

import socket

from ..config import Settings
from ..models import NetworkDevice, WakeEligibility, WakeResult, now


def magic_packet(mac: str) -> bytes:
    clean = mac.replace(":", "").replace("-", "").lower()
    if len(clean) != 12:
        raise ValueError(f"invalid MAC: {mac}")
    return b"\xff" * 6 + bytes.fromhex(clean) * 16


def send_wol(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, port))


def evaluate_eligibility(device: NetworkDevice | None, settings: Settings,
                         device_id: str = "") -> WakeEligibility:
    """Decide whether a device may be woken, and explain a refusal.

    A device is eligible only when it is *known* (not unknown/guest/ignored),
    trusted/known, has a MAC, and its role or device_type marks it as something
    you'd actually wake (a workstation/server/NAS/desktop/media box — never a
    phone, IoT sensor, camera or guest). The reasons are Dutch so the UI can show
    them verbatim.
    """
    did = device.id if device else device_id
    base = WakeEligibility(device_id=did, wol_enabled=settings.wol_enabled,
                           broadcast_address=settings.wol_broadcast)
    if not settings.wol_enabled:
        base.reason = "Wake-on-LAN is uitgeschakeld"
        return base
    if device is None:
        base.reason = "Onbekend apparaat"
        return base
    base.target_mac = device.mac_address
    if device.ignored:
        base.reason = "Apparaat is genegeerd"
        return base
    if device.trust_level not in ("trusted", "known"):
        base.reason = "Alleen bekende of vertrouwde apparaten"
        return base
    if not device.is_known:
        base.reason = "Apparaat is niet als bekend gemarkeerd"
        return base
    if not device.mac_address:
        base.reason = "Geen MAC-adres bekend"
        return base
    if not _role_suitable(device, settings):
        base.reason = "Toesteltype ondersteunt Wake-on-LAN niet"
        return base
    base.can_wake = True
    base.reason = None
    return base


def _role_suitable(device: NetworkDevice, settings: Settings) -> bool:
    return (device.role in settings.wol_allowed_roles
            or device.device_type in settings.wol_allowed_device_types)


def attempt_wake(device: NetworkDevice | None, settings: Settings,
                 device_id: str = "") -> WakeResult:
    """Run the eligibility gate, then send the magic packet. Always returns a
    ``WakeResult`` — never raises — so the route maps status → HTTP cleanly."""
    elig = evaluate_eligibility(device, settings, device_id)
    did = device.id if device else device_id
    result = WakeResult(device_id=did, target_mac=elig.target_mac,
                        broadcast_address=settings.wol_broadcast,
                        attempted_at=now())
    if not elig.can_wake:
        # an unknown device / disabled WoL is "unsupported"; a present-but-barred
        # device (untrusted, ignored, wrong type) is "forbidden".
        unsupported = device is None or not settings.wol_enabled
        result.status = "unsupported" if unsupported else "forbidden"
        result.message = elig.reason
        return result
    try:
        send_wol(device.mac_address, settings.wol_broadcast)  # type: ignore[arg-type]
        result.status = "sent"
        result.message = "Wake-on-LAN verzonden"
    except (OSError, ValueError) as exc:
        result.status = "failed"
        result.message = f"Versturen mislukt: {exc}"
    return result
