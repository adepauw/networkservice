"""Wake-on-LAN — the one benign outbound action this service performs.

A magic packet (6×0xFF + the target MAC ×16) sent as a UDP broadcast. Gated by the
caller to *known, trusted* devices with a MAC. This is the protective opposite of
the offensive toolkit: it only ever helps a device you own wake up.
"""

from __future__ import annotations

import socket


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
