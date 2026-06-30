"""Defensive threat detection: deauth, rogue AP, ARP spoof, port exposure."""

from __future__ import annotations

from app.config import Settings
from app.models import EventType, NetworkDevice, SourceSnapshot
from app.services.security import SecurityMonitor


def _collect(events):
    def emit(type_, severity, title, message, target, metadata):
        events.append((type_, severity))
    return emit


def test_deauth_flood_detected():
    mon = SecurityMonitor(Settings(mock=True))
    events = []
    snap = SourceSnapshot(source_id="s", security_signals={"deauth_frames_last_interval": 140})
    mon.inspect([snap], [], _collect(events))
    assert (EventType.SECURITY_DEAUTH_DETECTED.value, "critical") in events


def test_rogue_ap_detected():
    mon = SecurityMonitor(Settings(mock=True))
    events = []
    snap = SourceSnapshot(source_id="s", security_signals={"nearby_ssids": [
        {"ssid": "catnet", "bssid": "94:83:c4:00:00:02", "rssi": -44, "known": True},
        {"ssid": "catnet", "bssid": "de:ad:be:ef:00:01", "rssi": -39, "known": False},
    ]})
    mon.inspect([snap], [], _collect(events))
    assert EventType.SECURITY_ROGUE_AP_DETECTED.value in {t for t, _ in events}


def test_arp_spoof_suspected_on_mac_change():
    mon = SecurityMonitor(Settings(mock=True))
    s1 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.1", "mac": "aa:aa:aa:aa:aa:aa"}]})
    s2 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.1", "mac": "bb:bb:bb:bb:bb:bb"}]})
    mon.inspect([s1], [], _collect([]))
    events = []
    mon.inspect([s2], [], _collect(events))
    assert EventType.SECURITY_ARP_SPOOF_SUSPECTED.value in {t for t, _ in events}


def test_new_open_port_detected():
    mon = SecurityMonitor(Settings(mock=True))
    s1 = SourceSnapshot(source_id="s", security_signals={"open_ports": []})
    s2 = SourceSnapshot(source_id="s", security_signals={"open_ports": [{"proto": "tcp", "port": 32400}]})
    mon.inspect([s1], [], _collect([]))
    events = []
    mon.inspect([s2], [], _collect(events))
    assert EventType.SECURITY_PORT_EXPOSURE_CHANGED.value in {t for t, _ in events}
