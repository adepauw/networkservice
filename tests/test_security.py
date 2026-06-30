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


# Use globally-unique MACs (locally-administered bit clear) so they aren't treated
# as benign randomized/privacy MACs.
_OLD = "ac:50:de:00:00:01"
_NEW = "3c:5a:b4:00:00:02"


def test_arp_spoof_suspected_on_genuine_conflict():
    """Alert only when the old MAC is still online (two live hosts, one IP)."""
    mon = SecurityMonitor(Settings(mock=True))
    devs = [NetworkDevice(id="d_old", mac_address=_OLD, is_online=True),
            NetworkDevice(id="d_new", mac_address=_NEW, is_online=True)]
    s1 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.50", "mac": _OLD}]})
    s2 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.50", "mac": _NEW}]})
    mon.inspect([s1], devs, _collect([]))
    events = []
    mon.inspect([s2], devs, _collect(events))
    assert EventType.SECURITY_ARP_SPOOF_SUSPECTED.value in {t for t, _ in events}


def test_arp_no_alert_on_dhcp_reuse():
    """Old host gone offline → benign DHCP reassignment, no alert (false-positive guard)."""
    mon = SecurityMonitor(Settings(mock=True))
    s1 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.50", "mac": _OLD}]})
    s2 = SourceSnapshot(source_id="s", security_signals={"arp": [{"ip": "192.168.8.50", "mac": _NEW}]})
    mon.inspect([s1], [], _collect([]))
    events = []
    mon.inspect([s2], [NetworkDevice(id="d_new", mac_address=_NEW, is_online=True)], _collect(events))
    assert EventType.SECURITY_ARP_SPOOF_SUSPECTED.value not in {t for t, _ in events}


def test_new_open_port_detected():
    mon = SecurityMonitor(Settings(mock=True))
    s1 = SourceSnapshot(source_id="s", security_signals={"open_ports": []})
    s2 = SourceSnapshot(source_id="s", security_signals={"open_ports": [{"proto": "tcp", "port": 32400}]})
    mon.inspect([s1], [], _collect([]))
    events = []
    mon.inspect([s2], [], _collect(events))
    assert EventType.SECURITY_PORT_EXPOSURE_CHANGED.value in {t for t, _ in events}
