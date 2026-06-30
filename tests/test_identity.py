"""Identity + merge: the core correctness of the inventory."""

from __future__ import annotations

from app.models import DeviceMetadata, NetworkDevice
from app.services import identity


def _dev(**kw) -> NetworkDevice:
    return NetworkDevice(id=kw.pop("id", "x"), **kw)


def test_canonical_id_is_mac_based():
    d = _dev(mac_address="AA:BB:CC:DD:EE:FF")
    assert identity.device_id_for(d) == "dev_aabbccddeeff"


def test_merge_by_mac_unions_ips_no_duplicate():
    a = _dev(id="dev_1", mac_address="aa:bb:cc:00:00:01", ip_addresses=["192.168.8.10"])
    b = _dev(id="dev_1", mac_address="aa:bb:cc:00:00:01", ip_addresses=["192.168.8.99"])
    merged = identity.merge_devices(a, b)
    assert set(merged.ip_addresses) == {"192.168.8.10", "192.168.8.99"}


def test_ip_change_keeps_single_device():
    """A DHCP IP change must not spawn a second known device."""
    old = _dev(id="dev_1", mac_address="aa:bb:cc:00:00:01", ip_addresses=["192.168.8.10"])
    new = _dev(id="dev_1", mac_address="aa:bb:cc:00:00:01", ip_addresses=["192.168.8.55"])
    merged = identity.merge_devices(old, new)
    assert identity.device_id_for(merged) == "dev_aabbcc000001"
    assert "192.168.8.55" in merged.ip_addresses


def test_randomized_mac_detection():
    assert identity.is_randomized_mac("3e:9a:71:5c:1d:2f") is True   # locally-administered
    assert identity.is_randomized_mac("a4:83:e7:77:88:99") is False  # globally unique (Apple OUI)


def test_user_metadata_survives_merge():
    dev = _dev(id="dev_1", mac_address="aa:bb:cc:00:00:01", display_name=None)
    meta = DeviceMetadata(mac_address="aa:bb:cc:00:00:01", display_name="Alex Phone",
                          trust_level="trusted", role="resident_device")
    out = identity.apply_metadata(dev, meta)
    assert out.display_name == "Alex Phone"
    assert out.is_known is True
    assert out.trust_level == "trusted"


def test_classify_only_fills_unknowns():
    dev = _dev(mac_address="00:17:88:00:00:01", vendor="Signify (Philips Hue)")
    out = identity.classify(dev)
    assert out.device_type == "bridge"
    assert out.role == "smart_home"
    # already-typed device is untouched
    typed = _dev(mac_address="x", vendor="Apple", device_type="laptop", role="workstation")
    assert identity.classify(typed).device_type == "laptop"
