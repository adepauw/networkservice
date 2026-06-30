"""Wake-on-LAN eligibility + result tests (no real packets are sent)."""

from __future__ import annotations

from app.config import Settings
from app.models import NetworkDevice
from app.services.wol import attempt_wake, evaluate_eligibility


def _device(**kw) -> NetworkDevice:
    base = dict(id="dev_x", mac_address="00:11:22:33:44:55", is_known=True,
                trust_level="trusted", role="server", device_type="nas",
                is_online=False, ignored=False)
    base.update(kw)
    return NetworkDevice(**base)


def test_wake_rejects_unknown_device():
    s = Settings()
    res = attempt_wake(None, s, device_id="dev_missing")
    assert res.status == "unsupported"
    assert res.message


def test_wake_rejects_ignored_device():
    s = Settings()
    dev = _device(ignored=True, trust_level="ignored")
    elig = evaluate_eligibility(dev, s)
    assert not elig.can_wake
    assert attempt_wake(dev, s).status == "forbidden"


def test_wake_rejects_untrusted_device():
    s = Settings()
    dev = _device(trust_level="unknown", is_known=False)
    assert not evaluate_eligibility(dev, s).can_wake
    assert attempt_wake(dev, s).status == "forbidden"


def test_wake_rejects_unsuitable_type():
    s = Settings()
    # a trusted phone is not a wake target (wrong role/type)
    dev = _device(role="resident_device", device_type="phone")
    assert not evaluate_eligibility(dev, s).can_wake


def test_wake_requires_mac():
    s = Settings()
    dev = _device(mac_address=None)
    assert not evaluate_eligibility(dev, s).can_wake


def test_wake_sends_for_trusted_eligible_device(monkeypatch):
    s = Settings()
    dev = _device()
    elig = evaluate_eligibility(dev, s)
    assert elig.can_wake
    sent: dict = {}

    def fake_send(mac, broadcast, *a, **k):
        sent["mac"] = mac

    monkeypatch.setattr("app.services.wol.send_wol", fake_send)
    res = attempt_wake(dev, s)
    assert res.status == "sent"
    assert sent["mac"] == dev.mac_address


def test_wake_disabled_is_unsupported():
    s = Settings(wol_enabled=False)
    dev = _device()
    assert not evaluate_eligibility(dev, s).can_wake
    assert attempt_wake(dev, s).status == "unsupported"
