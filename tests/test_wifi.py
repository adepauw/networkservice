"""WiFi Quality Coach: buckets, debounced poor/recovered, ignored exclusion."""

from __future__ import annotations

from app.config import Settings
from app.models import NetworkDevice, NetworkInterface
from app.services.wifi import WifiQualityCoach, client_quality


def _wifi_device(did, rssi, ignored=False, role="resident_device", online=True):
    return NetworkDevice(
        id=did, mac_address=f"aa:bb:cc:00:00:{did[-2:]}", is_online=online,
        is_known=True, ignored=ignored, role=role,
        interfaces=[NetworkInterface(device_id=did, connection_type="wifi",
                                     band="2.4ghz", rssi=rssi)] if online else [],
    )


def _collect(events):
    def emit(type_, severity, title, message, target, metadata):
        events.append((type_, severity, getattr(target, "id", None)))
    return emit


def _settings(**kw):
    return Settings(mock=True, poor_rssi_dbm=-75, wifi_critical_rssi_dbm=-82,
                    wifi_poor_sample_threshold=3, wifi_recovery_sample_threshold=2, **kw)


def test_client_quality_buckets():
    assert client_quality(-48, -75, -82) == "excellent"
    assert client_quality(-60, -75, -82) == "good"
    assert client_quality(-70, -75, -82) == "fair"
    assert client_quality(-78, -75, -82) == "poor"
    assert client_quality(-90, -75, -82) == "critical"
    assert client_quality(None, -75, -82) == "unknown"


def test_poor_signal_requires_repeated_samples():
    coach = WifiQualityCoach(_settings())
    events: list = []
    dev = _wifi_device("dev_x", -78)
    for _ in range(2):
        coach.evaluate([dev], _collect(events))
    assert not any(t == "wifi.signalPoor" for t, _, _ in events)
    coach.evaluate([dev], _collect(events))  # 3rd poor sample
    assert any(t == "wifi.signalPoor" for t, _, _ in events)


def test_recovered_requires_healthy_samples():
    coach = WifiQualityCoach(_settings())
    events: list = []
    poor = _wifi_device("dev_x", -78)
    good = _wifi_device("dev_x", -55)
    for _ in range(3):
        coach.evaluate([poor], _collect(events))   # raises signalPoor
    coach.evaluate([good], _collect(events))         # 1 healthy
    assert not any(t == "wifi.signalRecovered" for t, _, _ in events)
    coach.evaluate([good], _collect(events))         # 2 healthy
    assert any(t == "wifi.signalRecovered" for t, _, _ in events)


def test_ignored_device_no_wifi_alert():
    coach = WifiQualityCoach(_settings())
    events: list = []
    dev = _wifi_device("dev_ig", -90, ignored=True)
    for _ in range(5):
        coach.evaluate([dev], _collect(events))
    assert events == []


def test_critical_signal_event():
    coach = WifiQualityCoach(_settings())
    events: list = []
    dev = _wifi_device("dev_c", -90)
    for _ in range(3):
        coach.evaluate([dev], _collect(events))
    assert any(t == "wifi.signalCritical" for t, _, _ in events)
    summary = coach.last
    assert summary.critical_client_count == 1


def test_summary_counts_and_status():
    coach = WifiQualityCoach(_settings())
    devices = [_wifi_device("dev_a", -50), _wifi_device("dev_b", -78)]
    coach.evaluate(devices, _collect([]))
    s = coach.last
    assert s.client_count == 2
    assert s.weak_client_count == 1
    assert s.status in ("poor", "fair")


def test_too_many_weak_clients_recovers():
    """The broad weak-clients alert emits a recovery event once the count drops,
    so the engine can resolve the open alert."""
    from app.models import EventType
    coach = WifiQualityCoach(_settings(wifi_too_many_weak_clients=2))
    weak = [_wifi_device(f"dev_w{i}", -80) for i in range(3)]
    events = []
    coach.evaluate(weak, _collect(events))
    assert EventType.WIFI_TOO_MANY_WEAK_CLIENTS.value in {e[0] for e in events}
    # signal improves → recovery event fires exactly once
    good = [_wifi_device(f"dev_w{i}", -50) for i in range(3)]
    events = []
    coach.evaluate(good, _collect(events))
    assert EventType.WIFI_WEAK_CLIENTS_RECOVERED.value in {e[0] for e in events}
    events = []
    coach.evaluate(good, _collect(events))
    assert EventType.WIFI_WEAK_CLIENTS_RECOVERED.value not in {e[0] for e in events}
