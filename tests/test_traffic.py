"""Traffic insights — compact top devices + graceful empty state."""

from __future__ import annotations

from app.config import Settings
from app.models import NetworkDevice, NetworkMetric
from app.services.traffic import TrafficService
from app.store import LiveStore


def _live_with_traffic() -> LiveStore:
    live = LiveStore(50, 200)
    devices = [
        NetworkDevice(id="dev_nas", display_name="NAS", mac_address="00:11:22:33:44:55",
                      is_online=True, is_known=True),
        NetworkDevice(id="dev_tv", display_name="TV", mac_address="aa:bb:cc:dd:ee:ff",
                      is_online=True, is_known=True),
    ]
    live.set_devices(devices)
    # rxBytes: NAS heavier than TV
    for i in range(3):
        live.append_metric(NetworkMetric(id=f"rx_nas_{i}", type="device.rxBytes",
                                         scope="device", device_id="dev_nas", value=5_000_000))
        live.append_metric(NetworkMetric(id=f"rx_tv_{i}", type="device.rxBytes",
                                         scope="device", device_id="dev_tv", value=1_000_000))
        live.append_metric(NetworkMetric(id=f"tx_nas_{i}", type="device.txBytes",
                                         scope="device", device_id="dev_nas", value=2_000_000))
    return live


def test_traffic_summary_returns_compact_top_devices():
    live = _live_with_traffic()
    svc = TrafficService(Settings(), live)
    summary = svc.build_summary(limit=10)
    assert summary.top_download_devices
    assert summary.top_download_devices[0].device_id == "dev_nas"
    assert summary.top_download_devices[0].rank == 1
    assert summary.total_rx_bytes > 0


def test_traffic_unavailable_returns_graceful_empty_state():
    live = LiveStore(50, 200)  # no metrics
    svc = TrafficService(Settings(), live)
    summary = svc.build_summary()
    assert summary.top_download_devices == []
    assert summary.history_available is False
    assert "reason" in summary.metadata


def test_traffic_disabled_reports_disabled():
    svc = TrafficService(Settings(traffic_enabled=False), LiveStore(10, 10))
    summary = svc.build_summary()
    assert summary.metadata.get("enabled") is False
