"""End-to-end API smoke test against the real app (mock mode)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_api_shapes():
    with TestClient(app) as client:  # lifespan runs the priming poll
        health = client.get("/health").json()
        assert health["status"] == "ok"
        assert health["mock_mode"] is True
        assert any(s["type"] == "mock" for s in health["sources"])

        summary = client.get("/summary").json()
        assert "devices" in summary and summary["devices"]["online"] > 0
        assert "internet" in summary and "wifi" in summary

        devices = client.get("/devices").json()["devices"]
        assert len(devices) > 0
        # filter works
        online = client.get("/devices?online=true").json()["devices"]
        assert all(d["is_online"] for d in online)

        presence = client.get("/presence").json()
        assert "presence" in presence

        metrics = client.get("/metrics/recent").json()["metrics"]
        assert len(metrics) > 0


def test_summary_includes_internet_and_wifi():
    with TestClient(app) as client:
        s = client.get("/summary").json()
        assert s["internet"]["status"] in ("online", "degraded", "offline", "unknown")
        assert "quality" in s["internet"]
        assert s["wifi"]["status"] in ("good", "fair", "poor", "critical", "unknown")
        assert isinstance(s["wifi"]["weak_client_count"], int)
        assert isinstance(s["network_health_score"], int)
        assert "trends" in s


def test_diagnostic_endpoints():
    with TestClient(app) as client:
        assert client.get("/internet/status").json()["internet"]["status"]
        diag = client.get("/diagnostics/internet").json()
        assert "thresholds" in diag and "sources" in diag
        wifi = client.get("/wifi/summary").json()["wifi"]
        assert "status" in wifi and "recommendations" in wifi
        clients = client.get("/wifi/clients").json()["clients"]
        assert isinstance(clients, list)
        history = client.get("/health/history").json()
        assert "samples" in history and history["count"] >= 1


def test_health_history_ring_buffer_limit():
    from app.models import NetworkHealthSample
    from app.store import LiveStore
    live = LiveStore(10, 10, history_limit=5)
    for i in range(12):
        live.append_health_sample(NetworkHealthSample(id=f"hs_{i}"))
    assert len(live.health_history) == 5
    assert len(live.health_samples(limit=3)) == 3


def test_patch_persists_metadata():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        target = next(d for d in devices if d["mac_address"])
        res = client.patch(f"/devices/{target['id']}",
                           json={"display_name": "Renamed", "trust_level": "trusted"})
        assert res.status_code == 200
        assert res.json()["device"]["display_name"] == "Renamed"
        # rejects non-editable fields
        bad = client.patch(f"/devices/{target['id']}", json={"vendor": "hacker"})
        assert bad.status_code == 400


def test_patch_rejects_source_owned_fields():
    with TestClient(app) as client:
        target = next(d for d in client.get("/devices").json()["devices"] if d["mac_address"])
        # source-owned fields are silently dropped → "no editable fields" 400
        bad = client.patch(f"/devices/{target['id']}",
                           json={"mac_address": "00:00:00:00:00:00", "ip_addresses": ["1.2.3.4"]})
        assert bad.status_code == 400
        # an invalid enum value is a 422, never persisted
        invalid = client.patch(f"/devices/{target['id']}", json={"trust_level": "superuser"})
        assert invalid.status_code == 422


def test_convenience_endpoints():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        target = next(d for d in devices if d["mac_address"])
        did = target["id"]

        known = client.post(f"/devices/{did}/mark-known").json()["device"]
        assert known["is_known"] is True and known["trust_level"] == "known"

        guest = client.post(f"/devices/{did}/mark-guest").json()["device"]
        assert guest["trust_level"] == "guest"

        ignored = client.post(f"/devices/{did}/ignore").json()["device"]
        assert ignored["ignored"] is True

        owned = client.post(f"/devices/{did}/assign-owner", json={"owner": "alex"}).json()["device"]
        assert owned["owner"] == "alex"


def test_device_detail_returns_events_and_interfaces():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        # the mock router has interfaces; pick a device that has one
        target = next(d for d in devices if d["interfaces"])
        detail = client.get(f"/devices/{target['id']}").json()
        assert "device" in detail
        assert "interfaces" in detail and isinstance(detail["interfaces"], list)
        assert "events" in detail and "metrics" in detail
        assert "presence_usage" in detail and "sources" in detail


def test_wake_requires_trust():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        unknown = next((d for d in devices if not d["is_known"] and d["mac_address"]), None)
        if unknown:
            res = client.post(f"/devices/{unknown['id']}/wake")
            assert res.status_code == 403  # not trusted


def test_wake_status_endpoint():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        nas = next((d for d in devices if d["device_type"] == "nas"), None)
        assert nas is not None
        # set up deterministic eligible state (other tests share the metadata db)
        client.patch(f"/devices/{nas['id']}",
                     json={"trust_level": "trusted", "role": "server",
                           "device_type": "nas", "ignored": False, "is_known": True})
        elig = client.get(f"/devices/{nas['id']}/wake/status").json()["eligibility"]
        assert elig["can_wake"] is True
        # a device classified as a phone/resident is not a wake target
        client.patch(f"/devices/{nas['id']}",
                     json={"role": "resident_device", "device_type": "phone"})
        e2 = client.get(f"/devices/{nas['id']}/wake/status").json()["eligibility"]
        assert e2["can_wake"] is False and e2["reason"]
        # restore
        client.patch(f"/devices/{nas['id']}",
                     json={"role": "server", "device_type": "nas"})


def test_sprint3_summary_blocks():
    with TestClient(app) as client:
        s = client.get("/summary").json()
        assert "traffic" in s and "dns" in s and "vpn" in s and "topology" in s
        # mock mode: traffic available, dns/vpn unconfigured, topology available
        assert s["traffic"]["enabled"] is True
        assert s["dns"]["configured"] is False
        assert s["vpn"]["configured"] is False
        assert s["topology"]["available"] is True


def test_traffic_endpoints():
    with TestClient(app) as client:
        t = client.get("/traffic/summary").json()["traffic"]
        assert "top_download_devices" in t
        devices = client.get("/traffic/devices").json()["devices"]
        assert isinstance(devices, list)
        hist = client.get("/traffic/history").json()
        assert "samples" in hist


def test_dns_endpoints_unconfigured():
    with TestClient(app) as client:
        dns = client.get("/dns/summary").json()["dns"]
        assert dns["configured"] is False
        assert client.get("/dns/devices").json()["configured"] is False
        assert client.get("/dns/blocked").json()["configured"] is False


def test_vpn_endpoints_unconfigured():
    with TestClient(app) as client:
        vpn = client.get("/vpn/summary").json()["vpn"]
        assert vpn["configured"] is False
        assert client.get("/vpn/peers").json()["configured"] is False


def test_topology_endpoint_groups_devices():
    with TestClient(app) as client:
        t = client.get("/topology").json()
        assert t["available"] is True
        assert isinstance(t["groups"], list) and t["groups"]
        assert isinstance(t["counts"], dict)
        # the mock router should be present in a 'router' group
        assert any(g["id"] == "router" for g in t["groups"])


def test_unignore_via_patch_clears_trust_sentinel():
    """PATCH {"ignored": false} must actually un-ignore a device that was ignored
    via /ignore (which also sets the legacy trust_level="ignored" sentinel)."""
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        target = next(d for d in devices if d["mac_address"])
        did = target["id"]

        ignored = client.post(f"/devices/{did}/ignore").json()["device"]
        assert ignored["ignored"] is True and ignored["trust_level"] == "ignored"

        restored = client.patch(f"/devices/{did}", json={"ignored": False}).json()["device"]
        assert restored["ignored"] is False
        assert restored["trust_level"] != "ignored"


def test_alert_persistence_roundtrip(tmp_path):
    """Open alerts survive via SQLite: save → reload open ones; resolved ones
    drop out of the open set."""
    from app.models import NetworkEvent
    from app.store import MetadataStore

    store = MetadataStore(str(tmp_path / "alerts.db"))
    store.init()
    a = NetworkEvent(id="evt_a", type="wifi.signalPoor", severity="warning",
                     title="Zwak signaal", dedupe_key="wifi.signalPoor:dev_x")
    b = NetworkEvent(id="evt_b", type="internet.offline", severity="critical",
                     title="Internet offline", dedupe_key="internet.offline:internet")
    store.save_alert(a)
    store.save_alert(b)
    assert {e.id for e in store.open_alerts()} == {"evt_a", "evt_b"}

    from app.models import now
    a.resolved_at = now()
    store.save_alert(a)  # persist the resolution
    reloaded = store.open_alerts()
    assert [e.id for e in reloaded] == ["evt_b"]
    assert reloaded[0].dedupe_key == "internet.offline:internet"
