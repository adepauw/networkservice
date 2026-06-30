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
