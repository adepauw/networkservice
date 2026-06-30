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


def test_wake_requires_trust():
    with TestClient(app) as client:
        devices = client.get("/devices").json()["devices"]
        unknown = next((d for d in devices if not d["is_known"] and d["mac_address"]), None)
        if unknown:
            res = client.post(f"/devices/{unknown['id']}/wake")
            assert res.status_code == 403  # not trusted
