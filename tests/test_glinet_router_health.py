"""GL.iNet adapter — router health metric extraction from ``system.get_status``.

Fixture data below mirrors the actual shape returned by a live Flint 2
(GL-MT6000, firmware 4.x) ``system.get_status`` call, captured during adapter
development. Only the ``system`` key is used — the same call also echoes the
``wifi`` list (with plaintext passwords) and a ``service`` list, neither of
which the adapter touches.
"""

from __future__ import annotations

from app.config import Settings, SourceConfig
from app.sources.glinet import GlinetAdapter

_SYSTEM_STATUS = {
    "memory_total": 1037430784,
    "memory_free": 368242688,
    "memory_buff_cache": 243568640,
    "uptime": 1562206.15,
    "cpu": {"temperature": 51},
    "load_average": [0.03, 0.02, 0],
}


def _adapter() -> GlinetAdapter:
    cfg = SourceConfig(id="flint2", type="glinet", display_name="Flint 2",
                       options={"username": "root", "password_env": "GLINET_PASSWORD_TEST"})
    return GlinetAdapter(cfg, Settings())


def test_router_metrics_extracts_memory_uptime_temp_load():
    adapter = _adapter()
    out: list = []
    uptime = adapter._router_metrics(_SYSTEM_STATUS, out)

    assert uptime == _SYSTEM_STATUS["uptime"]
    by_type = {m.type: m for m in out}
    assert set(by_type) == {
        "router.memoryPercent", "router.uptimeSeconds",
        "router.cpuTemperatureC", "router.loadAverage1m",
    }
    assert by_type["router.cpuTemperatureC"].value == 51
    assert by_type["router.loadAverage1m"].value == 0.03
    assert by_type["router.uptimeSeconds"].value == _SYSTEM_STATUS["uptime"]
    expected_mem_pct = (1 - 368242688 / 1037430784) * 100
    assert abs(by_type["router.memoryPercent"].value - expected_mem_pct) < 1e-6
    assert all(m.scope == "router" and m.source == "flint2" for m in out)


def test_router_metrics_never_fakes_cpu_percent():
    out: list = []
    adapter = _adapter()
    adapter._router_metrics(_SYSTEM_STATUS, out)
    assert "router.cpuPercent" not in {m.type for m in out}


def test_router_metrics_missing_fields_are_skipped_not_faked():
    adapter = _adapter()
    out: list = []
    uptime = adapter._router_metrics({}, out)

    assert uptime is None
    assert out == []
