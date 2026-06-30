"""Inventory reconcile: transitions, offline grace, unknown-device alerting."""

from __future__ import annotations

import time

from app.config import Settings
from app.models import EventType, NetworkDevice, SourceSnapshot
from app.services.inventory import NetworkInventoryService
from app.store import LiveStore, MetadataStore


class _MemMetadata(MetadataStore):
    def __init__(self):
        self._mem = {}

    def init(self): ...
    def all(self): return dict(self._mem)
    def upsert(self, meta): self._mem[meta.mac_address] = meta


def _engine(offline_grace=300):
    settings = Settings(offline_grace_seconds=offline_grace, mock=True)
    live = LiveStore(100, 100)
    inv = NetworkInventoryService(settings, live, _MemMetadata())
    inv.load_metadata()
    return settings, live, inv


def _collect(events):
    def emit(type_, severity, title, message, target, metadata):
        events.append((type_, severity, target))
    return emit


def _snap(devices):
    return SourceSnapshot(source_id="mock", devices=devices)


def test_first_seen_and_unknown_joined():
    _, live, inv = _engine()
    # cold-start baseline poll seeds existing devices silently (no alerts)
    live.set_devices(inv.reconcile(inv.merge([_snap([])]), _collect([])))
    # a device appearing *after* the baseline alerts
    events = []
    fresh = inv.merge([_snap([NetworkDevice(id="x", mac_address="3e:9a:71:00:00:01",
                                            is_online=True)])])
    out = inv.reconcile(fresh, _collect(events))
    live.set_devices(out)
    types = {e[0] for e in events}
    assert EventType.DEVICE_FIRST_SEEN.value in types
    assert EventType.DEVICE_UNKNOWN_JOINED.value in types


def test_baseline_poll_is_silent():
    """Every already-connected device on cold start must NOT flood join alerts."""
    _, live, inv = _engine()
    events = []
    fresh = inv.merge([_snap([
        NetworkDevice(id="a", mac_address="aa:bb:cc:00:00:01", is_online=True),
        NetworkDevice(id="b", mac_address="aa:bb:cc:00:00:02", is_online=True),
    ])])
    live.set_devices(inv.reconcile(fresh, _collect(events)))
    assert events == []


def test_offline_grace_suppresses_immediate_offline():
    settings, live, inv = _engine(offline_grace=300)
    # device present
    fresh = inv.merge([_snap([NetworkDevice(id="x", mac_address="aa:bb:cc:00:00:09",
                                            is_online=True, trust_level="trusted")])])
    out = inv.reconcile(fresh, _collect([]))
    live.set_devices(out)
    # now it vanishes — within grace, no offline event, still shown online
    events = []
    out2 = inv.reconcile(inv.merge([_snap([])]), _collect(events))
    live.set_devices(out2)
    assert EventType.DEVICE_OFFLINE.value not in {e[0] for e in events}
    assert out2[0].is_online is True  # kept online during grace


def test_offline_emitted_after_grace():
    settings, live, inv = _engine(offline_grace=0)  # grace elapsed instantly
    fresh = inv.merge([_snap([NetworkDevice(id="x", mac_address="aa:bb:cc:00:00:09",
                                            is_online=True, trust_level="trusted")])])
    live.set_devices(inv.reconcile(fresh, _collect([])))
    events = []
    inv.reconcile(inv.merge([_snap([])]), _collect(events))
    assert EventType.DEVICE_OFFLINE.value in {e[0] for e in events}
