"""Presence: debounce, confidence, and the no-instant-flip rule."""

from __future__ import annotations

from app.config import Settings
from app.models import NetworkDevice, NetworkInterface
from app.services.presence import PresenceResolver

PERSON = {
    "person_id": "p1", "display_name": "P1",
    "primary_device_ids": ["dev_phone"], "supporting_device_ids": ["dev_laptop"],
}


def _phone(online=True):
    return NetworkDevice(id="dev_phone", mac_address="a4:83:e7:00:00:01", is_online=online,
                         interfaces=[NetworkInterface(device_id="dev_phone",
                                                      connection_type="wifi")] if online else [])


def _collect(events):
    def emit(type_, severity, title, message, person_id):
        events.append((type_, person_id))
    return emit


def test_primary_online_is_home_with_confidence():
    r = PresenceResolver(Settings(mock=True), [PERSON])
    states = r.resolve([_phone(True)], _collect([]))
    assert states[0].status == "home"
    assert states[0].confidence >= 0.75


def test_presence_does_not_instantly_flip_away():
    # a primary phone that was just online but dropped off stays "probably_home"
    # during the grace window (recently-seen partial confidence) — never an
    # instant "away".
    r = PresenceResolver(Settings(presence_away_grace_seconds=900, mock=True), [PERSON])
    r.resolve([_phone(True)], _collect([]))            # home
    states = r.resolve([_phone(False)], _collect([]))  # phone gone, but within grace
    assert states[0].status != "away"                  # not "away" yet
    assert states[0].status == "probably_home"         # recently seen → probably_home


def test_presence_flips_away_after_grace():
    r = PresenceResolver(Settings(presence_away_grace_seconds=0, mock=True), [PERSON])
    r.resolve([_phone(True)], _collect([]))
    events = []
    states = r.resolve([_phone(False)], _collect(events))
    assert states[0].status == "away"
    assert any(t == "presence.personLeft" for t, _ in events)


def test_presence_event_only_on_status_change():
    # the same status across polls must not re-emit events.
    r = PresenceResolver(Settings(presence_away_grace_seconds=0, mock=True), [PERSON])
    r.resolve([_phone(True)], _collect([]))            # baseline home
    events = []
    r.resolve([_phone(True)], _collect(events))        # still home → no event
    assert events == []
    r.resolve([_phone(False)], _collect(events))       # home → away → one event
    assert [t for t, _ in events] == ["presence.personLeft"]
    r.resolve([_phone(False)], _collect(events))       # still away → no new event
    assert [t for t, _ in events] == ["presence.personLeft"]
