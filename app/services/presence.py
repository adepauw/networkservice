"""Presence resolver — turns device online/offline into *person* presence.

Deliberately conservative:

* Presence is derived from **configured persons** with one or more **primary
  devices** (and optional supporting devices). A device alone never implies a
  person unless it's configured as that person's primary.
* A person flips to ``away`` only after **all** their devices have been gone for
  ``presence_away_grace`` — a *longer* window than raw device offline, so a phone
  briefly dropping WiFi doesn't evict someone from the house.
* Confidence is a weighted blend of the evidence (primary device on WiFi counts
  more than a supporting device), surfaced for the UI.
* ``probably_home`` / ``probably_away`` express the in-between, low-confidence
  states rather than committing to home/away prematurely.

Person config (from the JSON config file; demo persons in mock mode):
    {"person_id","display_name","primary_device_ids":[...],"supporting_device_ids":[...]}
"""

from __future__ import annotations

from typing import Any

from ..config import Settings
from ..models import (
    EventType,
    NetworkDevice,
    PresenceEvidence,
    PresenceState,
    now,
)

PRIMARY_WEIGHT = 0.75
SUPPORTING_WEIGHT = 0.25
# while a primary device is within its offline grace we keep a fraction of its
# confidence so a phone briefly off WiFi reads "probably home", not "away".
GRACE_PRIMARY_WEIGHT = 0.4


class PresenceResolver:
    def __init__(self, settings: Settings, persons: list[dict[str, Any]]) -> None:
        self.settings = settings
        self._persons = persons
        self._states: dict[str, PresenceState] = {}
        # person_id -> first time all their devices were gone
        self._away_since: dict[str, float] = {}
        # device_id -> last time we saw it online (for grace-period partial credit)
        self._last_seen_online: dict[str, float] = {}

    def resolve(self, devices: list[NetworkDevice], emit) -> list[PresenceState]:
        t = now()
        by_id = {d.id: d for d in devices}
        out: list[PresenceState] = []

        for person in self._persons:
            pid = person["person_id"]
            primary = list(person.get("primary_device_ids", []))
            supporting = list(person.get("supporting_device_ids", []))
            prev = self._states.get(pid)

            evidence: list[PresenceEvidence] = []
            score = 0.0
            primary_online = False
            primary_in_grace = False
            for did in primary:
                dev = by_id.get(did)
                # a device that is ignored or not a presence candidate must not
                # count toward its owner's presence (guest phones, IoT, etc.).
                if dev and dev.is_online and not dev.ignored:
                    self._last_seen_online[did] = t
                    primary_online = True
                    on_wifi = bool(dev.interfaces and dev.interfaces[0].connection_type == "wifi")
                    evidence.append(PresenceEvidence(
                        device_id=did,
                        reason="primary device online on wifi" if on_wifi else "primary device online",
                        weight=PRIMARY_WEIGHT,
                    ))
                    score += PRIMARY_WEIGHT
                else:
                    # recently-seen primary device → partial credit during grace.
                    last = self._last_seen_online.get(did)
                    if last is not None and (t - last) < self.settings.presence_away_grace_seconds:
                        primary_in_grace = True
                        evidence.append(PresenceEvidence(
                            device_id=did, reason="primary device recently seen",
                            weight=GRACE_PRIMARY_WEIGHT))
                        score += GRACE_PRIMARY_WEIGHT
            any_supporting = False
            for did in supporting:
                dev = by_id.get(did)
                if dev and dev.is_online and not dev.ignored:
                    self._last_seen_online[did] = t
                    any_supporting = True
                    evidence.append(PresenceEvidence(
                        device_id=did, reason="supporting device online",
                        weight=SUPPORTING_WEIGHT))
                    score += SUPPORTING_WEIGHT

            confidence = min(score, 1.0)

            # Determine status with the longer away-grace debounce.
            if primary_online:
                status = "home"
                self._away_since.pop(pid, None)
            elif any_supporting or primary_in_grace:
                status = "probably_home"
                self._away_since.pop(pid, None)
            else:
                gone_at = self._away_since.setdefault(pid, t)
                if (t - gone_at) >= self.settings.presence_away_grace_seconds:
                    status = "away"
                else:
                    status = "probably_away"

            state = PresenceState(
                person_id=pid,
                display_name=person.get("display_name", pid),
                status=status,  # type: ignore[arg-type]
                confidence=round(confidence, 2),
                primary_device_ids=primary,
                supporting_device_ids=supporting,
                evidence=evidence,
                last_arrived_at=prev.last_arrived_at if prev else None,
                last_left_at=prev.last_left_at if prev else None,
                last_changed_at=prev.last_changed_at if prev else t,
            )

            # Transition events: only when the status string actually changes, so
            # repeated polls in a steady state never re-emit. The strong home/away
            # transitions are success/info; the in-between probably_* are quieter.
            if prev is not None and prev.status != status:
                state.last_changed_at = t
                if status == "home":
                    state.last_arrived_at = t
                    emit(EventType.PRESENCE_PERSON_ARRIVED.value, "success",
                         f"{state.display_name} is thuisgekomen", None, pid)
                elif status == "away":
                    state.last_left_at = t
                    emit(EventType.PRESENCE_PERSON_LEFT.value, "info",
                         f"{state.display_name} is vertrokken", None, pid)
                elif status == "probably_home":
                    emit(EventType.PRESENCE_PERSON_PROBABLY_HOME.value, "info",
                         f"{state.display_name} is waarschijnlijk thuis", None, pid)
                elif status == "probably_away":
                    emit(EventType.PRESENCE_PERSON_PROBABLY_AWAY.value, "info",
                         f"{state.display_name} is waarschijnlijk weg", None, pid)

            self._states[pid] = state
            out.append(state)
        return out

    def home_count(self) -> int:
        return sum(1 for s in self._states.values() if s.status in ("home", "probably_home"))
