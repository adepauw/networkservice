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

PRIMARY_WEIGHT = 0.8
SUPPORTING_WEIGHT = 0.2


class PresenceResolver:
    def __init__(self, settings: Settings, persons: list[dict[str, Any]]) -> None:
        self.settings = settings
        self._persons = persons
        self._states: dict[str, PresenceState] = {}
        # person_id -> first time all their devices were gone
        self._away_since: dict[str, float] = {}

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
            for did in primary:
                dev = by_id.get(did)
                if dev and dev.is_online:
                    primary_online = True
                    on_wifi = bool(dev.interfaces and dev.interfaces[0].connection_type == "wifi")
                    evidence.append(PresenceEvidence(
                        device_id=did,
                        reason="primary device online on wifi" if on_wifi else "primary device online",
                        weight=PRIMARY_WEIGHT,
                    ))
                    score += PRIMARY_WEIGHT
            any_supporting = False
            for did in supporting:
                dev = by_id.get(did)
                if dev and dev.is_online:
                    any_supporting = True
                    evidence.append(PresenceEvidence(
                        device_id=did, reason="supporting device online",
                        weight=SUPPORTING_WEIGHT))
                    score += SUPPORTING_WEIGHT

            confidence = min(score, 1.0)
            any_online = primary_online or any_supporting

            # Determine status with the longer away-grace debounce.
            if primary_online:
                status = "home"
                self._away_since.pop(pid, None)
            elif any_supporting:
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

            # Transition events on a meaningful home<->away change.
            prev_home = prev and prev.status in ("home", "probably_home")
            now_home = status in ("home", "probably_home")
            if prev is not None and prev_home != now_home:
                state.last_changed_at = t
                if now_home:
                    state.last_arrived_at = t
                    emit(EventType.PRESENCE_PERSON_ARRIVED.value, "success",
                         f"{state.display_name} is thuisgekomen", None, pid)
                else:
                    state.last_left_at = t
                    emit(EventType.PRESENCE_PERSON_LEFT.value, "info",
                         f"{state.display_name} is vertrokken", None, pid)

            self._states[pid] = state
            out.append(state)
        return out

    def home_count(self) -> int:
        return sum(1 for s in self._states.values() if s.status in ("home", "probably_home"))
