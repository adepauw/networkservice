"""Inventory service — merges source snapshots into the canonical device list and
detects the device-level state transitions that become network events.

Flow each poll:
    1. Collect snapshots from every source.
    2. Merge devices by identity (MAC > hostname), unioning IPs/sources.
    3. Overlay persisted user metadata + classify unknown devices.
    4. Diff against the previous snapshot to emit firstSeen / online / offline /
       ipChanged / unknownJoined, honouring the offline grace period.

Offline is *debounced*: a known device must be unseen for ``offline_grace`` before
we emit ``device.offline`` (a phone briefly dropping WiFi shouldn't flap).
"""

from __future__ import annotations

from ..config import Settings
from ..models import DeviceMetadata, EventType, NetworkDevice, now
from ..store import LiveStore, MetadataStore
from . import identity


class NetworkInventoryService:
    def __init__(self, settings: Settings, live: LiveStore, metadata: MetadataStore) -> None:
        self.settings = settings
        self.live = live
        self.metadata = metadata
        self._metadata_cache: dict[str, DeviceMetadata] = {}
        # mac -> first time we noticed it gone (for the offline grace window)
        self._gone_since: dict[str, float] = {}
        # The first poll seeds the baseline silently: every already-connected
        # device would otherwise look "new" and fire firstSeen/unknownJoined on
        # cold start (40 alerts on boot). We only alert on devices that appear
        # *after* the baseline is established. Mirrors ServiceEventMonitor's
        # "first observation is the baseline" rule.
        self._baseline_seeded = False

    def load_metadata(self) -> None:
        self._metadata_cache = self.metadata.all()

    def metadata_for(self, mac: str | None) -> DeviceMetadata | None:
        mac = identity.normalize_mac(mac)
        return self._metadata_cache.get(mac) if mac else None

    @staticmethod
    def _unknown_alert_metadata(dev: NetworkDevice, randomized: bool) -> dict:
        """Rich payload for an unknown-device alert — everything CatOS needs to
        render the card and recommend an action without a second round-trip."""
        iface = dev.interfaces[0] if dev.interfaces else None
        return {
            "mac": dev.mac_address,
            "device_id": dev.id,
            "name": dev.name,
            "vendor": dev.vendor,
            "host_name": dev.host_name,
            "ip_address": dev.ip_addresses[0] if dev.ip_addresses else None,
            "connection_type": iface.connection_type if iface else None,
            "band": iface.band if iface else None,
            "first_seen_at": dev.first_seen_at,
            "last_seen_at": dev.last_seen_at,
            "randomized": randomized,
            "advice": "Controleer of dit een bekend toestel is; maak het bekend, "
                      "markeer als gast of negeer het.",
        }

    def _maybe_alert_unknown(self, dev: NetworkDevice, emit) -> None:
        """Raise the unknown-device alert (plus the randomized-MAC hint) for an
        online, non-known, non-ignored device. The poller's per-MAC cooldown
        keeps a flapping device from re-alerting more than once an hour."""
        if dev.is_known or dev.ignored or not dev.is_online:
            return
        randomized = identity.is_randomized_mac(dev.mac_address)
        # guests are expected on the network → a softer signal.
        severity = "info" if dev.trust_level == "guest" else "warning"
        emit(EventType.DEVICE_UNKNOWN_JOINED.value, severity,
             f"Onbekend toestel gevonden: {dev.name}",
             f"{dev.vendor or 'onbekende fabrikant'} · {', '.join(dev.ip_addresses) or '?'}",
             dev, self._unknown_alert_metadata(dev, randomized))
        if randomized:
            emit(EventType.DEVICE_RANDOMIZED_MAC_SUSPECTED.value, "info",
                 f"Toevallig MAC-adres vermoed: {dev.name}",
                 "Het apparaat gebruikt waarschijnlijk een privacy-/random MAC-adres.",
                 dev, {"mac": dev.mac_address})

    def merge(self, snapshots: list) -> list[NetworkDevice]:
        """Pure-ish merge: snapshots -> canonical, metadata-overlaid device list."""
        canonical: dict[str, NetworkDevice] = {}
        for snap in snapshots:
            for raw in snap.devices:
                raw = raw.model_copy(deep=True)
                raw.mac_address = identity.normalize_mac(raw.mac_address)
                did = identity.device_id_for(raw)
                raw.id = did
                if did in canonical:
                    canonical[did] = identity.merge_devices(canonical[did], raw)
                else:
                    canonical[did] = raw
        # overlay metadata + classify
        out: list[NetworkDevice] = []
        for dev in canonical.values():
            meta = self.metadata_for(dev.mac_address)
            dev = identity.apply_metadata(dev, meta)
            dev = identity.classify(dev)
            out.append(dev)
        return out

    def reconcile(self, fresh: list[NetworkDevice], emit) -> list[NetworkDevice]:
        """Diff fresh devices against the live store; emit transition events.

        ``emit(type, severity, title, message, device, metadata)`` is supplied by
        the poller (it owns dedupe/cooldown). Returns the device list to persist
        as the new live snapshot (with offline-grace applied).
        """
        t = now()
        prev = self.live.devices
        baseline = not self._baseline_seeded
        fresh_by_id = {d.id: d for d in fresh}
        result: list[NetworkDevice] = []

        for dev in fresh:
            old = prev.get(dev.id)
            self._gone_since.pop(dev.mac_address or dev.id, None)
            if old is None:
                # brand-new device this poll. On the cold-start baseline poll we
                # seed silently — only devices that appear *after* boot alert.
                dev.first_seen_at = dev.first_seen_at or t
                if not baseline:
                    emit(EventType.DEVICE_FIRST_SEEN.value, "info",
                         f"Nieuw apparaat: {dev.name}",
                         dev.vendor or dev.host_name, dev, {"mac": dev.mac_address})
                    # unknown-device alert — but never for devices the user has
                    # told us to ignore (no noisy alerts), for known ones, nor for
                    # a device the source lists as *offline* (router client lists
                    # include historical clients that aren't actually present).
                    self._maybe_alert_unknown(dev, emit)
            else:
                dev.first_seen_at = old.first_seen_at
                if old.is_known and not old.is_online and dev.is_online:
                    emit(EventType.DEVICE_ONLINE.value, "info",
                         f"{dev.name} is online", None, dev, {})
                elif not old.is_online and dev.is_online and not baseline:
                    # an unknown device re-joining after being away re-alerts,
                    # throttled by the poller's per-MAC unknown-device cooldown.
                    self._maybe_alert_unknown(dev, emit)
                if set(old.ip_addresses) and set(dev.ip_addresses) and \
                        old.ip_addresses[0] != dev.ip_addresses[0]:
                    emit(EventType.DEVICE_IP_CHANGED.value, "info",
                         f"{dev.name} kreeg een nieuw IP",
                         f"{old.ip_addresses[0]} → {dev.ip_addresses[0]}", dev, {})
                dev.last_changed_at = old.last_changed_at
            result.append(dev)

        # devices that vanished this poll — apply the offline grace before emitting
        for did, old in prev.items():
            if did in fresh_by_id:
                continue
            key = old.mac_address or did
            gone_at = self._gone_since.setdefault(key, t)
            grace_passed = (t - gone_at) >= self.settings.offline_grace_seconds
            stale = old.model_copy(deep=True)
            if grace_passed:
                if old.is_online and old.is_known:
                    emit(EventType.DEVICE_OFFLINE.value, "info",
                         f"{old.name} is offline", None, old, {})
                stale.is_online = False
                result.append(stale)
            else:
                # still within grace: keep showing it online so we don't flap
                result.append(stale)
        self._baseline_seeded = True
        return result
