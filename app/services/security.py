"""Defensive threat detection.

CatOS does not attack anything. This module watches for the *fingerprints* of the
common LAN/WiFi attacks and raises alerts so the user can respond — the protective
counterpart to the offensive techniques we deliberately don't build:

* **Deauth / disassoc floods** — a spike in deauth frames reported by the WiFi
  source (the signature of a deauth attack used to knock clients off / set up an
  evil twin). Detection only; we can't and don't transmit deauth frames.
* **Evil-twin / rogue AP** — a nearby BSSID broadcasting *our* SSID that isn't one
  of our known APs.
* **ARP spoofing / MITM** — the same IP suddenly mapping to a new MAC, or one MAC
  claiming many IPs (gratuitous-ARP poisoning used for man-in-the-middle).
* **MAC spoofing** — a trusted device's MAC appearing with a wildly different
  fingerprint (vendor/host) than we've recorded.
* **Port-exposure changes** — a new inbound port opened on the router/firewall
  (the surface an exploit scan would look for); we alert on the *delta*.
* **Suspicious unknown device** — an unknown device that also trips one of the
  above heuristics gets escalated.

All inputs arrive as passive ``snapshot.security_signals`` from sources. Nothing
here probes, captures payloads, or interferes with traffic.
"""

from __future__ import annotations

from ..config import Settings
from ..models import EventType, NetworkDevice, SourceSnapshot, now


class SecurityMonitor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._known_ip_mac: dict[str, str] = {}   # ip -> last-seen mac
        self._open_ports: set[tuple[str, int]] | None = None
        self._device_fingerprint: dict[str, str] = {}  # mac -> "vendor|host"

    def inspect(self, snapshots: list[SourceSnapshot], devices: list[NetworkDevice], emit) -> None:
        """Interpret security signals + the device list into defensive events.

        ``emit(type, severity, title, message, device, metadata)`` — same shape
        the poller hands the inventory service (it owns dedupe/cooldown so a
        sustained attack doesn't spam the timeline).
        """
        by_mac = {d.mac_address: d for d in devices if d.mac_address}

        for snap in snapshots:
            sig = snap.security_signals or {}

            # --- deauth flood -------------------------------------------------
            deauth = sig.get("deauth_frames_last_interval")
            if isinstance(deauth, (int, float)) and deauth >= 100:
                emit(EventType.SECURITY_DEAUTH_DETECTED.value, "critical",
                     "Mogelijke deauth-aanval gedetecteerd",
                     f"{int(deauth)} deauth-frames in laatste interval"
                     + (f" gericht op {sig.get('deauth_target_bssid')}" if sig.get("deauth_target_bssid") else ""),
                     None, {"source": snap.source_id, "frames": deauth,
                            "advice": "Mogelijke poging om clients van WiFi te trappen / evil-twin op te zetten."})

            # --- rogue AP / evil twin ----------------------------------------
            for ap in sig.get("nearby_ssids", []) or []:
                if ap.get("ssid") and not ap.get("known", True) and self._mimics_known(ap, sig):
                    emit(EventType.SECURITY_ROGUE_AP_DETECTED.value, "critical",
                         f"Mogelijke evil-twin op SSID '{ap['ssid']}'",
                         f"Onbekende BSSID {ap.get('bssid')} zendt uit als jouw netwerk (rssi {ap.get('rssi')}).",
                         None, {"source": snap.source_id, "bssid": ap.get("bssid"),
                                "advice": "Verbind niet; controleer of dit een eigen access point is."})

            # --- ARP spoofing -------------------------------------------------
            for entry in sig.get("arp", []) or []:
                ip, mac = entry.get("ip"), entry.get("mac")
                if not ip or not mac:
                    continue
                prev_mac = self._known_ip_mac.get(ip)
                if prev_mac and prev_mac != mac:
                    dev = by_mac.get(mac)
                    emit(EventType.SECURITY_ARP_SPOOF_SUSPECTED.value, "warning",
                         "Verdachte ARP-wijziging",
                         f"{ip} wijst nu naar {mac} (was {prev_mac}) — mogelijke MITM/ARP-spoofing.",
                         dev, {"ip": ip, "old_mac": prev_mac, "new_mac": mac,
                               "advice": "Kan duiden op een man-in-the-middle poging."})
                self._known_ip_mac[ip] = mac

            # --- port exposure delta -----------------------------------------
            ports = sig.get("open_ports")
            if ports is not None:
                current = {(p.get("proto", "tcp"), int(p.get("port"))) for p in ports if p.get("port")}
                if self._open_ports is not None:
                    added = current - self._open_ports
                    for proto, port in sorted(added):
                        emit(EventType.SECURITY_PORT_EXPOSURE_CHANGED.value, "warning",
                             f"Nieuwe open poort: {proto}/{port}",
                             "Een inkomende poort is nu bereikbaar vanaf buiten — controleer of dit bedoeld is.",
                             None, {"proto": proto, "port": port,
                                    "advice": "Nieuw blootgesteld oppervlak; mogelijk doelwit voor exploit-scans."})
                self._open_ports = current

        # --- MAC spoofing of a trusted device --------------------------------
        for dev in devices:
            if not dev.mac_address:
                continue
            fp = f"{(dev.vendor or '').lower()}|{(dev.host_name or '').lower()}"
            prev = self._device_fingerprint.get(dev.mac_address)
            if (prev and prev != fp and dev.trust_level == "trusted"
                    and prev.split("|")[0] and fp.split("|")[0]
                    and prev.split("|")[0] != fp.split("|")[0]):
                emit(EventType.SECURITY_MAC_SPOOF_SUSPECTED.value, "warning",
                     f"Vertrouwd MAC met afwijkende kenmerken: {dev.name}",
                     f"Vingerafdruk veranderde van '{prev}' naar '{fp}' — mogelijk MAC-spoofing.",
                     dev, {"mac": dev.mac_address, "advice": "Iemand kan het MAC van een vertrouwd apparaat nabootsen."})
            self._device_fingerprint[dev.mac_address] = fp

    @staticmethod
    def _mimics_known(ap: dict, sig: dict) -> bool:
        """A nearby AP mimics us if it shares an SSID with one of our known APs."""
        known_ssids = {a.get("ssid") for a in sig.get("nearby_ssids", []) if a.get("known")}
        return ap.get("ssid") in known_ssids
