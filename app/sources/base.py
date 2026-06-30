"""Source adapter interface.

A source adapter is the *only* place that knows a vendor's protocol. It polls its
upstream and returns a normalized ``SourceSnapshot``. It must be:

* **fault-tolerant** — never raise on a transient upstream hiccup; set
  ``self.last_error`` and return the last good snapshot (or an empty one).
* **capability-honest** — report in ``snapshot.capabilities`` only what it
  actually fulfilled this poll, not what it was configured to want.
* **read-only by default** — observation, DHCP/ARP/WiFi visibility, counters,
  health. Any active behaviour (a connectivity ping, a speed test, Wake-on-LAN)
  must be explicit and safe. There is no offensive capability here.
"""

from __future__ import annotations

import time
from typing import Optional

from ..config import Settings, SourceConfig
from ..models import NetworkSource, SourceSnapshot


class NetworkSourceAdapter:
    #: SourceType this adapter implements; overridden by subclasses.
    source_type: str = "unknown"

    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        self.config = config
        self.settings = settings
        self.last_poll_at: Optional[float] = None
        self.last_success_at: Optional[float] = None
        self.last_error_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self._last_snapshot: Optional[SourceSnapshot] = None
        self._fulfilled: list[str] = []

    @property
    def id(self) -> str:
        return self.config.id

    async def start(self) -> None:
        """Optional one-time setup (open a session, authenticate). Default no-op."""

    async def stop(self) -> None:
        """Optional teardown. Default no-op."""

    async def poll(self) -> SourceSnapshot:
        """Fetch + normalize one snapshot. Subclasses implement ``_poll``."""
        self.last_poll_at = time.time()
        try:
            snapshot = await self._poll()
            self.last_success_at = self.last_poll_at
            self.last_error = None
            self._last_snapshot = snapshot
            self._fulfilled = snapshot.capabilities
            return snapshot
        except Exception as exc:  # noqa: BLE001 — never let one source kill the poll loop
            self.last_error = str(exc)
            self.last_error_at = self.last_poll_at
            # Degrade gracefully: hand back the last good snapshot so the device
            # list doesn't blink out on a single failed poll.
            if self._last_snapshot is not None:
                stale = self._last_snapshot.model_copy()
                stale.capabilities = []
                return stale
            return SourceSnapshot(source_id=self.id)

    async def _poll(self) -> SourceSnapshot:  # pragma: no cover - abstract
        raise NotImplementedError

    # --- introspection --------------------------------------------------------
    def describe(self) -> NetworkSource:
        if self.last_error:
            status = "error" if self.last_success_at is None else "degraded"
        elif not self.config.enabled:
            status = "disabled"
        elif self.last_success_at is not None:
            status = "ok"
        else:
            status = "unknown"
        return NetworkSource(
            id=self.id,
            type=self.source_type,  # type: ignore[arg-type]
            display_name=self.config.display_name,
            status=status,  # type: ignore[arg-type]
            last_poll_at=self.last_poll_at,
            last_success_at=self.last_success_at,
            last_error_at=self.last_error_at,
            error_message=self.last_error,
            capabilities=self._fulfilled or self.config.capabilities,
            metadata={"base_url": self.config.base_url} if self.config.base_url else {},
        )

    def supports(self, capability: str) -> bool:
        return capability in (self._fulfilled or self.config.capabilities)
