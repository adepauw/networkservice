"""SSE broadcaster — identical pattern to hueservice/doorbellservice.

The poller publishes a typed signal whenever observable state changes; CatOS holds
one EventSource on ``/events/stream`` and revalidates on each signal instead of
hammering the poll endpoints. publish() is thread-safe so it can be called from
any worker thread (SSH/ubus calls run in a thread pool).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any


class EventBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def publish(self, event: str = "changed", payload: dict[str, Any] | None = None) -> None:
        """Fan out an SSE event. `event` is the SSE event name CatOS listens for."""
        loop = self._loop
        if loop is None:
            return
        data = json.dumps(payload or {"reason": event})
        loop.call_soon_threadsafe(self._fanout, event, data)

    def _fanout(self, event: str, data: str) -> None:
        frame = f"event: {event}\ndata: {data}\n\n"
        for q in list(self._subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(frame)

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator["asyncio.Queue[str]"]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=32)
        self._subscribers.add(q)
        try:
            yield q
        finally:
            self._subscribers.discard(q)


broker = EventBroker()


async def event_source(request, keepalive: float = 25.0) -> AsyncIterator[bytes]:
    """SSE response body: typed events plus periodic keepalive comments.

    Emits a generic ``changed`` event (so the existing useServiceEvents hook
    revalidates) for every published frame, since each frame already carries its
    own event name. A reconnecting EventSource resumes cleanly — no server state.
    """
    async with broker.subscribe() as q:
        yield b": connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                frame = await asyncio.wait_for(q.get(), timeout=keepalive)
                yield frame.encode()
            except asyncio.TimeoutError:
                yield b": keepalive\n\n"
