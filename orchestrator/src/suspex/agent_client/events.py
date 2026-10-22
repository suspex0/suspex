"""Event dataclass and in-process broadcast bus for the agent client."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    kind: str  # "debug" | "console" | "status"
    session_id: int = 0
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class EventBus:
    """Broadcast hub with per-subscriber queues."""

    def __init__(self, history: int = 1000) -> None:
        self._subs: dict[int, asyncio.Queue[Event]] = {}
        self._next = 0
        self._history: list[Event] = []
        self._history_cap = history

    def subscribe(self) -> tuple[int, asyncio.Queue[Event]]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=4096)
        self._next += 1
        self._subs[self._next] = q
        return self._next, q

    def unsubscribe(self, sub_id: int) -> None:
        self._subs.pop(sub_id, None)

    def publish(self, ev: Event) -> None:
        self._history.append(ev)
        if len(self._history) > self._history_cap:
            del self._history[: len(self._history) - self._history_cap]
        for q in list(self._subs.values()):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass

    @property
    def recent(self) -> list[Event]:
        return list(self._history)
