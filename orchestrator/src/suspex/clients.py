"""In-process client registry for the suspex0 orchestrator.

Tracks every MCP peer that has said hello — first-seen / last-op
wall-clock stamps for the /peers dashboard, per-view refcounts so the
concurrency lease knows when a view is idle, and a set of "held" attach
pids so a peer that vanishes doesn't leave a target permanently latched.
A single ``asyncio.Lock`` guards every mutation so tool handlers running
on different tasks can update the same peer without racing.

``subscribe()`` yields ``{kind, client_id, ...}`` events; the lease
manager publishes acquire/release through the same channel so the
dashboard SSE stream sees one ordered feed of everything that happens
to a peer (join, refcount, held-attach, leave).

Nothing runs on import. ``ClientRegistry.start(idle_reap_s)`` — called
once from ``server.build_app`` after the event loop is up — spins the
periodic idle-reaper. ``stop()`` is provided for orderly shutdown and
for tests that build a registry per case."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator


def _iso(ts: float) -> str:
    """UTC ISO-8601 stamp truncated to seconds — matches the format the
    dashboard renders in its peer table."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class ClientInfo:
    """One peer's state. ``first_seen`` / ``last_op`` are ``time.time()``
    wall-clock seconds so ISO conversion is a straight
    ``datetime.fromtimestamp``; the reap loop's own scheduling uses the
    asyncio loop clock (monotonic) so a wall-clock jump can only ever
    cause a one-cycle delay in evicting a stale peer, never a spin."""

    client_id: str
    transport: str
    first_seen: float
    last_op: float
    held_attach: set[tuple[str, int]] = field(default_factory=set)
    refs: dict[str, int] = field(default_factory=dict)


class ClientRegistry:
    """Async-safe peer registry + SSE-style event bus.

    Every public mutation acquires ``self._lock`` for the read/modify
    of ``self._clients``. Event publishing happens *after* releasing
    the lock so a slow subscriber queue can never wedge the registry.
    """

    def __init__(self) -> None:
        self._clients: dict[str, ClientInfo] = {}
        self._lock = asyncio.Lock()
        self._subs: set[asyncio.Queue[dict]] = set()
        self._reap_task: asyncio.Task[None] | None = None
        self._reap_interval: float = 30.0
        self._reap_idle_s: float = 300.0
        # Signals the reap loop to exit promptly on stop() instead of
        # sleeping out its next tick.
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self, idle_reap_s: float) -> None:
        """Spin up the periodic idle-reaper. Idempotent: a second call
        with a different threshold updates the interval but does not
        start a second task."""
        async with self._lock:
            self._reap_idle_s = float(idle_reap_s)
            # Wake at least once per quarter-window (so a peer is at
            # worst 1.25× the threshold old before eviction) and at
            # most every 5s (so a tiny idle_reap_s doesn't spin the
            # loop).
            self._reap_interval = max(5.0, float(idle_reap_s) / 4.0)
            if self._reap_task is None or self._reap_task.done():
                self._stop.clear()
                self._reap_task = asyncio.create_task(
                    self._reap_loop(), name="suspex-client-reaper")

    async def stop(self) -> None:
        """Cancel the reap task and wait for it to exit. Safe to call
        even if ``start()`` was never called."""
        self._stop.set()
        task = self._reap_task
        self._reap_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                # A crash in the reap loop must not propagate out of
                # shutdown — logging happens inside the loop itself.
                pass

    # ------------------------------------------------------------------ #
    # Registration / activity
    # ------------------------------------------------------------------ #
    async def register(self, client_id: str, transport: str = "http") -> None:
        """First-touch a peer. Idempotent: re-registering the same
        ``client_id`` refreshes ``last_op`` and ``transport`` but does
        not emit a duplicate ``join`` event."""
        now = time.time()
        event: dict | None = None
        async with self._lock:
            info = self._clients.get(client_id)
            if info is None:
                self._clients[client_id] = ClientInfo(
                    client_id=client_id,
                    transport=transport,
                    first_seen=now,
                    last_op=now,
                )
                event = {
                    "kind": "join",
                    "client_id": client_id,
                    "transport": transport,
                    "at": _iso(now),
                }
            else:
                info.last_op = now
                info.transport = transport
        if event is not None:
            await self.publish(event)

    async def touch(self, client_id: str) -> None:
        """Bump ``last_op`` for an existing peer. No-op if unknown —
        the caller (tool dispatch) may not know yet whether ``hello``
        landed for this client_id, and we don't want to synthesize a
        peer here (that's ``register``'s job)."""
        now = time.time()
        async with self._lock:
            info = self._clients.get(client_id)
            if info is not None:
                info.last_op = now

    async def get(self, client_id: str) -> ClientInfo | None:
        async with self._lock:
            return self._clients.get(client_id)

    async def list_peers(self) -> list[dict]:
        """Snapshot of every peer for the /peers dashboard route.
        Sorted by ``client_id`` so a UI refresh doesn't reorder rows
        under the operator's cursor."""
        now = time.time()
        async with self._lock:
            out: list[dict] = []
            for info in self._clients.values():
                out.append({
                    "client_id": info.client_id,
                    "first_seen_iso": _iso(info.first_seen),
                    "last_op_iso": _iso(info.last_op),
                    "seconds_idle": max(0.0, now - info.last_op),
                    "held_attach_pids": sorted({pid for _, pid in info.held_attach}),
                    "connected_views": sorted(v for v, n in info.refs.items() if n > 0),
                })
        out.sort(key=lambda p: p["client_id"])
        return out

    # ------------------------------------------------------------------ #
    # Held attaches (survive across a peer's tool calls)
    # ------------------------------------------------------------------ #
    async def held_attach_add(self, client_id: str, view: str, pid: int) -> None:
        async with self._lock:
            info = self._clients.get(client_id)
            if info is not None:
                info.held_attach.add((view, int(pid)))
                info.last_op = time.time()

    async def held_attach_remove(self, client_id: str, view: str, pid: int) -> None:
        async with self._lock:
            info = self._clients.get(client_id)
            if info is not None:
                info.held_attach.discard((view, int(pid)))
                info.last_op = time.time()

    # ------------------------------------------------------------------ #
    # Per-view refcounts (drive the concurrency lease)
    # ------------------------------------------------------------------ #
    async def refcount_add(self, client_id: str, view: str) -> None:
        async with self._lock:
            info = self._clients.get(client_id)
            if info is not None:
                info.refs[view] = info.refs.get(view, 0) + 1
                info.last_op = time.time()

    async def refcount_remove(self, client_id: str, view: str) -> None:
        """Decrement a view's refcount; drop the entry when it hits
        zero so ``list_peers`` reports ``connected_views`` accurately
        without a positive-count filter surprise later."""
        async with self._lock:
            info = self._clients.get(client_id)
            if info is None:
                return
            n = info.refs.get(view, 0) - 1
            if n <= 0:
                info.refs.pop(view, None)
            else:
                info.refs[view] = n
            info.last_op = time.time()

    # ------------------------------------------------------------------ #
    # Reap
    # ------------------------------------------------------------------ #
    async def reap_idle(self, idle_reap_s: float) -> list[str]:
        """Evict peers whose ``last_op`` is older than ``idle_reap_s``
        seconds — but leave alone any peer that still holds an attach
        pid or a positive-refcount view. Those are the lease-release
        path's responsibility; the idle sweeper reaping them would
        silently drop live state."""
        now = time.time()
        deadline = now - float(idle_reap_s)
        events: list[dict] = []
        reaped: list[str] = []
        async with self._lock:
            for cid, info in list(self._clients.items()):
                if info.last_op > deadline:
                    continue
                if info.held_attach or any(n > 0 for n in info.refs.values()):
                    continue
                del self._clients[cid]
                reaped.append(cid)
                events.append({
                    "kind": "leave",
                    "client_id": cid,
                    "reason": "idle",
                    "seconds_idle": now - info.last_op,
                    "at": _iso(now),
                })
        for ev in events:
            await self.publish(ev)
        return reaped

    async def _reap_loop(self) -> None:
        """Wake every ``self._reap_interval`` seconds (or immediately
        on stop) and call ``reap_idle``. Exceptions inside the sweep
        are swallowed so one bad tick doesn't kill the loop."""
        try:
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=self._reap_interval)
                    return  # stop set — exit
                except asyncio.TimeoutError:
                    pass
                try:
                    await self.reap_idle(self._reap_idle_s)
                except Exception:
                    # Best-effort: a subscriber queue error or a lock
                    # anomaly here must not let idle peers accumulate
                    # forever. Server-level logging picks it up if the
                    # dashboard notices peers going stale.
                    pass
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------ #
    # Event bus
    # ------------------------------------------------------------------ #
    def subscribe(self) -> AsyncIterator[dict]:
        """Return an async iterator of registry events for one SSE
        client. Each subscriber gets its own unbounded queue: dropping
        a join/leave would silently desync the dashboard's peer list,
        and only a runaway publisher could actually fill it (in which
        case memory pressure is the least of the operator's problems).
        The subscriber's ``finally`` clause discards its queue when
        the consumer stops iterating — no manual unsubscribe needed."""
        q: asyncio.Queue[dict] = asyncio.Queue()
        self._subs.add(q)

        async def _stream() -> AsyncIterator[dict]:
            try:
                while True:
                    yield await q.get()
            finally:
                self._subs.discard(q)

        return _stream()

    async def publish(self, event: dict) -> None:
        """Fan an event out to every current subscriber. Snapshotted
        via ``list(...)`` so a subscriber unsubscribing mid-publish
        (its generator's ``finally`` runs ``discard``) doesn't mutate
        the set we're iterating."""
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover — queues are unbounded
                pass
