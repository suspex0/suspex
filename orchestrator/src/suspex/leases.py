"""Async-safe lease manager for suspex0.

Two resource families are leased in this system:

* ``debug:<view>:pid=<pid>`` — held from ``debug_manage`` launch/attach until
  detach (or peer reap by ``release_by_owner``).
* ``driver`` — held for the duration of ``driver_load`` / ``driver_unload``.
  A peer's kernel-view refcount is enforced *outside* this module and blocks
  ``driver_unload`` with ``in_use_by``; the lease here only serializes the
  load/unload critical section itself.

The manager is async-only. All mutations are serialized under one
:class:`asyncio.Condition`, so concurrent tasks observe a consistent view of
holders and waiters are woken deterministically when a slot frees.

Every ``acquire`` and ``release`` publishes an event dict of the shape

    {"type": "lease_acquire" | "lease_release",
     "resource": str, "owner": str, "since": float}

onto the injected ``publish_event`` callable.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Union

__all__ = ["LeaseManager", "LeaseHandle", "BusyInfo"]


PublishEvent = Callable[[dict[str, Any]], Any]


def _iso(ts: float) -> str:
    """Format an epoch-second timestamp as an ISO-8601 UTC string ending in ``Z``."""
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class BusyInfo:
    """Returned by :meth:`LeaseManager.acquire` when the resource is held.

    ``waited_s`` reflects how long the caller actually blocked before giving
    up — ``0.0`` on the non-blocking path, and up to ``wait_s`` on the
    blocking path.
    """

    held_by: str
    since_iso: str
    waited_s: float
    kind: str = "busy"


@dataclass(eq=False)
class LeaseHandle:
    """A held lease. Acts as an async context manager:

        async with await mgr.acquire("driver", "kernel", 5.0) as lease:
            ...

    Callers may also release explicitly via :meth:`LeaseManager.release`.
    Both paths are idempotent — releasing twice, or exiting the ``async
    with`` after an explicit release, is a no-op.
    """

    resource: str
    owner: str
    since: float
    _mgr: "LeaseManager" = field(repr=False)
    _released: bool = field(default=False, repr=False)

    @property
    def since_iso(self) -> str:
        return _iso(self.since)

    async def __aenter__(self) -> "LeaseHandle":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._mgr.release(self)


# Convenience alias for the acquire() return type.
AcquireResult = Union[LeaseHandle, BusyInfo]


class LeaseManager:
    """Async-safe lease manager.

    A single :class:`asyncio.Condition` serializes state changes and is used
    to wake waiters when a resource is released. Construct one per running
    event loop — the internal condition binds to the loop it was created on.
    """

    def __init__(self, publish_event: PublishEvent) -> None:
        self._publish = publish_event
        self._cond = asyncio.Condition()
        self._holders: dict[str, LeaseHandle] = {}

    # ------------------------------------------------------------------ core

    async def acquire(
        self,
        resource: str,
        owner: str,
        wait_s: float | None,
    ) -> AcquireResult:
        """Acquire ``resource`` for ``owner``.

        * ``wait_s`` of ``None`` or ``<= 0`` is non-blocking: returns
          :class:`BusyInfo` immediately if the resource is held.
        * ``wait_s > 0`` waits up to that many seconds (measured on the
          running loop's monotonic clock) before giving up with
          :class:`BusyInfo`.

        On success returns a :class:`LeaseHandle` and publishes a
        ``lease_acquire`` event.
        """
        loop = asyncio.get_running_loop()
        wait_start = loop.time()
        blocking = wait_s is not None and wait_s > 0
        deadline = wait_start + (wait_s if blocking else 0.0)

        async with self._cond:
            while resource in self._holders:
                if not blocking:
                    return self._busy(resource, waited_s=0.0)

                remaining = deadline - loop.time()
                if remaining <= 0:
                    return self._busy(
                        resource, waited_s=loop.time() - wait_start
                    )

                try:
                    await asyncio.wait_for(
                        self._cond.wait(), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    # The slot may have freed at the very moment we timed
                    # out — give it one recheck before declaring busy.
                    if resource not in self._holders:
                        break
                    return self._busy(
                        resource, waited_s=loop.time() - wait_start
                    )

            handle = LeaseHandle(
                resource=resource,
                owner=owner,
                since=time.time(),
                _mgr=self,
            )
            self._holders[resource] = handle

        self._emit("lease_acquire", handle)
        return handle

    async def release(self, handle: LeaseHandle) -> None:
        """Release ``handle``. Idempotent.

        A no-op when the handle has already been released, or when the slot
        has since been taken by a different owner (defensive — a peer reap
        via :meth:`release_by_owner` marks the handle first, so the async
        context-manager exit that follows stays quiet).
        """
        async with self._cond:
            if handle._released:
                return
            current = self._holders.get(handle.resource)
            if current is not handle:
                handle._released = True
                return
            handle._released = True
            del self._holders[handle.resource]
            self._cond.notify_all()

        self._emit("lease_release", handle)

    async def release_by_owner(self, owner: str) -> list[str]:
        """Release every lease currently held by ``owner``.

        Used when a peer disappears (a debug view is reaped, an agent
        disconnects). Returns the resource names that were freed, in the
        order they were dropped from the holder table. Publishes one
        ``lease_release`` event per victim.
        """
        victims: list[LeaseHandle] = []
        async with self._cond:
            for h in list(self._holders.values()):
                if h.owner == owner and not h._released:
                    h._released = True
                    del self._holders[h.resource]
                    victims.append(h)
            if victims:
                self._cond.notify_all()

        for h in victims:
            self._emit("lease_release", h)
        return [h.resource for h in victims]

    # ------------------------------------------------------------ observers

    def who_holds(self, resource: str) -> str | None:
        """Return the current owner of ``resource``, or ``None`` if free.

        Lock-free by design so the dashboard can render snapshots without
        contending with an in-flight acquire.
        """
        h = self._holders.get(resource)
        return h.owner if h is not None else None

    def snapshot(self) -> dict[str, dict[str, str]]:
        """Return ``{resource: {"owner", "since_iso"}}`` for held leases.

        The returned dict is a fresh copy; callers may mutate it freely.
        """
        return {
            res: {"owner": h.owner, "since_iso": _iso(h.since)}
            for res, h in self._holders.items()
        }

    # -------------------------------------------------------------- helpers

    def _busy(self, resource: str, waited_s: float) -> BusyInfo:
        holder = self._holders[resource]
        return BusyInfo(
            held_by=holder.owner,
            since_iso=_iso(holder.since),
            waited_s=waited_s,
        )

    def _emit(self, kind: str, handle: LeaseHandle) -> None:
        self._publish(
            {
                "type": kind,
                "resource": handle.resource,
                "owner": handle.owner,
                "since": handle.since,
            }
        )
