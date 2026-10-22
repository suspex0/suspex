"""In-process ownership registry for non-leased primitives.

Records which owner (e.g. an agent/session id) claimed a given primitive
identity — a breakpoint view, an exec_shell view, an IDA session, an
emulator session — so tools can flag mutations from a different owner as
"foreign" and let the caller decide policy (warn-only, refuse, prompt,
etc.). Leased primitives have their own lease machinery; this module is
for the everything-else case.

Categories are opaque strings; the well-known ones are:

    - 'bp:<view>'
    - 'exec_shell:<view>'
    - 'exec_detached:<view>'
    - 'ida_session'
    - 'emulate_session'

but callers may invent their own. Keys are opaque strings scoped to
their category.

The registry is async-safe: every mutation and read that traverses more
than one entry goes through an ``asyncio.Lock``. Point reads
(``owner_of``, ``is_foreign_or_none``) also take the lock so callers
never observe a torn state during a claim/release.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class _Entry:
    owner: str
    since: float  # epoch seconds, from time.time()


def _iso(since: float) -> str:
    """Render an epoch second as an ISO-8601 UTC string (seconds precision)."""
    return (
        datetime.fromtimestamp(since, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class OwnershipRegistry:
    """Async-safe ownership tag store.

    All state lives in ``self._by_cat: dict[str, dict[str, _Entry]]``,
    guarded by ``self._lock``. Operations are O(1) per key except
    ``release_by_owner`` and ``list_by``, which scan.
    """

    def __init__(self) -> None:
        self._by_cat: dict[str, dict[str, _Entry]] = {}
        self._lock = asyncio.Lock()

    # ---- mutation --------------------------------------------------------

    async def claim(self, category: str, key: str, owner: str) -> None:
        """Record ``owner`` as the owner of ``(category, key)``.

        No-op if the same owner already owns it (idempotent re-claim).
        If a *different* owner already owns it, the existing owner is
        left in place — callers must release first if they want to
        transfer ownership. This keeps ``claim`` safe to call
        opportunistically (e.g. on every mutation) without accidentally
        stealing tags.
        """
        async with self._lock:
            bucket = self._by_cat.setdefault(category, {})
            existing = bucket.get(key)
            if existing is None:
                bucket[key] = _Entry(owner=owner, since=time.time())
            # same owner or different owner: leave existing entry alone.

    async def release(self, category: str, key: str) -> None:
        """Drop the tag for ``(category, key)`` if present."""
        async with self._lock:
            bucket = self._by_cat.get(category)
            if bucket is None:
                return
            bucket.pop(key, None)
            if not bucket:
                self._by_cat.pop(category, None)

    async def release_by_owner(self, owner: str) -> None:
        """Drop every tag currently held by ``owner``.

        Intended for teardown when an agent/session goes away.
        """
        async with self._lock:
            empty_cats: list[str] = []
            for cat, bucket in self._by_cat.items():
                stale = [k for k, e in bucket.items() if e.owner == owner]
                for k in stale:
                    del bucket[k]
                if not bucket:
                    empty_cats.append(cat)
            for cat in empty_cats:
                self._by_cat.pop(cat, None)

    # ---- reads -----------------------------------------------------------

    async def owner_of(self, category: str, key: str) -> str | None:
        """Return the owner string for ``(category, key)`` or None."""
        async with self._lock:
            bucket = self._by_cat.get(category)
            if bucket is None:
                return None
            entry = bucket.get(key)
            return entry.owner if entry is not None else None

    async def list_by(self, category: str) -> list[dict[str, Any]]:
        """Snapshot all tags in ``category``.

        Returns a list of ``{key, owner, since_iso}`` dicts, sorted by
        ``since`` ascending so oldest claims come first. The list is a
        fresh copy — safe for the caller to mutate.
        """
        async with self._lock:
            bucket = self._by_cat.get(category)
            if not bucket:
                return []
            items = sorted(bucket.items(), key=lambda kv: kv[1].since)
            return [
                {"key": k, "owner": e.owner, "since_iso": _iso(e.since)}
                for k, e in items
            ]

    async def categories(self) -> list[str]:
        """Snapshot every category name currently holding tags."""
        async with self._lock:
            return list(self._by_cat.keys())

    async def release_category(self, category: str) -> int:
        """Drop every tag in ``category``; returns the count removed."""
        async with self._lock:
            bucket = self._by_cat.pop(category, None)
            return len(bucket) if bucket else 0

    async def is_foreign_or_none(
        self,
        category: str,
        key: str,
        current_owner: str,
    ) -> bool | None:
        """Would a mutation by ``current_owner`` be foreign?

        Returns:
            True  — a different owner holds the tag.
            False — ``current_owner`` holds the tag (or is re-claiming).
            None  — no tag is recorded; caller decides policy
                    (typically permissive: warn-but-allow, or auto-claim).
        """
        async with self._lock:
            bucket = self._by_cat.get(category)
            if bucket is None:
                return None
            entry = bucket.get(key)
            if entry is None:
                return None
            return entry.owner != current_owner

    # ---- bulk annotation -------------------------------------------------

    async def annotate(
        self,
        category: str,
        entries: list[dict[str, Any]],
        id_field: str,
        current_owner: str,
    ) -> None:
        """Stamp ``owner`` and ``foreign`` fields onto each entry in place.

        For every ``e`` in ``entries``, looks up
        ``(category, e[id_field])`` and sets:

            e['owner']   = owner string or None
            e['foreign'] = True if owned by someone other than
                           current_owner; False if owned by
                           current_owner; None if unowned.

        Missing ``id_field`` on an entry is treated as an unowned key
        (both fields become None) rather than raising, so this can be
        called against listings assembled from multiple sources without
        pre-validation.

        The whole pass runs under a single lock so the snapshot is
        consistent across entries.
        """
        async with self._lock:
            bucket = self._by_cat.get(category, {})
            for e in entries:
                key = e.get(id_field)
                entry = bucket.get(key) if isinstance(key, str) else None
                if entry is None:
                    e["owner"] = None
                    e["foreign"] = None
                else:
                    e["owner"] = entry.owner
                    e["foreign"] = entry.owner != current_owner


__all__ = ["OwnershipRegistry"]
