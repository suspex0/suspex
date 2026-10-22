"""Sessions mixin: adopt / cache / route / MRU bookkeeping."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .errors import IdaBridgeError
from .helpers import _NON_SESSION_ACTIONS

log = logging.getLogger(__name__)


class IdaSessionsMixin:
    """Session lifecycle helpers: refresh, cache, MRU, snapshot, resolve."""

    # ------------------------------------------------------------ tool calls ----

    async def refresh_sessions(self) -> None:
        try:
            listing = await self.call_tool_raw("idb_list", {})
        except IdaBridgeError as exc:
            log.warning("ida_bridge: idb_list failed during adopt: %s", exc)
            return
        if self._cache_sessions_from_listing(listing):
            # v0.24: adopted sessions imply live backends — refresh the
            # tool inventory so extension tools survive a supervisor
            # respawn without a manual schemas call.
            await self._refresh_tools_for_live_backend()

    async def _maybe_lazy_reopen(
        self, name: str, owner: str | None = None,
    ) -> bool:
        """Auto-open a session that only exists in the manifest.

        Called from :meth:`ida_manage` when the caller referenced a
        name that isn't in ``_sessions`` but IS in the manifest —
        typical case: orchestrator restarted while an idalib
        persistent worker died with it, and the LLM just tried to
        call a session-scoped action against the pre-restart name.

        Silently drops the manifest entry if the recorded input path
        no longer exists (the .sys was moved or the user deleted it):
        the caller then hits the usual unknown-name error path with a
        clean bookkeeping state instead of a stale ghost.

        Returns True when the reopen succeeded, False otherwise.
        """
        info = self._manifest_sessions.get(name)
        if info is None:
            return False
        input_path = info.get("input_path", "")
        if not input_path or not Path(input_path).is_file():
            log.info(
                "ida_bridge: manifest entry %r points at missing "
                "%s; dropping", name, input_path,
            )
            self._manifest_sessions.pop(name, None)
            # Persist the drop so a same-crash-loop doesn't keep
            # trying the same dead entry.
            self._save_manifest()
            return False
        try:
            envelope = await self.open_database(
                Path(input_path), preferred_name=name,
                run_auto_analysis=bool(
                    info.get("run_auto_analysis", True)),
                owner=owner,
            )
        except IdaBridgeError as exc:
            log.warning(
                "ida_bridge: lazy re-open of %r failed (%s); manifest "
                "entry retained", name, exc,
            )
            return False
        # open_database may return status=pending on huge DBs — treat
        # that as "started, use the pending path" — the caller can
        # poll open_status. But for the ida_manage session-scoped call
        # flow the caller expected a live session, so pending is
        # effectively a "still not ready" failure at THIS call site.
        return isinstance(envelope, dict) and envelope.get("status") == "ready"

    def _cache_sessions_from_listing(self, listing: Any) -> int:
        text = self._result_text(listing)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return 0
        # shim idb_list returns {"sessions": [{session_id, input_path, ...}, ...]}
        items: list[Any]
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            items = data["sessions"]
        elif isinstance(data, list):
            items = data
        else:
            return 0
        adopted = 0
        for item in items:
            if not isinstance(item, dict) or "session_id" not in item:
                continue
            sid = str(item["session_id"])
            name = str(item.get("preferred_session_id") or sid)
            self._sessions[name] = sid
            adopted += 1
            # Adopted sessions have no orchestrator-side owner; setdefault
            # preserves any owner already recorded from an in-process open.
            self._sessions_owner.setdefault(name, None)
            self._co_owners.setdefault(name, set())
            input_path = item.get("input_path")
            if isinstance(input_path, str):
                self._session_paths.setdefault(name, input_path)
        return adopted

    @property
    def mru_session(self) -> str | None:
        """v0.17 C1-3: most-recently-touched session name (open or reuse)
        that a session-scoped ``ida_manage`` action may auto-fill against
        when the caller didn't supply ``name=``. ``None`` when no sessions
        are known.

        Read by :py:meth:`tools.ida_manage` (via
        :py:meth:`autofill_session_name`); ``ida_bridge`` never dispatches
        against the MRU on its own — the caller either passes the name
        explicitly or falls through to the autofill helper.
        """
        return self._mru_session

    def _touch_mru(self, name: str) -> None:
        """Record a successful session touch (open, reuse, co-own)."""
        self._mru_session = name

    def _rotate_mru_after_close(self, closed_name: str) -> None:
        """After a real close (not detach/handover), pick any remaining
        session as the new MRU. Preserves the current MRU when a
        non-MRU session went away."""
        if self._mru_session != closed_name:
            return
        # dict.keys iteration order is insertion-ordered so the fallback is
        # deterministic: the next-oldest live session inherits MRU. When
        # no sessions remain we clear the pointer so autofill_session_name
        # surfaces the right actionable "no MRU" error instead of a stale
        # dangling name.
        self._mru_session = next(iter(self._sessions), None)

    def autofill_session_name(
        self, action: str, name: str | None,
    ) -> tuple[str | None, bool]:
        """v0.17 C1-3: resolve ``(name, mru_autofilled)`` for a caller
        that may or may not have supplied ``name=`` on a session-scoped
        action.

        Returns ``(name, False)`` unchanged when:
          * ``action`` is a non-session action (``open`` / ``open_async``
            / ``open_status`` / ``list`` / ``schemas``) — those either
            create a session, or don't need one, and never fall back to
            an MRU;
          * ``name`` was supplied — the caller was explicit, respect it.

        Returns ``(mru, True)`` when a session-scoped action was called
        with no ``name=`` and an MRU session exists. Callers surface a
        warning after the dispatch so silent MRU steering never masks
        which session actually served the request.

        Returns ``(None, True)`` when a session-scoped action was
        called with no ``name=`` and no MRU exists — the ``True``
        signals "should have autofilled but couldn't" so the caller
        raises an actionable "open a session first" error instead of
        letting the shim surface a confusing bad-database failure.
        """
        if action in _NON_SESSION_ACTIONS:
            return name, False
        if name:
            return name, False
        mru = self._mru_session
        return mru, True

    @property
    def sessions(self) -> dict[str, str]:
        """friendly name -> idalib session id (use as the `database` argument).

        Kept for backwards compatibility with callers that only need the
        name -> session_id mapping. Prefer :meth:`sessions_snapshot`,
        which also reports ownership and share state per public name.
        """
        return dict(self._sessions)

    def sessions_snapshot(
        self, current_owner: str | None = None,
    ) -> list[dict[str, Any]]:
        """Structured view of every known session.

        Each entry:
          - ``name``: public name (may include a ``#hex`` suffix if two
            owners requested the same friendly name for different paths)
          - ``session_id``: idalib session id (the ``database=`` argument)
          - ``owner``: primary owner client_id (``None`` for sessions
            adopted from a persistent worker)
          - ``co_owners``: sorted list of extra client_ids sharing via
            ``share=True``
          - ``path``: recorded input_path (``None`` if adopted without one)
          - ``foreign``: ``True`` when ``current_owner`` was supplied and
            is neither the primary owner nor a co-owner of this session
          - ``shared``: ``True`` when ``current_owner`` is a co-owner of
            this session (i.e. joined via ``share=True``)
        """
        out: list[dict[str, Any]] = []
        for name, sid in sorted(self._sessions.items()):
            primary = self._sessions_owner.get(name)
            co = sorted(self._co_owners.get(name, set()))
            entry: dict[str, Any] = {
                "name": name,
                "session_id": sid,
                "owner": primary,
                "co_owners": co,
                "path": self._session_paths.get(name),
                "foreign": False,
                "shared": False,
            }
            if current_owner is not None:
                if current_owner == primary:
                    pass  # primary owner: foreign=False, shared=False
                elif current_owner in co:
                    entry["shared"] = True
                else:
                    entry["foreign"] = True
            out.append(entry)
        return out

    async def resolve_database(
        self, name: str, current_owner: str | None = None,
    ) -> dict[str, Any]:
        """Map a friendly name (or raw session id) to the required
        ``database`` arg.

        ``current_owner`` — when supplied, this method still resolves
        the name (public names are unique and both primary and
        co-owners share the same entry), but callers can consult
        ``sessions_snapshot(current_owner)`` beforehand to detect and
        refuse access to a ``foreign`` session. The parameter is
        accepted here for symmetry with :meth:`close_database` and to
        leave room for future per-owner name views without another
        signature bump.
        """
        await self.ensure_started()
        if name in self._sessions:
            return {"database": self._sessions[name]}
        await self.refresh_sessions()
        if name in self._sessions:
            return {"database": self._sessions[name]}
        # the name itself may be a raw session id from the LLM
        return {"database": name}
