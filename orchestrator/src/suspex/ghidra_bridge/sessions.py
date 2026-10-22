"""Sessions mixin: adopt / cache / route / MRU bookkeeping."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .errors import GhidraBridgeError
from .helpers import _NON_SESSION_ACTIONS

log = logging.getLogger(__name__)


class GhidraSessionsMixin:
    """Session lifecycle helpers: refresh, cache, MRU, snapshot, resolve."""

    # ------------------------------------------------------------ tool calls ----

    async def refresh_sessions(self) -> None:
        try:
            listing = await self.call_tool_raw("ghidra_list", {})
        except GhidraBridgeError as exc:
            log.warning("ghidra_bridge: ghidra_list failed during adopt: %s", exc)
            return
        if self._cache_sessions_from_listing(listing):
            # Adopted sessions imply a live backend — refresh the tool
            # inventory so extension tools survive a supervisor respawn.
            await self._refresh_tools_for_live_backend()

    async def _maybe_lazy_reopen(
        self, name: str, owner: str | None = None,
    ) -> bool:
        """Auto-open a session that only exists in the manifest.

        Silently drops the manifest entry if the recorded input path no
        longer exists. Returns True when the reopen produced a ready
        session.
        """
        info = self._manifest_sessions.get(name)
        if info is None:
            return False
        input_path = info.get("input_path", "")
        if not input_path or not Path(input_path).is_file():
            log.info(
                "ghidra_bridge: manifest entry %r points at missing "
                "%s; dropping", name, input_path,
            )
            self._manifest_sessions.pop(name, None)
            self._save_manifest()
            return False
        try:
            envelope = await self.open_database(
                Path(input_path), preferred_name=name,
                run_auto_analysis=bool(
                    info.get("run_auto_analysis", True)),
                owner=owner,
            )
        except GhidraBridgeError as exc:
            log.warning(
                "ghidra_bridge: lazy re-open of %r failed (%s); manifest "
                "entry retained", name, exc,
            )
            return False
        return isinstance(envelope, dict) and envelope.get("status") == "ready"

    def _cache_sessions_from_listing(self, listing: Any) -> int:
        text = self._result_text(listing)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return 0
        # shim ghidra_list returns {"sessions": [{session_id, input_path,
        # binary_name, ...}, ...]}
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
            name = str(item.get("binary_name")
                        or item.get("preferred_session_id") or sid)
            self._sessions[name] = sid
            adopted += 1
            self._sessions_owner.setdefault(name, None)
            self._co_owners.setdefault(name, set())
            input_path = item.get("input_path")
            if isinstance(input_path, str) and input_path:
                self._session_paths.setdefault(name, input_path)
        return adopted

    @property
    def mru_session(self) -> str | None:
        """Most-recently-touched session name a session-scoped
        ``ghidra_manage`` action may auto-fill against."""
        return self._mru_session

    def _touch_mru(self, name: str) -> None:
        """Record a successful session touch (open, reuse, co-own)."""
        self._mru_session = name

    def _rotate_mru_after_close(self, closed_name: str) -> None:
        """After a real close (not detach/handover), pick any remaining
        session as the new MRU."""
        if self._mru_session != closed_name:
            return
        self._mru_session = next(iter(self._sessions), None)

    def autofill_session_name(
        self, action: str, name: str | None,
    ) -> tuple[str | None, bool]:
        """Resolve ``(name, mru_autofilled)`` for a caller that may or may
        not have supplied ``name=`` on a session-scoped action. Same
        contract as the IDA bridge."""
        if action in _NON_SESSION_ACTIONS:
            return name, False
        if name:
            return name, False
        mru = self._mru_session
        return mru, True

    @property
    def sessions(self) -> dict[str, str]:
        """friendly name -> shim session id (the `database` argument)."""
        return dict(self._sessions)

    def sessions_snapshot(
        self, current_owner: str | None = None,
    ) -> list[dict[str, Any]]:
        """Structured view of every known session — same shape as the
        IDA bridge's snapshot plus ``binary_name`` for the Ghidra
        program inside the shared project."""
        out: list[dict[str, Any]] = []
        for name, sid in sorted(self._sessions.items()):
            primary = self._sessions_owner.get(name)
            co = sorted(self._co_owners.get(name, set()))
            entry: dict[str, Any] = {
                "name": name,
                "session_id": sid,
                "binary_name": name,
                "owner": primary,
                "co_owners": co,
                "path": self._session_paths.get(name),
                "foreign": False,
                "shared": False,
            }
            if current_owner is not None:
                if current_owner == primary:
                    pass
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
        ``database`` arg."""
        await self.ensure_started()
        if name in self._sessions:
            return {"database": self._sessions[name]}
        await self.refresh_sessions()
        if name in self._sessions:
            return {"database": self._sessions[name]}
        # the name itself may be a raw session id from the LLM
        return {"database": name}
