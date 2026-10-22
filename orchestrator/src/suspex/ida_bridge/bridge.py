"""Concrete :class:`IdaBridge` — composes every mixin and holds the state."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .config import IdaConfigLite, _default_manifest_path
from .lifecycle import IdaLifecycleMixin
from .manifest import IdaManifestMixin
from .openclose import IdaOpenCloseMixin
from .sessions import IdaSessionsMixin
from .tools_schema import IdaToolsMixin


class IdaBridge(
    IdaManifestMixin,
    IdaSessionsMixin,
    IdaOpenCloseMixin,
    IdaToolsMixin,
    IdaLifecycleMixin,
):
    """One supervisor process, many idalib worker sessions."""

    def __init__(self, cfg: IdaConfigLite, artifacts_dir: Path) -> None:
        self.cfg = cfg
        self.artifacts_dir = artifacts_dir
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._next_id = 1
        self._tools: dict[str, dict[str, Any]] = {}
        # v0.24: latches True once the post-backend tools/list refresh has
        # pulled real schemas (see
        # IdaToolsMixin._refresh_tools_for_live_backend). The startup
        # inventory runs before any backend exists, so extension tools are
        # absent until then; one-shot so the refresh costs a single
        # tools/list per supervisor lifetime.
        self._tools_live_refreshed = False
        # public name -> idalib session id. "Public name" is the string
        # the winning caller passed as preferred_session_id; when a later
        # caller reuses the same name for a *different* binary, that
        # peer's public name is auto-suffixed with `#<hex>` so both open
        # sessions coexist. Every downstream `database=` arg uses the
        # session id stored here.
        self._sessions: dict[str, str] = {}
        # public name -> primary-owner client_id (whichever caller first
        # registered the name). None for sessions adopted from a
        # persistent worker by refresh_sessions -- no orchestrator owner
        # exists for those, so any caller may close them.
        self._sessions_owner: dict[str, str | None] = {}
        # public name -> extra client_ids co-using the session via
        # share=True. The primary owner is NOT duplicated here.
        self._co_owners: dict[str, set[str]] = {}
        # public name -> absolute binary path (str). Used to decide
        # whether a peer's open collides (different path -> synthesize a
        # new public name) or shares (same path + share=True -> add as
        # co-owner and route to the existing session id).
        self._session_paths: dict[str, str] = {}
        # name -> (task, binary_path) for open_database_async: a caller
        # that gave up on the first open call can poll open_status without
        # triggering a second spawn. The task runs to completion regardless.
        # The stored path guards against a same-name-different-path collision.
        self._pending_opens: dict[str, tuple[asyncio.Task[str], str]] = {}
        # v0.17 C1-3: most-recently-used public name. Every successful
        # open bumps this; a close of the current MRU rotates to any
        # remaining session (or clears when the last one goes). The
        # tools.py wrapper reads this to auto-fill `name=` on
        # session-scoped actions when the caller didn't supply one,
        # and injects a warning so silent MRU steering never confuses
        # the caller about which session actually served the request.
        self._mru_session: str | None = None
        # v0.17 C1-4: cold-start manifest — names we heard about
        # from ``~/.suspex0/ida_sessions.json`` before the shim was
        # up. Each entry is {input_path, idb_target, last_opened_iso,
        # run_auto_analysis}. On the first session-scoped call whose
        # name isn't in ``_sessions`` but IS here we lazily re-open
        # the DB instead of raising unknown-name. Populated by
        # :meth:`restore_from_manifest`; drained as sessions lazy-open
        # and merged again by :meth:`_save_manifest` on every open /
        # close so a same-name reopen after a crash still works.
        self._manifest_sessions: dict[str, dict[str, Any]] = {}
        self._manifest_path: Path = _default_manifest_path()
        # Dispatcher owns stdout.readline() so N concurrent `_call`s never
        # race on the reader; rid -> Future for the awaited response.
        self._pending_responses: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._dispatcher_task: asyncio.Task[None] | None = None
        # v0.24: public name -> time.monotonic() when its open was
        # dispatched, so open_status can report open_elapsed_s and flag a
        # PDB apply that has been "loading" far past a sane budget.
        self._open_started_at: dict[str, float] = {}
