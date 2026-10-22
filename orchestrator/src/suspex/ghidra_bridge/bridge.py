"""Concrete :class:`GhidraBridge` — composes every mixin and holds the state."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .config import GhidraConfigLite, _default_manifest_path
from .lifecycle import GhidraLifecycleMixin
from .manifest import GhidraManifestMixin
from .openclose import GhidraOpenCloseMixin
from .sessions import GhidraSessionsMixin
from .tools_schema import GhidraToolsMixin


class GhidraBridge(
    GhidraManifestMixin,
    GhidraSessionsMixin,
    GhidraOpenCloseMixin,
    GhidraToolsMixin,
    GhidraLifecycleMixin,
):
    """One supervisor process, one shared JVM backend, N program sessions."""

    def __init__(self, cfg: GhidraConfigLite, artifacts_dir: Path) -> None:
        self.cfg = cfg
        self.artifacts_dir = artifacts_dir
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._next_id = 1
        self._tools: dict[str, dict[str, Any]] = {}
        # Latches True once the post-backend tools/list refresh has pulled
        # real schemas (the startup inventory runs before any backend
        # exists, so the tool set is thin until then).
        self._tools_live_refreshed = False
        # public name -> shim session id. "Public name" is the string the
        # winning caller passed as preferred_session_id; a peer collision
        # on a different binary gets auto-suffixed with `#<hex>`.
        self._sessions: dict[str, str] = {}
        # public name -> primary-owner client_id; None for adopted
        # sessions (no orchestrator owner -> any caller may close).
        self._sessions_owner: dict[str, str | None] = {}
        # public name -> extra client_ids co-using via share=True.
        self._co_owners: dict[str, set[str]] = {}
        # public name -> absolute binary path (str).
        self._session_paths: dict[str, str] = {}
        # name -> (task, binary_path) for open_async.
        self._pending_opens: dict[str, tuple[asyncio.Task[str], str]] = {}
        # most-recently-used public name (MRU autofill).
        self._mru_session: str | None = None
        # cold-start manifest names -> {input_path, ...} for lazy reopen.
        self._manifest_sessions: dict[str, dict[str, Any]] = {}
        self._manifest_path: Path = _default_manifest_path()
        # Dispatcher owns stdout.readline(); rid -> Future.
        self._pending_responses: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._dispatcher_task: asyncio.Task[None] | None = None
        # public name -> time.monotonic() when its open was dispatched.
        self._open_started_at: dict[str, float] = {}
