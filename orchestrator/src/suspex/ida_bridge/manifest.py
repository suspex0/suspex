"""Manifest mixin: persist / restore the cross-restart session ledger."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from .config import IDA_MANIFEST_VERSION
from .helpers import _valid_session_name

log = logging.getLogger(__name__)


class IdaManifestMixin:
    """v0.17 C1-4: cross-restart session continuity."""

    # ------------------------------------------------------------ manifest ----

    def restore_from_manifest(self) -> int:
        """Load names + input paths from the persistent manifest.

        Called once at bridge construction (or on demand from a test).
        Populates ``self._manifest_sessions`` without spawning the shim
        — actual re-open is lazy (see :meth:`_maybe_lazy_reopen`) so a
        cold start doesn't pay the auto-analysis cost until the caller
        actually needs a session.

        Returns the number of names loaded. Corruption / missing file
        both silently return 0; a mangled manifest never blocks
        startup.
        """
        path = self._manifest_path
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return 0
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            log.warning(
                "ida_bridge: ida_sessions manifest at %s unreadable "
                "(%s); starting fresh", path, exc,
            )
            return 0
        if not isinstance(data, dict):
            return 0
        if data.get("version") != IDA_MANIFEST_VERSION:
            log.info(
                "ida_bridge: manifest version %r != expected %d; "
                "ignoring", data.get("version"), IDA_MANIFEST_VERSION,
            )
            return 0
        entries = data.get("sessions")
        if not isinstance(entries, dict):
            return 0
        loaded = 0
        for name, info in entries.items():
            if (not isinstance(name, str)
                    or not _valid_session_name(name)
                    or not isinstance(info, dict)):
                continue
            input_path = info.get("input_path")
            if not isinstance(input_path, str) or not input_path:
                continue
            self._manifest_sessions[name] = {
                "input_path": input_path,
                "idb_target": (info.get("idb_target")
                               or f"{input_path}.i64"),
                "last_opened_iso": info.get("last_opened_iso", ""),
                "run_auto_analysis": bool(
                    info.get("run_auto_analysis", True)),
            }
            loaded += 1
        return loaded

    def _save_manifest(self) -> None:
        """Snapshot every live session's input path to the manifest.

        Called at the end of every successful open and every real
        close. Writes tmp+rename so a concurrent read never sees a
        half-written file. Any I/O failure is logged and swallowed —
        the manifest is a convenience surface for the NEXT process,
        not the current one, so a broken disk shouldn't fail an
        otherwise-successful open.
        """
        path = self._manifest_path
        payload: dict[str, Any] = {
            "version": IDA_MANIFEST_VERSION, "sessions": {}}
        now_iso = datetime.now(timezone.utc).isoformat()
        # Live sessions first — they win over stale manifest entries
        # so a same-name reopen after a crash records the new path.
        for name, _sid in self._sessions.items():
            info = self._session_paths.get(name)
            if not info:
                # Session adopted from a persistent worker without a
                # recorded input path — skip; we can't lazy-reopen it
                # anyway.
                continue
            payload["sessions"][name] = {
                "input_path": info,
                "idb_target": f"{info}.i64",
                "last_opened_iso": now_iso,
                "run_auto_analysis": True,
            }
        # Keep manifest entries whose sessions aren't live yet — the
        # lazy-open flow needs them until a session actually opens.
        for name, info in self._manifest_sessions.items():
            payload["sessions"].setdefault(name, dict(info))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            log.warning(
                "ida_bridge: manifest save to %s failed (%s); "
                "restart continuity may be degraded", path, exc,
            )
