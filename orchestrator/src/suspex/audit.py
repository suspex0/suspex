"""Rotating JSONL audit sink for tool calls (v0.17 E-2).

The in-memory ring on :class:`suspex.session.Session` caps at 2000 entries
and wipes on orchestrator restart. That's fine for the dashboard's live
view; it is not enough for post-hoc forensics (what tool call did the
LLM issue right before the target wedged, three sessions ago?). This
module ships the disk half: every :meth:`Session.record_tool_call` also
appends to a rotating JSONL sink so a persistent breadcrumb survives a
crash.

Layout::

    ~/.suspex0/audit/<session_id>/YYYY-MM-DD-HHMMSS.jsonl

Rolls on:
    * File size reaches :env:`SUSPX_AUDIT_ROLL_BYTES` (default 16 MiB).
    * The UTC calendar day changes.

Retention:
    * Files older than :env:`SUSPX_AUDIT_RETAIN_DAYS` (default 14 days)
      are removed on :class:`AuditWriter` open — never mid-call, so a
      retention pass can't yank a currently-open file.

Design decisions:
    * Writes are **never** allowed to mask the call being recorded. All
      I/O errors are caught and logged; the tool call proceeds. The
      :func:`AuditWriter.dropped` counter surfaces this on the dashboard.
    * Concurrent orchestrator instances write to distinct session_ids
      (PID-included), so per-process files don't collide.
    * ``session_id`` is opaque to this module. The caller (Session)
      builds one deterministic per orchestrator boot and keeps a single
      :class:`AuditWriter` for its lifetime.

Query surface: :func:`query` reads across every roll file for a
``session_id``, filters by owner/method/time range, and returns the
oldest-first rows up to ``limit``. Used by
``target_manage(action="recent_ops", persistent=True)`` in E-2c.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


_log = logging.getLogger(__name__)


ROLL_BYTES_DEFAULT = 16 * 1024 * 1024
RETAIN_DAYS_DEFAULT = 14

# Environment overrides.
_ENV_ROLL_BYTES = "SUSPX_AUDIT_ROLL_BYTES"
_ENV_RETAIN_DAYS = "SUSPX_AUDIT_RETAIN_DAYS"
_ENV_DISABLE = "SUSPX_AUDIT_DISABLE"


def audit_disabled() -> bool:
    """Test hook + safety valve. Setting ``SUSPX_AUDIT_DISABLE=1`` skips
    disk I/O — used in tests that don't want a ``~/.suspex0/audit/...``
    tree materializing during unit runs."""
    return os.environ.get(_ENV_DISABLE, "").strip() == "1"


def default_base() -> Path:
    """The audit tree root.

    Defaults to ``~/.suspex0/audit`` but honors ``SUSPX_AUDIT_BASE_DIR``
    as a full override so both :class:`AuditWriter` (write path) and
    :func:`query` (read path) resolve to the same tree without needing
    the caller to plumb ``base=`` through. Tests point the env at a
    ``tmp_path`` to keep the real home tree untouched.
    """
    override = os.environ.get("SUSPX_AUDIT_BASE_DIR", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".suspex0" / "audit"


class AuditWriter:
    """Rotating JSONL sink. One instance per Session.

    Not thread-safe by itself — the caller (Session.record_tool_call)
    runs on the asyncio event loop and every ``write`` is dispatched
    synchronously, so serialization is inherited from the loop.
    """

    def __init__(self, session_id: str, *, base: Path | None = None) -> None:
        self.session_id = session_id
        # Base is <root>/<session_id>/ — never the raw root, so multi-
        # orchestrator hosts don't cross-contaminate.
        root = base if base is not None else default_base()
        self.base = Path(root) / session_id
        self._fp = None  # opened lazily
        self._path: Path | None = None
        self._bytes = 0
        self._day: str = ""
        try:
            self._roll_bytes = int(
                os.environ.get(_ENV_ROLL_BYTES) or ROLL_BYTES_DEFAULT)
        except (TypeError, ValueError):
            self._roll_bytes = ROLL_BYTES_DEFAULT
        try:
            self._retain_days = int(
                os.environ.get(_ENV_RETAIN_DAYS) or RETAIN_DAYS_DEFAULT)
        except (TypeError, ValueError):
            self._retain_days = RETAIN_DAYS_DEFAULT
        # Dropped-write counter — dashboards surface this so an operator
        # can spot silent audit-drop conditions.
        self._dropped = 0
        # Create the tree eagerly on non-disabled paths so a first write
        # doesn't race with mkdir. When disabled or the mkdir fails we
        # degrade to "every write drops" instead of raising.
        if not audit_disabled():
            try:
                self.base.mkdir(parents=True, exist_ok=True)
                self._reap_old()
            except OSError as exc:  # noqa: BLE001 — never mask
                _log.warning("audit: base mkdir failed: %s", exc)
                self._dropped += 1

    # ---- public API -------------------------------------------------------

    def write(self, record: dict[str, Any]) -> None:
        """Append one JSON row. Errors are caught + counted; never raised."""
        if audit_disabled():
            return
        try:
            if self._needs_roll():
                self._open_new()
            if self._fp is None:
                self._dropped += 1
                return
            line = json.dumps(record, default=str) + "\n"
            self._fp.write(line)
            self._fp.flush()
            self._bytes += len(line.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - audit must never mask
            self._dropped += 1
            _log.debug("audit: write dropped: %s", exc)

    def close(self) -> None:
        if self._fp:
            try:
                self._fp.close()
            except Exception:  # noqa: BLE001
                pass
            self._fp = None

    @property
    def dropped(self) -> int:
        """Number of writes silently dropped (I/O errors, disk full)."""
        return self._dropped

    @property
    def path(self) -> Path | None:
        """Current active roll file (``None`` before the first write)."""
        return self._path

    # ---- internals --------------------------------------------------------

    def _needs_roll(self) -> bool:
        if self._fp is None:
            return True
        if self._bytes >= self._roll_bytes:
            return True
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return today != self._day

    def _open_new(self) -> None:
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:  # noqa: BLE001
                pass
            self._fp = None
        now = datetime.now(timezone.utc)
        self._day = now.strftime("%Y-%m-%d")
        # Filename holds the roll timestamp so a directory listing sorts
        # oldest-first without extra bookkeeping. Full microseconds +
        # a per-writer counter guarantee uniqueness even when several
        # rolls happen inside the same second (unit tests thrash this).
        stamp = now.strftime("%Y-%m-%d-%H%M%S")
        micro = now.strftime("%f")
        self._roll_seq = getattr(self, "_roll_seq", 0) + 1
        self._path = self.base / f"{stamp}-{micro}-{self._roll_seq:04d}.jsonl"
        try:
            # 'a' preserves any content from an earlier run at this stamp.
            self._fp = open(self._path, "a", encoding="utf-8")
            self._bytes = (self._path.stat().st_size
                            if self._path.exists() else 0)
        except OSError as exc:  # noqa: BLE001
            _log.warning("audit: _open_new failed: %s", exc)
            self._fp = None
            self._bytes = 0

    def _reap_old(self) -> None:
        """Drop files older than ``self._retain_days``. Best-effort."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retain_days)
        if not self.base.exists():
            return
        for p in list(self.base.glob("*.jsonl")):
            try:
                mtime = datetime.fromtimestamp(p.stat().st_mtime,
                                                 tz=timezone.utc)
                if mtime < cutoff:
                    p.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Query surface — read across roll files, filter, page.
# ---------------------------------------------------------------------------


def query(session_id: str, *,
          owner: str | None = None,
          method: str | None = None,
          tool: str | None = None,
          since_iso: str | None = None,
          until_iso: str | None = None,
          limit: int = 500,
          base: Path | None = None) -> list[dict]:
    """Read the audit tree for ``session_id`` and return matching rows.

    Rows are returned oldest-first. ``method`` matches either ``action``
    or ``tool`` (so a plain "recent bp_add calls" filter works). Time
    bounds accept ISO-8601 (with or without ``Z`` suffix).
    """
    root = base if base is not None else default_base()
    dir_ = Path(root) / session_id
    if not dir_.exists():
        return []
    files = sorted(dir_.glob("*.jsonl"))
    since = _parse_iso(since_iso) if since_iso else None
    until = _parse_iso(until_iso) if until_iso else None
    out: list[dict] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as h:
                for line in h:
                    row = _parse_row(line)
                    if row is None:
                        continue
                    if not _match(row, owner=owner, method=method, tool=tool,
                                    since=since, until=until):
                        continue
                    out.append(row)
                    if len(out) >= limit:
                        return out
        except OSError:
            continue
    return out


def _parse_row(line: str) -> dict | None:
    line = line.rstrip("\n\r")
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _match(row: dict, *, owner: str | None, method: str | None,
           tool: str | None, since: datetime | None,
           until: datetime | None) -> bool:
    if owner is not None and row.get("owner") != owner:
        return False
    if method is not None:
        if row.get("action") != method and row.get("tool") != method:
            return False
    if tool is not None and row.get("tool") != tool:
        return False
    ts = row.get("ts")
    if since is not None and isinstance(ts, (int, float)):
        if ts < since.timestamp():
            return False
    if until is not None and isinstance(ts, (int, float)):
        if ts > until.timestamp():
            return False
    return True


def _parse_iso(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


__all__ = [
    "AuditWriter",
    "audit_disabled",
    "default_base",
    "query",
]
