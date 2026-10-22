"""v0.25: periodic pre-crash state capture + watchdog auto-arm.

Two pieces live here:

``SnapshotPump`` — a background task that copies every configured memory
range (``snapshots.ranges``) into ``artifacts/snapshots/<boot_epoch_ms>/``
on an interval while the primary view is connected. "Snapshot on
heartbeat loss" is impossible — a wedged target can't answer reads — so
periodic capture is the only honest shape: when the target BSODs or
wedges, the newest tick is already on disk. A failed read appends an
``{ok:false, error}`` index row instead of killing the pump, so a dead
target produces honest gaps rather than a crash.

``auto_arm_after_load`` — the orchestrator tier of the persistent-
watchdog feature. Called by target_manage after ``driver_load`` succeeds
and after a ``connect`` that reports ``boot_change.kind == "new_boot"``;
re-arms the configured watchdog id and re-attaches the orchestrator-side
kicker so hands-off protection survives driver loads and reboots.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from .caller import current_client_id
from .mcp.tools.follow import _auto_key, _auto_kick_start

log = logging.getLogger(__name__)

# Same cap family as mem reads / file read: keep a single snapshot range
# inside the agent's per-call gRPC message budget.
_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024

_NAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_name(name: str) -> str:
    s = _NAME_SAFE.sub("_", str(name or "").strip())
    return s.strip("._") or "range"


class SnapshotPump:
    """Periodic range capture for one view.

    The loop is self-supervising: every tick it re-reads
    ``session.clients[view]`` so connect/disconnect needs no explicit
    hook — with no client the pump idles. ``session._boot_ids`` supplies
    the ``<boot_epoch_ms>`` directory key; a boot change clears the
    address-resolution cache so ``module+offset`` range specs re-resolve
    against the new boot's module map.
    """

    def __init__(self, ctx, view: str, ranges: list[dict[str, Any]],
                 interval_s: float) -> None:
        self.ctx = ctx
        # Multi-machine: empty view follows ``session.primary`` live each
        # tick — the pump is built at startup before any connect, when the
        # primary key ('<machine>.kernel') doesn't exist yet.
        self.view = view
        self.ranges = [dict(r) for r in (ranges or [])]
        self.interval_s = max(1.0, float(interval_s or 30.0))
        self._task: asyncio.Task | None = None
        # name -> resolved address for the current boot. Cleared whenever
        # the recorded boot epoch changes.
        self._resolved: dict[str, int] = {}
        self._boot_key: str | None = None

    async def start(self) -> None:
        if not self.ranges:
            return
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run(), name=f"snapshot_pump_{self.view}")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    async def _run(self) -> None:
        # Tick immediately on start so the first snapshot lands at
        # connect-time, not one interval later.
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - the pump must not die
                log.warning("snapshot pump tick failed: %r", exc)
            await asyncio.sleep(self.interval_s)

    def _boot_dir(self) -> Path:
        """``artifacts/snapshots/<boot_epoch_ms>/`` — new dir per boot.

        ``_boot_ids`` is populated by ``note_boot_identity`` on the
        status/connect paths; an agent that reports no boot epoch lands
        under ``unknown`` rather than blocking capture.
        """
        ident = self.ctx.session._boot_ids.get(self.view or
                                               self.ctx.session.primary) or {}
        boot = ident.get("boot_epoch_ms") or 0
        key = str(boot) if boot else "unknown"
        if key != self._boot_key:
            self._resolved.clear()
            self._boot_key = key
        return Path(self.ctx.cfg.artifacts_dir()) / "snapshots" / key

    async def _resolve(self, client, spec: dict[str, Any]) -> int:
        """Resolve a range's address once per boot (module+offset honored).

        ``from_va`` + ``space='physical'`` goes VA->PA->physical read so a
        range can pin the backing page of a VA that may move across boots.
        """
        from .mcp.tools.common import _addr_resolve

        name = _safe_name(spec.get("name") or "range")
        if name in self._resolved:
            return self._resolved[name]
        space = str(spec.get("space") or "kernel").lower()
        pid = int(spec.get("pid") or 0)
        kernel = space in ("kernel", "physical")
        raw = spec.get("from_va") if spec.get("from_va") not in (None, "") \
            else spec.get("address")
        va = await _addr_resolve(raw, client, kernel=kernel, pid=pid,
                                 name=f"snapshots.ranges[{name}].address")
        if spec.get("from_va") not in (None, "") and space == "physical":
            tr = await client.mem_va_translate(va, space="kernel", pid=pid)
            if not tr.get("present"):
                raise RuntimeError(
                    f"snapshot range {name!r}: VA {hex(va)} has no valid PTE")
            va = int(tr.get("pa", 0))
        self._resolved[name] = va
        return va

    async def _tick(self) -> None:
        view = self.view or self.ctx.session.primary
        client = self.ctx.session.clients.get(view)
        if client is None:
            return
        out_dir = self._boot_dir()
        index_path = out_dir / "index.jsonl"
        wrote_dir = False
        for spec in self.ranges:
            name = _safe_name(spec.get("name") or "range")
            space = str(spec.get("space") or "kernel").lower()
            pid = int(spec.get("pid") or 0)
            size = min(int(spec.get("size") or 0), _MAX_SNAPSHOT_BYTES)
            row: dict[str, Any] = {
                "ts": time.time(), "name": name, "space": space,
                "size": size,
            }
            try:
                if size <= 0:
                    raise ValueError("size must be > 0")
                va = await self._resolve(client, spec)
                row["va"] = hex(va)
                data = await client.mem_read(pid, va, size, space,
                                             allow_fault=False)
                if isinstance(data, tuple):  # want_meta clients
                    data = data[0]
                data = bytes(data or b"")
                out_dir.mkdir(parents=True, exist_ok=True)
                wrote_dir = True
                (out_dir / f"{name}.bin").write_bytes(data)
                row.update({"ok": True, "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - honest gap, not a dead pump
                row.update({"ok": False,
                            "error": f"{type(exc).__name__}: {exc}"})
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
                with index_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, default=str) + "\n")
            except OSError as exc:
                log.warning("snapshot index append failed: %r", exc)


# --------------------------------------------------------------------------
# watchdog.auto_arm — re-arm + re-attach kicker after driver_load / new boot
# --------------------------------------------------------------------------


async def auto_arm_after_load(ctx, client, view: str) -> dict[str, Any] | None:
    """Re-arm the configured ``watchdog.auto_arm`` id and attach the
    orchestrator kicker.

    Returns the ``_auto_kick_start`` result dict when an arm happened,
    ``None`` when unconfigured / driver absent / already armed / a kicker
    is already pumping (idempotent across reconnects), and a
    ``{ok:True, warning}`` dict when the id collides with a foreign
    owner — a collision is a warning, never an error.
    """
    wdg = getattr(ctx.cfg, "watchdog", None)
    spec = (getattr(wdg, "auto_arm", None) or {}) if wdg is not None else {}
    if not spec:
        return None
    try:
        wid = int(spec.get("id") or 0)
    except (TypeError, ValueError):
        return None
    if wid <= 0:
        return None

    # A live local kicker for this id already means "armed and kicked" —
    # reconnect paths call us repeatedly, so skip without re-arming.
    key = _auto_key(view, wid)
    st_local = ctx._auto_kicks.get(key)
    if st_local is not None and not st_local.get("stopped"):
        task = st_local.get("task")
        if task is not None and not task.done():
            return None

    # Only arm when the driver reports loaded — an absent driver makes
    # the arm IOCTL fail anyway; skip quietly so the connect path stays
    # clean for driver-less workflows. The state set matches
    # target.py's driver_present computation; an agent too old to
    # report driver_state falls through and lets the arm attempt
    # decide (its failure envelope is still nonfatal).
    try:
        status = await client.status()
    except Exception:
        return None
    ds = str(status.get("driver_state") or "").upper()
    if ds and ds not in ("DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED",
                         "SERVICE", "MANUAL_MAPPED"):
        return None

    # Driver-side idempotence: the id already armed means some previous
    # lifetime (or peer) set it — don't reset its deadline.
    try:
        listing = await client.watchdog_list()
    except Exception:
        listing = {}
    rows = (listing.get("entries", []) if isinstance(listing, dict)
            else (listing or []))
    for r in rows:
        try:
            if int(r.get("id", 0) or 0) == wid:
                return None
        except (TypeError, ValueError):
            continue

    # A foreign-owned id is a warning, not an error — the caller should
    # surface it but the connect/load flow must not fail over it.
    if ctx.ownership is not None:
        try:
            foreign = await ctx.ownership.is_foreign_or_none(
                f"watchdog:{view}", str(wid), current_client_id())
        except Exception:  # noqa: BLE001 - registry is best-effort
            foreign = None
        if foreign is True:
            try:
                owner = await ctx.ownership.owner_of(f"watchdog:{view}", str(wid))
            except Exception:  # noqa: BLE001
                owner = None
            return {"ok": True, "skipped": "foreign_owned", "id": wid,
                    "view": view, "owner": owner,
                    "warning": (f"watchdog.auto_arm: id={wid} on view "
                                f"{view!r} is owned by peer {owner!r} — "
                                "auto-arm skipped (foreign collision)")}

    res = await _auto_kick_start(
        ctx, client, view, wid,
        int(spec.get("deadline_ms") or 45000),
        int(spec.get("interval_ms") or 10000),
        int(spec.get("bugcheck_code") or 0),
        int(spec.get("cookie") or 0),
        str(spec.get("label") or "auto_arm"),
        False)
    if not res.get("ok") and "collision" in str(res.get("error", "")).lower():
        # The arm raced a foreign registration between list and arm —
        # surface it as a warning so callers don't treat it as a failure.
        return {"ok": True, "skipped": "watchdog_collision", "id": wid,
                "view": view,
                "warning": (f"watchdog.auto_arm: {res.get('error')} — "
                            "a peer already holds the slot")}
    return res
