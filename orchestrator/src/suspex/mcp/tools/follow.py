"""File-follow / watchdog auto-kick helpers used by ``file_manage``.

Split out of the original ``tools.py`` module. All state still lives on
the ``Context`` object (``ctx._follows``, ``ctx._auto_kicks``, ...) so
the shared behavior is unchanged.
"""

from __future__ import annotations

from .common import _emit, _j, log
from .context import Context

import asyncio
import time as _time
from collections import deque
from typing import Any



# ------------------------------------------------------------------- follow --
# v0.11 log follow helpers used by file_manage(follow_*). The orchestrator
# side keeps one asyncio task per active follow_id draining the LogFollow
# stream into a bounded ring. The MCP client polls the ring.
#
# Chunk shape stored in the ring:
#   {"seq": int, "offset": int, "data": str, "rotated": bool,
#    "new_total_size": int, "eof": bool, "reason": str, "ts": float}


def _follow_key(ctx: Context) -> str:
    ctx._follow_next += 1
    return f"f{ctx._follow_next:06d}"


async def _follow_start(ctx: Context, c, remote_path: str, *,
                        from_offset: int, initial_tail_bytes: int,
                        poll_interval_ms: int, max_chunk_bytes: int,
                        line_align: bool, follow_rotation: bool,
                        duration_s: int, max_bytes: int,
                        ring_cap: int) -> dict[str, Any]:
    if not remote_path:
        return {"ok": False, "kind": "bad_arg",
                "error": "follow_start: remote_path/path arrived empty — "
                         "if you sent one, the param was stripped in transit",
                "received_args": {"remote_path": remote_path},
                "hint": ("e.g. remote_path=r'C:\\suspex\\exec_trace.log' — "
                         "any file the agent can read")}
    if not hasattr(c.files, "LogFollow"):
        return {"ok": False,
                "error": "file_manage follow_start: agent < v8 (LogFollow RPC missing)",
                "hint": ("fall back to file_manage(action='tail') for point-in-time "
                         "reads until the target's agent is rebuilt")}
    from collections import deque
    import time as _time

    # -1 → start at EOF (UINT64_MAX in the proto)
    fo = (1 << 64) - 1 if int(from_offset) < 0 else int(from_offset)

    fid = _follow_key(ctx)
    ring: deque = deque(maxlen=max(int(ring_cap), 16))
    state: dict[str, Any] = {
        "path": remote_path,
        "buffer": ring,
        "seq": 0,
        "started_ts": _time.time(),
        "last_poll_ts": 0.0,
        "eof": False,
        "reason": "",
        "task": None,
    }

    async def pump():
        try:
            async for chunk in c.log_follow_iter(
                remote_path,
                from_offset=fo,
                initial_tail_bytes=int(initial_tail_bytes),
                poll_interval_ms=int(poll_interval_ms),
                max_chunk_bytes=int(max_chunk_bytes),
                line_align=bool(line_align),
                follow_rotation=bool(follow_rotation),
                duration_s=int(duration_s),
                max_bytes=int(max_bytes),
            ):
                state["seq"] += 1
                entry: dict[str, Any] = {
                    "seq": state["seq"],
                    "offset": int(chunk.offset),
                    "rotated": bool(chunk.rotated),
                    "new_total_size": int(chunk.new_total_size),
                    "eof": bool(chunk.eof),
                    "reason": str(chunk.reason or ""),
                    "ts": _time.time(),
                    # v14: metadata-only chunk from a share-locked or
                    # not-yet-created file — the follow upgrades to content
                    # chunks the moment the agent's open succeeds.
                    "stat_only": bool(getattr(chunk, "stat_only", False)),
                }
                if chunk.data:
                    entry["data"] = bytes(chunk.data).decode("utf-8", "replace")
                    entry["bytes"] = len(chunk.data)
                else:
                    entry["data"] = ""
                    entry["bytes"] = 0
                ring.append(entry)
                if chunk.eof:
                    state["eof"] = True
                    state["reason"] = entry["reason"]
                    break
        except asyncio.CancelledError:
            state["eof"] = True
            state["reason"] = state["reason"] or "cancelled"
            raise
        except Exception as exc:
            state["eof"] = True
            state["reason"] = f"stream_error: {type(exc).__name__}: {exc}"

    task = asyncio.create_task(pump(), name=f"log_follow_{fid}")
    state["task"] = task
    ctx._follows[fid] = state

    # If the agent predates v8 the iterator returns immediately without
    # yielding — surface a clean fallback hint.
    await asyncio.sleep(0)
    if state["seq"] == 0 and state["eof"] and state["reason"].startswith("stream_error"):
        # error surfaced synchronously
        return {"ok": False, "follow_id": fid, "error": state["reason"],
                "hint": "agent < v8: LogFollow RPC unavailable — fall back to file_manage(tail)"}

    return {"ok": True, "follow_id": fid, "path": remote_path,
            "started_ts": state["started_ts"], "ring_cap": ring.maxlen,
            "hint": ("poll with file_manage(action='follow_poll', follow_id='"
                     + fid + "'); stop with follow_stop")}


def _follow_poll(ctx: Context, follow_id: str, *, from_seq: int = 0) -> dict[str, Any]:
    if not follow_id:
        return {"ok": False, "error": "follow_poll: follow_id is required"}
    state = ctx._follows.get(follow_id)
    if state is None:
        return {"ok": False, "error": f"follow_poll: unknown follow_id {follow_id!r}",
                "hint": "list active follows with file_manage(action='follow_list')"}
    import time as _time
    state["last_poll_ts"] = _time.time()
    ring = state["buffer"]
    ring_cap = ring.maxlen or 0
    out = [e for e in list(ring) if e["seq"] > int(from_seq)]
    # Bytes dropped from the front: if seq exceeds cap the caller lost the
    # first `seq - cap` chunks before their poll caught up. Surface that so
    # the caller can decide whether to grow ring_cap or poll faster.
    dropped = max(0, state["seq"] - ring_cap) if ring_cap else 0
    return {"ok": True, "follow_id": follow_id, "path": state["path"],
            "seq": state["seq"], "eof": state["eof"], "reason": state["reason"],
            "chunks": out, "dropped_prefix": dropped}


async def _follow_stop(ctx: Context, follow_id: str) -> dict[str, Any]:
    if not follow_id:
        return {"ok": False, "error": "follow_stop: follow_id is required"}
    state = ctx._follows.get(follow_id)
    if state is None:
        return {"ok": False, "error": f"follow_stop: unknown follow_id {follow_id!r}"}
    task = state["task"]
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    final = {"ok": True, "follow_id": follow_id, "path": state["path"],
             "final_seq": state["seq"], "eof": state["eof"],
             "reason": state["reason"] or "cancelled"}
    ctx._follows.pop(follow_id, None)
    return final


def _follow_list(ctx: Context) -> dict[str, Any]:
    import time as _time
    now = _time.time()
    rows = []
    for fid, s in ctx._follows.items():
        rows.append({
            "follow_id": fid,
            "path": s["path"],
            "seq": s["seq"],
            "buffered_chunks": len(s["buffer"]),
            "eof": s["eof"],
            "reason": s["reason"],
            "age_s": round(now - s["started_ts"], 1),
            "since_last_poll_s": round(now - s["last_poll_ts"], 1)
                                 if s["last_poll_ts"] else None,
        })
    return {"ok": True, "count": len(rows), "follows": rows}


# ---------------------------------------------------------- watchdog auto-kick --
# One background task per (view_name, watchdog_id) that arms once and kicks
# every interval_ms until stopped. The kicker records the last result / error
# on its own state row so auto_status can render it without waking the task.
#
# The recommended cadence is deadline_ms = 4x interval_ms — three misses
# fire. The tool defaults (deadline=45s / interval=10s) match that ratio.


def _auto_key(view_name: str, wid: int) -> str:
    return f"{view_name}:{wid}"


async def _auto_kick_start(ctx: Context, c, view_name: str, wid: int,
                            deadline_ms: int, interval_ms: int,
                            bugcheck_code: int, cookie: int, label: str,
                            replace: bool) -> dict[str, Any]:
    import time as _time
    if interval_ms < 100:
        return {"ok": False,
                "error": "watchdog auto_kick: interval_ms must be >= 100",
                "hint": "the network round-trip alone is ~10 ms; sub-100 ms "
                        "just amplifies gRPC load without adding safety"}
    if deadline_ms < interval_ms * 2:
        return {"ok": False,
                "error": ("watchdog auto_kick: deadline_ms must be >= 2 * "
                          "interval_ms — otherwise a single kick miss fires"),
                "hint": ("recommended: deadline_ms=4*interval_ms, e.g. "
                         "interval_ms=10000 + deadline_ms=45000")}

    key = _auto_key(view_name, wid)
    existing = ctx._auto_kicks.get(key)
    if existing and existing.get("task") and not existing["task"].done():
        return {"ok": False, "error": f"watchdog auto_kick: {key} already running",
                "hint": "stop the existing kicker first with auto_stop"}

    # Arm first (may fail if driver absent / agent < v8). If Arm fails don't
    # bother spawning the kicker.
    flags = 1 if (replace or existing is not None) else 0
    arm = await c.watchdog_arm(wid, deadline_ms, bugcheck_code=bugcheck_code,
                                flags=flags, cookie=cookie, label=label)
    if not arm.get("ok"):
        return {"ok": False, "action": "arm", "error": arm.get("error"),
                "hint": arm.get("hint", "")}

    state: dict[str, Any] = {
        "id": wid, "deadline_ms": deadline_ms, "interval_ms": interval_ms,
        "started_ts": _time.time(), "kicks": 0, "last_kick_ts": 0.0,
        "last_result": arm, "last_error": "",
        "task": None,
    }

    async def pump():
        try:
            while True:
                await asyncio.sleep(interval_ms / 1000.0)
                try:
                    r = await c.watchdog_kick(wid, deadline_ms=deadline_ms,
                                              cookie=cookie or 0)
                except Exception as exc:  # noqa: BLE001 - transient RPC surface
                    state["last_error"] = f"{type(exc).__name__}: {exc}"
                    # keep looping — a transient RPC error shouldn't stop us
                    continue
                state["last_result"] = r
                if r.get("ok"):
                    state["kicks"] += 1
                    state["last_kick_ts"] = _time.time()
                    state["last_error"] = ""
                else:
                    state["last_error"] = r.get("error", "")
                    # If the watchdog was disarmed out from under us
                    # (STATUS_NOT_FOUND), stop pumping — no point kicking
                    # an id that no longer exists. v0.17 E-1a: mark
                    # stopped so _auto_kick_status can reap the entry
                    # instead of leaking a zombie kicker. We don't pop
                    # here — popping ctx._auto_kicks while another
                    # coroutine may be iterating it (status, list) is a
                    # race. The reaper in _auto_kick_status removes
                    # stopped entries older than 60 s, and both
                    # auto_stop and disarm still explicitly pop.
                    if "NOT_FOUND" in str(r.get("error", "")).upper():
                        state["stopped"] = True
                        state["stopped_reason"] = "watchdog_not_found"
                        state["stopped_ts"] = _time.time()
                        break
        except asyncio.CancelledError:
            raise

    task = asyncio.create_task(pump(), name=f"watchdog_kick_{key}")
    state["task"] = task
    ctx._auto_kicks[key] = state
    return {"ok": True, "id": wid, "view": view_name,
            "deadline_ms": deadline_ms, "interval_ms": interval_ms,
            "hint": (f"kicking every {interval_ms} ms; three-miss window is "
                     f"{deadline_ms} ms — a wedge that outlasts that fires "
                     "MANUALLY_INITIATED_CRASH")}


async def _auto_kick_stop(ctx: Context, c, view_name: str, wid: int) -> dict[str, Any]:
    key = _auto_key(view_name, wid)
    state = ctx._auto_kicks.pop(key, None)
    if state is None:
        return {"ok": False, "error": f"watchdog auto_stop: no kicker for {key}"}
    task = state.get("task")
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    # Also disarm the slot — auto_stop is the "I'm done, don't crash me"
    # signal, not just "stop kicking."
    disarm = await c.watchdog_disarm(wid)
    return {"ok": True, "id": wid, "view": view_name,
            "kicks": state.get("kicks", 0),
            "disarm": disarm}


def _auto_kick_status(ctx: Context) -> dict[str, Any]:
    import time as _time
    now = _time.time()
    # v0.17 E-1a: reap stopped kickers older than 60 s so `auto_status`
    # doesn't accumulate zombies from NOT_FOUND / disarm-under-us cases.
    stale = [
        k for k, s in ctx._auto_kicks.items()
        if s.get("stopped") and (now - s.get("stopped_ts", now) > 60)
    ]
    for k in stale:
        ctx._auto_kicks.pop(k, None)
    rows = []
    for key, s in ctx._auto_kicks.items():
        task = s.get("task")
        rows.append({
            "key": key,
            "id": s["id"],
            "deadline_ms": s["deadline_ms"],
            "interval_ms": s["interval_ms"],
            "kicks": s["kicks"],
            "since_last_kick_s": round(now - s["last_kick_ts"], 1)
                                  if s["last_kick_ts"] else None,
            "age_s": round(now - s["started_ts"], 1),
            "last_error": s.get("last_error", ""),
            # v0.17 E-1a: expose pump state so callers can distinguish
            # a live kicker from one that stopped and hasn't been
            # reaped yet (e.g. NOT_FOUND before the 60 s grace window).
            "task_alive": (task is not None and not task.done()),
            "stopped": bool(s.get("stopped")),
            "stopped_reason": s.get("stopped_reason", ""),
        })
    return {"ok": True, "count": len(rows), "auto_kickers": rows}
