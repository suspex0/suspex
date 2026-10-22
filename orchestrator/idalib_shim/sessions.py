"""Session registry + backend lifecycle: spawn, adopt, probe, reap, list,
close.  Every open IDA backend the shim knows about lives in ``SESSIONS``
here.

Mechanical split-out from ``idalib_stdio_shim.py``; no behavior changes.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession
from mcp.client.sse import sse_client

from .backend import (
    POLL_INTERVAL_S,
    READY_TIMEOUT_S,
    _backend_cmd,
    _free_port,
    _prevalidate_pe,
)
from .logging import _log, _tail_log


# session_id -> state dict; path key -> session_id; alias name -> session_id
SESSIONS: dict[str, dict] = {}
BY_PATH: dict[str, str] = {}
ALIASES: dict[str, str] = {}
STACKS: list[AsyncExitStack] = []  # deliberately leaked until process exit
LOCKS: dict[str, asyncio.Lock] = {}


REG_LOCK = asyncio.Lock()


def _sess_payload(sid: str) -> dict:
    st = SESSIONS[sid]
    return {
        "success": True,
        "session": {
            "session_id": sid,
            "input_path": st["path"],
            "filename": Path(st["path"]).name,
            "port": st["port"],
        },
        "message": f"Binary opened: {Path(st['path']).name} ({sid})",
    }


def _resolve(database: str | None) -> tuple[str, ClientSession]:
    sid = database or ""
    sid = ALIASES.get(sid, sid)
    if sid not in SESSIONS and len(SESSIONS) == 1:
        sid = next(iter(SESSIONS))
    st = SESSIONS.get(sid)
    if st is None:
        known = ", ".join(SESSIONS) or "none"
        raise RuntimeError(f"unknown idalib session {database!r}; known: {known}")
    return sid, st["session"]


def _kill(st: dict) -> None:
    proc = st.get("proc")
    if proc is not None and proc.returncode is None:
        try:
            # /T kills the whole launcher tree (idalib-mcp.exe -> venv
            # redirector -> real python); os.kill would orphan children.
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
        except Exception:  # noqa: BLE001 - best-effort teardown
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except OSError:
                pass


async def _probe_alive(st: dict) -> bool:
    """Cheap round-trip check that a backend is still answering.

    Wraps `sess.list_tools()` in a short timeout so a hung/crashed
    backend does not wedge callers. Any failure -> treat as dead so
    the caller can reap and respawn. Kept intentionally paranoid:
    if the child died the SSE stream is usually already broken and
    list_tools raises immediately anyway.

    Takes the session's `st['lock']` so a probe can't race a live
    tool call on the same ClientSession -- the rest of the shim
    treats each session as single-writer under that lock.
    """
    sess = st["session"]
    try:
        async with st["lock"]:
            await asyncio.wait_for(sess.list_tools(), timeout=3.0)
    except Exception:  # noqa: BLE001 - any failure means "not alive"
        return False
    return True


async def _reap_dead(sid: str, st: dict) -> None:
    """Tear down a session's backend + log/pump. Caller has already
    removed sid from SESSIONS/BY_PATH/ALIASES under REG_LOCK.

    Awaits the pump task briefly before closing its log fh so a
    still-iterating `async for chunk in proc.stdout` never writes
    to a closed file (its broad except swallows the ValueError but
    the last log line is torn and the task is GC'd as 'Task was
    destroyed but it is pending!').
    """
    _kill(st)
    pm = st.get("pump")
    if pm is not None:
        try:
            await asyncio.wait_for(asyncio.shield(pm), timeout=3)
        except Exception:  # noqa: BLE001 - teardown races the pump
            pass
        pm.cancel()
    lf = st.get("log_fh")
    if lf is not None:
        try:
            lf.close()
        except Exception:  # noqa: BLE001
            pass


async def _open(input_path: str, run_auto_analysis: bool = True,
                preferred_session_id: str = "", mode: str = "", **_kw) -> str:
    resolved = str(Path(input_path).resolve())
    key = resolved.lower()
    # Pre-validate before any spawn: catches the nvlddmkm-style duplicate
    # `.text` case with an actionable error instead of an rc=1 crash.
    _prevalidate_pe(resolved)
    # In-flight spawn guard keyed by path: BY_PATH[key] isn't populated
    # until the backend finishes initializing (up to READY_TIMEOUT_S=230s),
    # so the later BY_PATH re-check only catches races against ALREADY-
    # finished spawns. Without this guard two concurrent opens for the
    # same path would both take the fresh-spawn branch, leaking one full
    # idalib backend. Different paths still spawn in parallel.
    async with REG_LOCK:
        spawn_lock = LOCKS.setdefault(key, asyncio.Lock())
    async with spawn_lock:
        return await _open_locked(resolved, key, run_auto_analysis,
                                  preferred_session_id)


async def _open_locked(resolved: str, key: str, run_auto_analysis: bool,
                       preferred_session_id: str) -> str:
    # Imported lazily to break the sessions <-> listing cycle at import
    # time; listing.py's module-level state already imports from us.
    from .listing import _maybe_populate_schemas

    # Adoption path: if we already have a session for this path, verify the
    # backend is still answering BEFORE handing it back. A stale entry
    # (backend crashed / port closed / SSE torn down out-of-band) would
    # otherwise poison every subsequent call on that sid. Probe outside
    # REG_LOCK so a hung backend cannot wedge concurrent opens.
    existing_sid: str | None = None
    existing_st: dict | None = None
    async with REG_LOCK:
        if key in BY_PATH:
            existing_sid = BY_PATH[key]
            existing_st = SESSIONS.get(existing_sid)
            if preferred_session_id and existing_st is not None:
                ALIASES[preferred_session_id] = existing_sid
    if existing_sid is not None and existing_st is not None:
        if await _probe_alive(existing_st):
            return json.dumps(_sess_payload(existing_sid))
        _log(f"shim: reaping stale backend sid={existing_sid} for {resolved}")
        async with REG_LOCK:
            # Only unregister if the mapping still points at THIS st;
            # a racing re-open may have already swapped in a fresh one.
            if SESSIONS.get(existing_sid) is existing_st:
                SESSIONS.pop(existing_sid, None)
                if BY_PATH.get(key) == existing_sid:
                    BY_PATH.pop(key, None)
                for k in [k for k, v in ALIASES.items() if v == existing_sid]:
                    ALIASES.pop(k, None)
                reap_this = True
            else:
                reap_this = False
        if reap_this:
            await _reap_dead(existing_sid, existing_st)
        # Fall through to the fresh-spawn path below.
    async with REG_LOCK:
        # Re-check: another caller may have raced ahead and (re-)populated
        # the mapping while we were probing/reaping.
        if key in BY_PATH:
            sid = BY_PATH[key]
            if preferred_session_id:
                ALIASES[preferred_session_id] = sid
            return json.dumps(_sess_payload(sid))
        sid = preferred_session_id or f"sess_{uuid.uuid4().hex[:8]}"
        ALIASES[sid] = sid

    port = _free_port()
    cmd = _backend_cmd(resolved, port)
    log_path = Path(tempfile.gettempdir()) / f"suspex_idalib_{sid}.log"
    log_fh = open(log_path, "ab")
    # `run_auto_analysis=False` -> env gate honored by our extension entry.
    # The vanilla idalib_server hardcodes autoanalysis on; on a 100 MB
    # driver that's 20-40 min per open.
    child_env = dict(os.environ)
    if not run_auto_analysis:
        child_env["SUSPX_IDA_NO_AUTO"] = "1"
    # stdin=DEVNULL: severs any inherited orchestrator/bridge pipe stdin
    # that would otherwise dangle on the backend. stdout=PIPE + stderr=STDOUT
    # feed the async pump task -> log file. Launcher chain bypassed by using
    # `python -m ida_pro_mcp.idalib_server` (one layer only).
    creationflags = 0
    if sys.platform == "win32":
        # New process group => backend does not share the shim's console
        # control handling; also avoids stdio-ancestry surprises when the
        # orchestrator itself was spawned as a stdio child of a bridge.
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        creationflags=creationflags, env=child_env,
    )

    async def _pump() -> None:
        try:
            assert proc.stdout is not None
            async for chunk in proc.stdout:
                log_fh.write(chunk)
                log_fh.flush()
        except Exception:  # noqa: BLE001 - backend teardown races the pump
            pass

    pump = asyncio.create_task(_pump())
    _log(f"shim: spawned backend pid={proc.pid} port={port} for {resolved}")

    # Cheap TCP-connect probe first; only enter the SSE context ONCE the
    # port is up. httpx-sse's aconnect_sse cleanup path raises GeneratorExit
    # on cancellation and crashes the task group -> the shim would die and
    # the bridge would report "supervisor exited before responding". By
    # avoiding aclose() on a live SSE stream in the retry loop we sidestep
    # that entirely.
    deadline = time.monotonic() + READY_TIMEOUT_S
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            break
        try:
            _tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _tcp.settimeout(1.0)
            _tcp.connect(("127.0.0.1", port))
            _tcp.close()
        except OSError as exc:
            last_err = exc
            await asyncio.sleep(POLL_INTERVAL_S)
            continue
        break
    else:
        _kill({"proc": proc})
        try:
            await asyncio.wait_for(asyncio.shield(pump), timeout=3)
        except Exception:  # noqa: BLE001
            pass
        pump.cancel()
        log_fh.close()
        raise RuntimeError(
            f"idb_open: backend TCP port {port} never opened in "
            f"{READY_TIMEOUT_S}s: {last_err}. "
            + _tail_log(log_path))

    if proc.returncode is None:
        # Now build the SSE context ONCE; shield initialize from external
        # cancellation so a caller giving up doesn't tear the SSE stream
        # apart mid-flight (that's the GeneratorExit crash).
        stack = AsyncExitStack()
        try:
            r, w = await stack.enter_async_context(
                sse_client(f"http://127.0.0.1:{port}/sse"))
            sess = await stack.enter_async_context(ClientSession(r, w))
            await asyncio.wait_for(asyncio.shield(sess.initialize()),
                                   timeout=60)
        except Exception as exc:  # noqa: BLE001
            # Best-effort teardown; swallow aclose errors so they cannot
            # bubble up and crash the shim.
            try:
                await asyncio.wait_for(asyncio.shield(stack.aclose()), timeout=2)
            except Exception:  # noqa: BLE001
                pass
            _kill({"proc": proc})
            try:
                await asyncio.wait_for(asyncio.shield(pump), timeout=3)
            except Exception:  # noqa: BLE001
                pass
            pump.cancel()
            log_fh.close()
            raise RuntimeError(
                f"idb_open: SSE initialize failed: {exc}. "
                + _tail_log(log_path)) from exc
        STACKS.append(stack)  # intentionally never closed (process lifetime)
        async with REG_LOCK:
            SESSIONS[sid] = {"session": sess, "proc": proc, "port": port,
                             "path": resolved, "lock": asyncio.Lock(),
                             "log_fh": log_fh, "pump": pump}
            BY_PATH[key] = sid
            ALIASES.setdefault(preferred_session_id or sid, sid)
        # First successful session -> pull real per-tool schemas from the
        # backend so downstream `ida_manage schemas` returns argument shapes.
        await _maybe_populate_schemas(sess)
        return json.dumps(_sess_payload(sid))
    _kill({"proc": proc})
    try:
        await asyncio.wait_for(asyncio.shield(pump), timeout=3)
    except Exception:  # noqa: BLE001
        pass
    pump.cancel()
    log_fh.close()
    if proc.returncode is not None:
        raise RuntimeError(
            f"idb_open: backend exited rc={proc.returncode}: see {log_path.name}. "
            + _tail_log(log_path))
    raise RuntimeError(
        f"idb_open: backend not ready after {READY_TIMEOUT_S}s: {last_err}. "
        + _tail_log(log_path))


async def _list() -> str:
    # Snapshot under the lock, then probe each backend WITHOUT holding it:
    # a stuck backend would otherwise wedge every other shim caller for the
    # probe's timeout window. Dead entries get reaped so the returned list
    # reflects reality — a follow-up idb_open will respawn from scratch.
    async with REG_LOCK:
        snapshot: list[tuple[str, dict]] = [(sid, st) for sid, st in SESSIONS.items()]
    if not snapshot:
        return json.dumps({"sessions": [], "count": 0})
    probes = await asyncio.gather(
        *(_probe_alive(st) for _, st in snapshot),
        return_exceptions=True,
    )
    alive: list[tuple[str, dict]] = []
    dead: list[tuple[str, dict]] = []
    for (sid, st), ok in zip(snapshot, probes):
        if ok is True:
            alive.append((sid, st))
        else:
            dead.append((sid, st))
    if dead:
        reaped: list[tuple[str, dict]] = []
        async with REG_LOCK:
            for sid, st in dead:
                # Skip anything a racing re-open replaced with a fresh st.
                if SESSIONS.get(sid) is not st:
                    continue
                SESSIONS.pop(sid, None)
                for k in [k for k, v in BY_PATH.items() if v == sid]:
                    BY_PATH.pop(k, None)
                for k in [k for k, v in ALIASES.items() if v == sid]:
                    ALIASES.pop(k, None)
                reaped.append((sid, st))
        for sid, st in reaped:
            _log(f"shim: reaped stale backend sid={sid} in idb_list")
            await _reap_dead(sid, st)
    # Include a liveness marker so `idb_list` callers can distinguish
    # "session tracked" from "session tracked AND probed alive right
    # now". `port` + `backend_pid` help operators correlate with the OS
    # process view.
    sessions = [
        {"session_id": sid, "input_path": st["path"],
         "filename": Path(st["path"]).name,
         "backend_alive": True,
         "port": st.get("port"),
         "backend_pid": st["proc"].pid if st.get("proc") is not None else None}
        for sid, st in alive
    ]
    reaped_names = [sid for sid, _ in dead if SESSIONS.get(sid) is None]
    return json.dumps({"sessions": sessions, "count": len(sessions),
                       "reaped_dead": reaped_names})


async def _close(database: str = "", name: str = "", save: bool = True,
                 **_kw) -> str:
    # `database` is the shim's canonical key; `name` is what the bridge's
    # ida_manage action=close resolves via friendly-name. Accept both so a
    # caller who reaches us via either surface never gets "unknown session ''".
    key = database or name
    async with REG_LOCK:
        sid = ALIASES.get(key, key)
        if sid not in SESSIONS and len(SESSIONS) == 1:
            sid = next(iter(SESSIONS))
        st = SESSIONS.pop(sid, None)
        for k in [k for k, v in BY_PATH.items() if v == sid]:
            BY_PATH.pop(k, None)
        for k in [k for k, v in ALIASES.items() if v == sid]:
            ALIASES.pop(k, None)
    if st is None:
        known = ", ".join(SESSIONS) or "none"
        raise RuntimeError(
            f"idb_close: unknown session {key!r}; known sessions: {known}. "
            "Pass 'database' (shim canonical) or 'name' (friendly alias).")
    # Use the shared teardown so the pump task is awaited before its log
    # fh is closed -- otherwise a mid-iteration `async for chunk in
    # proc.stdout` writes to a closed fh (its except swallows it, but
    # the last log line is torn and the task can be GC'd as
    # 'Task was destroyed but it is pending!').
    await _reap_dead(sid, st)
    return json.dumps({"success": True, "closed": sid})


def _cleanup() -> None:
    for st in list(SESSIONS.values()):
        _kill(st)
