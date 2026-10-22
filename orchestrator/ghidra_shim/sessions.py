"""Session registry + shared-backend lifecycle for the ghidra shim.

ONE backend process (JVM + shared Ghidra project) hosts every program.
``SESSIONS`` maps a session id -> ``{program, path, lock}`` where
``program`` is the Ghidra program name inside the project — the
``binary_name`` argument every backend tool takes. ``BACKEND`` holds
the single child-proc / MCP client-session / log-pump handle.

Structural counterpart of ``idalib_shim.sessions``; the per-session
backend spawn is replaced by ``_ensure_backend`` which lazily spawns
(and respawns after crash) the one shared child.
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
    _backend_env,
    _free_port,
)
from .logging import _log, _tail_log


# session_id -> {"program", "path", "lock"}; path key -> session_id;
# alias name -> session_id
SESSIONS: dict[str, dict] = {}
BY_PATH: dict[str, str] = {}
ALIASES: dict[str, str] = {}
STACKS: list[AsyncExitStack] = []  # deliberately leaked until process exit
LOCKS: dict[str, asyncio.Lock] = {}

# The single shared backend: {"proc", "port", "session", "lock",
# "log_fh", "pump"} — the SSE MCP client to suspex_pyghidra_ext.
BACKEND: dict = {}
BACKEND_LOG = Path(tempfile.gettempdir()) / "suspex_pyghidra_backend.log"

REG_LOCK = asyncio.Lock()
SPAWN_LOCK = asyncio.Lock()


def _sess_payload(sid: str) -> dict:
    st = SESSIONS[sid]
    fname = Path(st["path"]).name if st["path"] else st["program"]
    return {
        "success": True,
        "session": {
            "session_id": sid,
            "input_path": st["path"],
            "filename": fname,
            "binary_name": st["program"],
            "port": BACKEND.get("port"),
            "shared_backend": True,
        },
        "message": f"Binary opened in Ghidra project: {st['program']} ({sid})",
    }


def _resolve(database: str | None) -> tuple[str, ClientSession]:
    sid = database or ""
    sid = ALIASES.get(sid, sid)
    if sid not in SESSIONS and len(SESSIONS) == 1:
        sid = next(iter(SESSIONS))
    st = SESSIONS.get(sid)
    if st is None:
        known = ", ".join(SESSIONS) or "none"
        raise RuntimeError(f"unknown ghidra session {database!r}; known: {known}")
    sess = BACKEND.get("session")
    if sess is None:
        raise RuntimeError(
            "ghidra backend not running — re-issue the call or "
            "ghidra_manage(action='open', ...) to respawn it")
    return sid, sess


def _kill_backend_proc() -> None:
    proc = BACKEND.get("proc")
    if proc is not None and proc.returncode is None:
        try:
            # /T kills the whole tree (python -> java); os.kill orphans.
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
        except Exception:  # noqa: BLE001 - best-effort teardown
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except OSError:
                pass


def _kill_proc(proc) -> None:
    """Kill a not-yet-registered child (spawn failure paths)."""
    if proc is not None and proc.returncode is None:
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
        except Exception:  # noqa: BLE001
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except OSError:
                pass


async def _probe_backend_alive() -> bool:
    """Cheap round-trip on the shared backend (list_tools under lock)."""
    sess = BACKEND.get("session")
    if sess is None:
        return False
    try:
        async with BACKEND["lock"]:
            await asyncio.wait_for(sess.list_tools(), timeout=5.0)
    except Exception:  # noqa: BLE001 - any failure means "not alive"
        return False
    return True


async def _teardown_backend() -> None:
    """Tear down the shared backend + log/pump. Drop SESSIONS entries —
    a dead backend can't answer for any program anyway; _adopt on the
    next spawn repopulates from the persisted project."""
    _kill_backend_proc()
    pm = BACKEND.get("pump")
    if pm is not None:
        try:
            await asyncio.wait_for(asyncio.shield(pm), timeout=3)
        except Exception:  # noqa: BLE001 - teardown races the pump
            pass
        pm.cancel()
    lf = BACKEND.get("log_fh")
    if lf is not None:
        try:
            lf.close()
        except Exception:  # noqa: BLE001
            pass
    BACKEND.clear()


async def _ensure_backend() -> ClientSession:
    """Return the shared backend's ClientSession, spawning the child on
    first use / respawning after a crash."""
    if BACKEND.get("session") is not None and await _probe_backend_alive():
        return BACKEND["session"]
    async with SPAWN_LOCK:
        if (BACKEND.get("session") is not None
                and await _probe_backend_alive()):
            return BACKEND["session"]
        await _teardown_backend()

        port = _free_port()
        cmd = _backend_cmd(port)
        log_fh = open(BACKEND_LOG, "ab")
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        _log(f"shim: spawning pyghidra backend: {cmd}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            # stdin=PIPE (held open, never written): the backend's
            # stdin watchdog exits when our write end dies — orphaned
            # JVMs can't hold the project lock past a shim kill.
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            creationflags=creationflags, env=_backend_env(),
        )

        async def _pump() -> None:
            try:
                assert proc.stdout is not None
                async for chunk in proc.stdout:
                    log_fh.write(chunk)
                    log_fh.flush()
            except Exception:  # noqa: BLE001 - teardown races the pump
                pass

        pump = asyncio.create_task(_pump())

        # TCP-readiness probe first; only enter the SSE context ONCE the
        # port is up (same GeneratorExit lesson as the idalib shim).
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
            _kill_proc(proc)
            try:
                await asyncio.wait_for(asyncio.shield(pump), timeout=3)
            except Exception:  # noqa: BLE001
                pass
            pump.cancel()
            log_fh.close()
            raise RuntimeError(
                f"ghidra_open: backend TCP port {port} never opened in "
                f"{READY_TIMEOUT_S}s (JVM+project boot is slow; check "
                f"GHIDRA_INSTALL_DIR/JAVA_HOME/pyghidra): {last_err}. "
                + _tail_log(BACKEND_LOG))

        if proc.returncode is None:
            stack = AsyncExitStack()
            try:
                r, w = await stack.enter_async_context(
                    sse_client(f"http://127.0.0.1:{port}/sse"))
                sess = await stack.enter_async_context(ClientSession(r, w))
                await asyncio.wait_for(asyncio.shield(sess.initialize()),
                                       timeout=60)
            except Exception as exc:  # noqa: BLE001
                try:
                    await asyncio.wait_for(asyncio.shield(stack.aclose()),
                                           timeout=2)
                except Exception:  # noqa: BLE001
                    pass
                _kill_proc(proc)
                try:
                    await asyncio.wait_for(asyncio.shield(pump), timeout=3)
                except Exception:  # noqa: BLE001
                    pass
                pump.cancel()
                log_fh.close()
                raise RuntimeError(
                    f"ghidra_open: backend SSE initialize failed: {exc}. "
                    + _tail_log(BACKEND_LOG)) from exc
            STACKS.append(stack)
            BACKEND.update({"proc": proc, "port": port, "session": sess,
                            "lock": asyncio.Lock(), "log_fh": log_fh,
                            "pump": pump})
            _log(f"shim: pyghidra backend up pid={proc.pid} port={port}")
            # Adopt programs a dead predecessor imported — the project
            # file outlives the backend process.
            await _adopt_project_programs()
            # First live backend -> pull real per-tool schemas so
            # `ghidra_manage schemas` returns argument shapes.
            from .listing import _maybe_populate_schemas
            await _maybe_populate_schemas(sess)
            return sess
        _kill_proc(proc)
        try:
            await asyncio.wait_for(asyncio.shield(pump), timeout=3)
        except Exception:  # noqa: BLE001
            pass
        pump.cancel()
        log_fh.close()
        raise RuntimeError(
            f"ghidra_open: backend exited rc={proc.returncode}: see "
            f"{BACKEND_LOG.name}. " + _tail_log(BACKEND_LOG))


async def _call_backend(tool: str, args: dict):
    """One serialized call on the shared backend's MCP session."""
    sess = await _ensure_backend()
    async with BACKEND["lock"]:
        return await sess.call_tool(tool, args)


async def _adopt_project_programs() -> None:
    """Rebuild SESSIONS from the shared project's contents after a
    backend (re)spawn."""
    from .listing import _flat_text_from_content
    try:
        r = await _call_backend("list_project_binaries", {})
    except Exception as exc:  # noqa: BLE001
        _log(f"shim: adopt/list_project_binaries failed: {exc}")
        return
    text = _flat_text_from_content(getattr(r, "content", []) or [])
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return
    rows = data.get("binaries") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return
    async with REG_LOCK:
        for row in rows:
            pname = row.get("binary_name")
            if not pname:
                continue
            sid = ALIASES.get(pname)
            if sid is None:
                sid = f"sess_{uuid.uuid4().hex[:8]}"
                ALIASES[pname] = sid
            if sid not in SESSIONS:
                SESSIONS[sid] = {"program": pname,
                                 "path": row.get("path") or "",
                                 "lock": asyncio.Lock()}
                if row.get("path"):
                    BY_PATH[str(Path(row["path"]).resolve()).lower()] = sid
    _log(f"shim: adopted {sum(1 for _ in SESSIONS)} project programs")


async def _open(input_path: str, run_auto_analysis: bool = True,
                preferred_session_id: str = "", mode: str = "", **_kw) -> str:
    resolved = str(Path(input_path).resolve())
    key = resolved.lower()
    # In-flight import guard keyed by path (same race the idalib shim
    # guards): BY_PATH isn't populated until import_binary returns.
    async with REG_LOCK:
        spawn_lock = LOCKS.setdefault(key, asyncio.Lock())
    async with spawn_lock:
        async with REG_LOCK:
            existing_sid = BY_PATH.get(key)
            if existing_sid is not None and preferred_session_id:
                ALIASES[preferred_session_id] = existing_sid
        if existing_sid is not None:
            return json.dumps(_sess_payload(existing_sid))
        await _ensure_backend()
        # import_binary adopts same-name project programs; analyze=False
        # honors the no-auto-analysis path for huge drivers.
        r = await _call_backend("import_binary", {
            "binary_path": resolved,
            "name": preferred_session_id or "",
            "analyze": bool(run_auto_analysis),
        })
        from .listing import _flat_text_from_content
        text = _flat_text_from_content(getattr(r, "content", []) or [])
        if getattr(r, "isError", False):
            raise RuntimeError(f"import_binary failed: {text}")
        try:
            data = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"import_binary returned unparseable payload: {text[:400]}") from exc
        if isinstance(data, dict) and data.get("ok") is False:
            raise RuntimeError(
                f"import_binary failed: {data.get('error', text[:400])}")
        pname = (data.get("binary_name")
                 or preferred_session_id
                 or Path(resolved).stem)
        sid = preferred_session_id or pname or f"sess_{uuid.uuid4().hex[:8]}"
        async with REG_LOCK:
            SESSIONS[sid] = {"program": pname, "path": resolved,
                             "lock": asyncio.Lock()}
            BY_PATH[key] = sid
            ALIASES[sid] = sid
            if preferred_session_id:
                ALIASES[preferred_session_id] = sid
            ALIASES.setdefault(pname, sid)
        return json.dumps(_sess_payload(sid))


async def _list() -> str:
    try:
        await _ensure_backend()
        alive = await _probe_backend_alive()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"sessions": [], "count": 0,
                           "backend_alive": False,
                           "backend_error": f"{type(exc).__name__}: {exc}",
                           "shared_backend": True})
    proc = BACKEND.get("proc")
    sessions = [
        {"session_id": sid, "input_path": st["path"],
         "filename": Path(st["path"]).name if st["path"] else st["program"],
         "binary_name": st["program"],
         "backend_alive": alive,
         "port": BACKEND.get("port"),
         "backend_pid": proc.pid if proc is not None else None}
        for sid, st in SESSIONS.items()
    ]
    return json.dumps({"sessions": sessions, "count": len(sessions),
                       "backend_alive": alive, "shared_backend": True})


async def _close(database: str = "", name: str = "", save: bool = True,
                 purge: bool = False, **_kw) -> str:
    # `database` is the shim's canonical key; `name` is the friendly
    # alias the bridge resolves. Accept both.
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
            f"ghidra_close: unknown session {key!r}; known sessions: {known}. "
            "Pass 'database' (shim canonical) or 'name' (friendly alias).")
    # The program stays in the project on release (reopenable); purge
    # deletes the domain file entirely.
    tool = "delete_project_binary" if purge else "release_program"
    args = {"binary_name": st["program"]}
    if not purge:
        args["save"] = bool(save)
    try:
        r = await _call_backend(tool, args)
        from .listing import _flat_text_from_content
        backend_text = _flat_text_from_content(
            getattr(r, "content", []) or [])[:800]
    except Exception as exc:  # noqa: BLE001
        backend_text = f"{type(exc).__name__}: {exc}"
    return json.dumps({"success": True, "closed": sid,
                       "binary_name": st["program"],
                       "purged": bool(purge),
                       "backend_result": backend_text})


def _cleanup() -> None:
    _kill_backend_proc()
