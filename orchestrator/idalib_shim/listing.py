"""Backend tool inventory + list_tools/log/preview helpers.

The MCP ``Server`` instance lives here since the tools-listing decorator
is where it first anchors; ``dispatch.py`` imports it back to hang the
call-tool handler off the same object.

Mechanical split-out from ``idalib_stdio_shim.py``; no behavior changes.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import mcp.types as types
from mcp import ClientSession
from mcp.server.lowlevel import Server

from .logging import _log, _tail_log


PREVIEW_BYTES = 2048


BACKEND_TOOLS: list[str] = []
# name -> {"description": str, "inputSchema": dict} — populated once from
# the first live backend's tools/list so callers see real schemas
# (argument names/types) instead of a generic "any object" placeholder.
BACKEND_TOOL_META: dict[str, dict] = {}


server = Server("suspex-idalib-shim")


async def _maybe_populate_schemas(sess: ClientSession) -> None:
    if BACKEND_TOOL_META:
        return
    try:
        resp = await asyncio.wait_for(sess.list_tools(), timeout=15)
    except Exception as exc:  # noqa: BLE001 - inventory is best-effort
        _log(f"shim: could not fetch backend schemas: {exc}")
        return
    for t in resp.tools:
        BACKEND_TOOL_META[t.name] = {
            "description": t.description or f"IDA tool {t.name}",
            "inputSchema": t.inputSchema or {"type": "object",
                                              "additionalProperties": True},
        }
    _log(f"shim: cached {len(BACKEND_TOOL_META)} backend tool schemas")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    generic = {"type": "object", "additionalProperties": True}
    tools = [
        types.Tool(name="idb_open",
                   description="Open a binary in a headless IDA session",
                   inputSchema=generic),
        types.Tool(name="idb_list",
                   description="List open IDA sessions (marks backend_alive + reaps dead)",
                   inputSchema=generic),
        types.Tool(name="idb_close", description="Close an IDA session",
                   inputSchema=generic),
        types.Tool(name="ida_log",
                   description="Last N lines of the backend log (works even if backend just died)",
                   inputSchema=generic),
        types.Tool(name="ida_job_start",
                   description="Explicitly start a passthrough tool as a background job. "
                               "Prefer letting the shim auto-promote — this is for cases "
                               "you know up-front will exceed the soft deadline.",
                   inputSchema=generic),
        types.Tool(name="ida_job_status",
                   description="Poll a background job's status (pending|done|error|cancelled).",
                   inputSchema=generic),
        types.Tool(name="ida_result",
                   description="Fetch one chunk of a completed job's result. "
                               "Callers concatenate `data` across pages 0..total_pages-1.",
                   inputSchema=generic),
        types.Tool(name="ida_job_cancel",
                   description="Best-effort cancel a pending job (task.cancel).",
                   inputSchema=generic),
        types.Tool(name="ida_job_list",
                   description="Enumerate known jobs; active_only=true skips finished ones.",
                   inputSchema=generic),
    ]
    # Union BACKEND_TOOLS (from the startup rpc_registry sample) with
    # anything the live backend actually advertised on first open —
    # picks up the extension's create_function/exec_idapython even
    # though they aren't in the rpc_registry.
    seen: set[str] = set()
    for n in list(BACKEND_TOOLS) + list(BACKEND_TOOL_META):
        if n in seen:
            continue
        seen.add(n)
        meta = BACKEND_TOOL_META.get(n)
        if meta is not None:
            tools.append(types.Tool(name=n,
                                    description=meta["description"],
                                    inputSchema=meta["inputSchema"]))
        else:
            tools.append(types.Tool(name=n,
                                    description=f"IDA tool {n}",
                                    inputSchema=generic))
    return tools


async def _log_tail(database: str = "", name: str = "", lines: int = 40,
                    **_kw) -> str:
    """Return the last N lines of the backend's own log — startup-hook
    tracebacks (NameError inside our extension, PDB download failures,
    etc.) live here and are invisible from the tool-call surface
    otherwise. Works even if the backend just died: we own the log
    file handle.
    """
    # Imported lazily to avoid the sessions <-> listing cycle at import
    # time; sessions.py itself imports from this module.
    from .sessions import ALIASES, REG_LOCK, SESSIONS

    key = database or name
    async with REG_LOCK:
        sid = ALIASES.get(key, key)
        if sid not in SESSIONS and len(SESSIONS) == 1:
            sid = next(iter(SESSIONS))
        st = SESSIONS.get(sid)
    if st is None:
        # Not tracked — try to find the log by preferred name anyway.
        candidate = Path(tempfile.gettempdir()) / f"suspex_idalib_{key or sid}.log"
        if candidate.exists():
            return json.dumps({"session_id": key or sid, "backend_alive": False,
                               "log_path": str(candidate),
                               "log_tail": _tail_log(candidate, lines)})
        return json.dumps({"ok": False,
                           "error": f"unknown session {key!r}; "
                                    "no log file at " + str(candidate)})
    log_path = Path(tempfile.gettempdir()) / f"suspex_idalib_{sid}.log"
    proc = st.get("proc")
    return json.dumps({
        "session_id": sid,
        "backend_alive": proc is not None and proc.returncode is None,
        "backend_pid": proc.pid if proc else None,
        "log_path": str(log_path),
        "log_tail": _tail_log(log_path, lines),
    })


def _result_text(result: types.CallToolResult) -> str:
    parts = [c.text for c in result.content
             if isinstance(c, types.TextContent)]
    return "\n".join(parts) if parts else "tool error"


def _preview(text: str) -> str:
    """Head of the payload for the pending/chunked envelope so callers can
    at least glance without paging. Truncate at PREVIEW_BYTES."""
    if len(text) <= PREVIEW_BYTES:
        return text
    return text[:PREVIEW_BYTES] + "\n… [truncated preview; ida_result to fetch remaining pages]"


def _flat_text_from_content(content: list) -> str:
    """Concatenate all TextContent parts of an mcp result into a single
    string. Non-text parts are ignored (we don't ship non-text upstream
    right now; if that changes, add a base64 wrapping here)."""
    parts = []
    for c in content:
        if isinstance(c, types.TextContent):
            parts.append(c.text)
    return "\n".join(parts)
