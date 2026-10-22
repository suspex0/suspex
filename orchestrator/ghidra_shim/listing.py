"""Backend tool inventory + list_tools/log/preview helpers.

The MCP ``Server`` instance lives here since the tools-listing decorator
is where it first anchors; ``dispatch.py`` imports it back to hang the
call-tool handler off the same object.

Port of ``idalib_shim.listing``.
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
# the shared backend's tools/list so callers see real schemas (argument
# names/types) instead of a generic "any object" placeholder.
BACKEND_TOOL_META: dict[str, dict] = {}


server = Server("suspex-ghidra-shim")


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
            "description": t.description or f"Ghidra tool {t.name}",
            "inputSchema": t.inputSchema or {"type": "object",
                                              "additionalProperties": True},
        }
    _log(f"shim: cached {len(BACKEND_TOOL_META)} backend tool schemas")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    generic = {"type": "object", "additionalProperties": True}
    tools = [
        types.Tool(name="ghidra_open",
                   description="Import a binary into the shared Ghidra project "
                               "(spawns the one-JVM backend on first use)",
                   inputSchema=generic),
        types.Tool(name="ghidra_list",
                   description="List open Ghidra sessions/programs + backend liveness",
                   inputSchema=generic),
        types.Tool(name="ghidra_close",
                   description="Release (save) or purge a program from the project",
                   inputSchema=generic),
        types.Tool(name="ghidra_log",
                   description="Last N lines of the backend log (works even if backend just died)",
                   inputSchema=generic),
        types.Tool(name="ghidra_job_start",
                   description="Explicitly start a passthrough tool as a background job. "
                               "Prefer letting the shim auto-promote — this is for cases "
                               "you know up-front will exceed the soft deadline.",
                   inputSchema=generic),
        types.Tool(name="ghidra_job_status",
                   description="Poll a background job's status (pending|done|error|cancelled).",
                   inputSchema=generic),
        types.Tool(name="ghidra_result",
                   description="Fetch one chunk of a completed job's result. "
                               "Callers concatenate `data` across pages 0..total_pages-1.",
                   inputSchema=generic),
        types.Tool(name="ghidra_job_cancel",
                   description="Best-effort cancel a pending job (task.cancel).",
                   inputSchema=generic),
        types.Tool(name="ghidra_job_list",
                   description="Enumerate known jobs; active_only=true skips finished ones.",
                   inputSchema=generic),
    ]
    # Union BACKEND_TOOLS (startup inventory sample) with anything the
    # live backend actually advertised on first open.
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
                                    description=f"Ghidra tool {n}",
                                    inputSchema=generic))
    return tools


async def _log_tail(database: str = "", name: str = "", lines: int = 40,
                    **_kw) -> str:
    """Return the last N lines of the shared backend's own log — JVM
    boot failures, project open tracebacks, import errors live here and
    are invisible from the tool-call surface otherwise. Works even if
    the backend just died: we own the log file handle.
    """
    from .sessions import ALIASES, BACKEND, REG_LOCK, SESSIONS

    key = database or name
    async with REG_LOCK:
        sid = ALIASES.get(key, key)
        if sid not in SESSIONS and len(SESSIONS) == 1:
            sid = next(iter(SESSIONS))
        st = SESSIONS.get(sid)
    log_path = Path(tempfile.gettempdir()) / "suspex_pyghidra_backend.log"
    proc = BACKEND.get("proc")
    return json.dumps({
        "session_id": sid if st is not None else (key or None),
        "binary_name": st["program"] if st is not None else None,
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
    return text[:PREVIEW_BYTES] + "\n… [truncated preview; ghidra_result to fetch remaining pages]"


def _flat_text_from_content(content: list) -> str:
    """Concatenate all TextContent parts of an mcp result into a single
    string. Non-text parts are ignored (we don't ship non-text upstream
    right now; if that changes, add a base64 wrapping here)."""
    parts = []
    for c in content:
        if isinstance(c, types.TextContent):
            parts.append(c.text)
    return "\n".join(parts)
