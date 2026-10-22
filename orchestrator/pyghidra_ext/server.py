"""MCP SSE server for the pyghidra backend.

Plain ``mcp.server.lowlevel.Server`` + ``SseServerTransport`` on
Starlette/uvicorn — the same transport shape the idalib backends serve
and the shim connects to (``sse_client(http://127.0.0.1:<port>/sse)``).

The tool registry is a flat ``{name: (fn, one_liner)}`` dict built from
the tools_* modules, so adding a tool is one line in ``_build_registry``.
"""
from __future__ import annotations

import inspect
import json
from typing import Any, Callable

import mcp.types as types
from mcp.server.lowlevel import Server

from . import tools_analysis, tools_edit, tools_misc, tools_programs, \
    tools_types
from .state import STATE, _log


def _build_registry() -> dict[str, tuple[Callable, str]]:
    """name -> (callable, description). Grouped by module for readability."""
    reg: dict[str, tuple[Callable, str]] = {}

    def add(fn: Callable, desc: str = "") -> None:
        if not desc:
            doc = (fn.__doc__ or "").strip()
            desc = doc.splitlines()[0] if doc else f"ghidra tool {fn.__name__}"
        reg[fn.__name__] = (fn, desc)

    # project/session management (the shim's open/close/list map onto these)
    add(tools_programs.import_binary)
    add(tools_programs.list_project_binaries)
    add(tools_programs.list_project_binary_metadata)
    add(tools_programs.delete_project_binary)
    add(tools_programs.program_save)
    add(tools_programs.release_program)
    add(tools_programs.analyze_program)
    add(tools_programs.project_info)

    # analysis
    for fn in (
        tools_analysis.get_metadata,
        tools_analysis.list_functions,
        tools_analysis.get_function_by_name,
        tools_analysis.get_function_by_address,
        tools_analysis.search_symbols_by_name,
        tools_analysis.decompile_function,
        tools_analysis.disassemble_function,
        tools_analysis.get_pcode,
        tools_analysis.list_xrefs,
        tools_analysis.gen_callgraph,
        tools_analysis.list_imports,
        tools_analysis.list_exports,
        tools_analysis.get_entry_points,
        tools_analysis.list_segments,
        tools_analysis.read_bytes,
        tools_analysis.search_strings,
        tools_analysis.create_function,
        tools_analysis.pattern_scan,
        tools_analysis.qword_value_scan,
        tools_analysis.search_code,
        tools_analysis.analysis_status,
        tools_analysis.ghidra_query_context,
        tools_analysis.ghidra_status,
    ):
        add(fn)

    # edits
    for fn in (
        tools_edit.rename_function,
        tools_edit.rename_variable,
        tools_edit.set_variable_type,
        tools_edit.set_function_prototype,
        tools_edit.set_comment,
        tools_edit.patch_bytes,
    ):
        add(fn)

    # types
    for fn in (
        tools_types.type_info,
        tools_types.get_struct_member,
        tools_types.resolve_offset,
        tools_types.analyze_struct_detailed,
        tools_types.list_data_types,
        tools_types.dump_layout,
    ):
        add(fn)

    # escape hatch
    add(tools_misc.exec_ghidra_script)
    return reg


def _schema_for(fn: Callable) -> dict:
    """Cheap inputSchema from the python signature: every param is a
    string/number/bool/array; binary_name is always required, the rest
    carry defaults and are optional."""
    sig = inspect.signature(fn)
    props: dict[str, Any] = {}
    required: list[str] = []
    for pname, p in sig.parameters.items():
        ann = p.annotation
        t = "string"
        if ann in (int, "int"):
            t = "integer"
        elif ann in (bool, "bool"):
            t = "boolean"
        props[pname] = {"type": t}
        if p.default is inspect.Parameter.empty:
            required.append(pname)
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": True}


def make_server() -> tuple[Server, dict]:
    registry = _build_registry()
    server: Server = Server("suspex-pyghidra-ext")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [types.Tool(name=n, description=d,
                           inputSchema=_schema_for(fn))
                for n, (fn, d) in sorted(registry.items())]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list[types.Content]:
        entry = registry.get(name)
        if entry is None:
            return [types.TextContent(
                type="text",
                text=json.dumps({"ok": False, "kind": "unknown_tool",
                                 "error": f"no such tool {name!r}",
                                 "available": sorted(registry)}))]
        fn, _ = entry
        try:
            kwargs = dict(arguments or {})
            # callers may spell binary_name as database/name/program —
            # normalize here so tool bodies only see binary_name.
            if "binary_name" not in kwargs:
                for alt in ("database", "program", "name", "binary"):
                    if alt in kwargs:
                        kwargs["binary_name"] = kwargs.pop(alt)
                        break
            sig = inspect.signature(fn)
            if "binary_name" in sig.parameters:
                kwargs.setdefault("binary_name", "")
            # drop args the function doesn't accept (forgiving shim)
            accepted = set(sig.parameters)
            kwargs = {k: v for k, v in kwargs.items() if k in accepted}
            text = fn(**kwargs)
        except Exception as exc:  # noqa: BLE001
            text = json.dumps({
                "ok": False, "kind": "tool_error",
                "error": f"{type(exc).__name__}: {exc}"})
        return [types.TextContent(type="text", text=str(text))]

    return server, registry


def serve(host: str, port: int) -> None:
    """Run the SSE app on uvicorn (blocking)."""
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    import uvicorn

    server, _ = make_server()
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request):
        async with sse.connect_sse(request.scope, request.receive,
                                   request._send) as (read, write):
            await server.run(
                read, write, server.create_initialization_options())

    async def handle_health(request: Request):
        return JSONResponse({
            "ok": True, "project": STATE.project_name,
            "jvm": STATE.jvm_started,
            "programs": sorted(STATE.programs)})

    app = Starlette(routes=[
        Route("/sse", handle_sse),
        Route("/health", handle_health),
        Mount("/messages/", app=sse.handle_post_message),
    ])
    _log(f"SSE backend listening on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
