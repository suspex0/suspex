"""Ghidra tool registration for the suspex0 MCP server.

Sibling of ``ida.py``: ``ghidra_manage`` fronts the headless pyghidra
backend (one shared JVM + shared project) through the same
open/open_async/open_status/close/passthrough surface as ``ida_manage``,
so an analysis can switch engines by changing one tool name.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
# Part 3 evidence envelope (detail=/retention) — passthrough actions only.
from ..evidence.store import split_detail as _ev_split_detail
from ..evidence.store import with_evidence as _ev_with
from .. import _coverage


# Passthrough shim verbs whose results carry decompiler coverage
# (decompile + xref per the provenance/coverage plan).
_DECOMPILER_COVERAGE_ACTIONS = frozenset({
    "decompile", "decompile_function", "xrefs", "list_xrefs",
})


# Curated one-liners for the short verbs. The action list is open — any
# unknown verb is passed through verbatim to the shim — so this tool
# deliberately has no schema enum and no _unknown_action gate.
_GHIDRA_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "ghidra_manage(action='actions')"},
    "open": {"one_liner": "open a binary in a Ghidra session (named, "
                          "shared project)",
             "key_args": "path, name, share",
             "example": "ghidra_manage(action='open', path='x.sys')"},
    "open_async": {"one_liner": "start open in background; poll "
                                "open_status/list for readiness",
                   "key_args": "path, name, share, return_after_s",
                   "example": "ghidra_manage(action='open_async', "
                              "path='big.sys')"},
    "open_status": {"one_liner": "poll an async open",
                    "key_args": "name",
                    "example": "ghidra_manage(action='open_status', "
                               "name='big.sys')"},
    "close": {"one_liner": "close a Ghidra session (save+release; "
                           "purge=true deletes the program)",
              "key_args": "name, force, purge",
              "example": "ghidra_manage(action='close', name='x.sys')"},
    "list": {"one_liner": "list open sessions + available bridge tools",
             "key_args": "none",
             "example": "ghidra_manage(action='list')"},
    "schemas": {"one_liner": "fetch per-tool inputSchema from the bridge "
                             "(args_json={\"tools\":[...]} filters)",
                "key_args": "args_json",
                "example": "ghidra_manage(action='schemas')"},
    "tools": {"one_liner": "light inventory — bridge tool names + "
                           "one-liners",
              "key_args": "none",
              "example": "ghidra_manage(action='tools')"},
    "health": {"one_liner": "probe shim/backend liveness (no program open)",
               "key_args": "none",
               "example": "ghidra_manage(action='health')"},
    "dump_layout": {"one_liner": "dump struct/enum layout into the "
                                 "orchestrator's pdb_layout_cache "
                                 "(feeds symbols_manage layout verbs)",
                    "key_args": "args_json={\"names\":[...]}",
                    "example": "ghidra_manage(action='dump_layout', "
                               "args_json='{\"names\":[\"_EPROCESS\"]}')"},
    "<passthrough>": {
        "one_liner": "any other action is forwarded verbatim to the "
                     "ghidra shim (decompile, disasm, pcode, xrefs, "
                     "funcs, types, strings, imports, exports, segments, "
                     "search_symbols_by_name, read_bytes, list_xrefs, "
                     "gen_callgraph, search_code, rename_function, "
                     "rename_variable, set_variable_type, "
                     "set_function_prototype, set_comment, "
                     "create_function, pattern_scan, qword_value_scan, "
                     "type_info, get_struct_member, resolve_offset, "
                     "analyze_struct_detailed, exec_ghidra_script, "
                     "import_binary, list_project_binaries, "
                     "program_save, analyze_program, ...)",
        "key_args": "args_json — per-tool args (see action='schemas')",
        "example": "ghidra_manage(action='decompile', "
                   "args_json='{\"name_or_address\":\"0x140001000\"}')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``ghidra_manage`` tool on *mcp*, using *ctx* for state."""
    # ----------------------------------------------------------- ghidra_manage --

    class GhidraArgs(BaseModel):
        action: str = Field(description=(
            "open|open_async|open_status|list|schemas|tools|close|"
            "ghidra_job_*|<any ghidra backend tool name — passthrough; "
            "action='schemas' lists the full inventory"))
        name: str = Field(default="", description="session name / program id from open")
        path: str = ""
        args_json: str = Field(default="{}", description=(
            "JSON object of tool arguments; addresses as '0x...' or "
            "decimal"))
        share: bool = Field(default=False, description=(
            "open/open_async: join a same-(name,path) session as co-owner"))
        force: bool = Field(default=False, description=(
            "close: bypass the ownership check"))

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def ghidra_manage(action: str, name: str = "", path: str = "", args_json: str = "{}",
                            share: bool = False, force: bool = False,
                            detail: str = "complete") -> str:
        """Ghidra analysis proxied to the headless pyghidra backend —
        open/open_async/open_status manage named program sessions inside
        one shared project; every other action is a backend tool name
        forwarded verbatim (action='schemas' lists the full inventory,
        'tools' a light one). Slow/oversize calls convert to background
        jobs (ghidra_job_*).

        Use instead of ida_manage when IDA/idalib is unavailable or a
        second decompiler opinion is wanted (P-code via
        action='pcode'|get_pcode). Per-verb help:
        ghidra_manage(action='actions')."""
        args = {"action": action, "name": name, "path": path}
        # Part 3: detail="summary" bounds the inline payload to counts;
        # both modes retain the complete record (artifacts/evidence/).
        _ev_detail, _ = _ev_split_detail(detail)

        async def run() -> str:
            if action == "actions":
                # Pure-compute discovery — must answer even while the
                # engine is disabled/not configured (same contract as
                # ida_manage actions).
                return _actions_help("ghidra_manage", _GHIDRA_ACTION_HELP)
            if not getattr(ctx.cfg, "ghidra", None) \
                    or not ctx.cfg.ghidra.enabled:
                raise GhidraBridgeError(
                    "ghidra_manage is disabled — set ghidra.enabled=true "
                    "in the suspex0 config, point ghidra.ghidra_dir at a "
                    "Ghidra install, and ensure pyghidra+JDK are available "
                    "in the backend env (ghidra.backend_python / "
                    ".ghidra-venv)."
                )
            if ctx.gbridge is None:
                raise GhidraBridgeError(
                    "ghidra_manage: bridge not wired into this "
                    "orchestrator (ghidra.enabled=false at boot?)"
                )
            cid = current_client_id()
            if action == "list":
                tools = await ctx.gbridge.list_tools()
                try:
                    await ctx.gbridge.refresh_sessions()
                except Exception:  # noqa: BLE001 - stale cache is not fatal
                    pass
                return _j({"tools": sorted(t["name"] for t in tools),
                           "sessions": ctx.gbridge.sessions_snapshot(cid)})
            if action == "schemas":
                await ctx.gbridge.refresh_tools()
                wanted = _parse_ida_schemas_filter(args_json)
                rows = _filter_ida_schemas(ctx.gbridge.tool_schemas(), wanted)
                return _j({"count": len(rows),
                           "filtered": bool(wanted),
                           "tools": rows})
            if action == "tools":
                await ctx.gbridge.refresh_tools()
                rows = [{"name": t.get("name"),
                         "one_liner": _one_line_desc(t.get("description", ""))}
                        for t in ctx.gbridge.tool_schemas()]
                return _j({"count": len(rows), "tools": rows})
            call_args = json.loads(args_json) | ({"path": path} if path else {})
            if action in ("open", "open_async"):
                call_args.setdefault("share", share)
            elif action == "close":
                call_args.setdefault("force", force)
            # Session-scoped actions with no explicit name fall back to
            # the bridge's MRU — same contract as ida_manage.
            resolved_name, mru_autofilled = ctx.gbridge.autofill_session_name(
                action, name or None,
            )
            if mru_autofilled and resolved_name is None:
                raise GhidraBridgeError(
                    f"ghidra_manage {action}: no session name given and no "
                    "MRU session; call ghidra_manage(action='open', "
                    "path=...) first, or pass name=... explicitly"
                )
            result = await ctx.gbridge.ghidra_manage(
                action, resolved_name, call_args, owner=cid,
            )
            if ctx.ownership is not None:
                if action in ("open", "open_async"):
                    try:
                        env = json.loads(result)
                    except (TypeError, ValueError):
                        env = None
                    env_name = (env.get("name")
                                if isinstance(env, dict) else None)
                    if env_name:
                        await ctx.ownership.claim(
                            "ghidra_session", env_name, cid)
                elif action == "close" and name:
                    await ctx.ownership.release("ghidra_session", name)
            # auto-breadcrumbs: register open/close in the shared
            # analysis-session table (engine='ghidra') + emit tool_events
            # rows so a peer's about(sha=…) shows cross-engine work.
            try:
                if action in ("open", "open_async"):
                    try:
                        env = json.loads(result)
                    except (TypeError, ValueError):
                        env = None
                    env_name = (env.get("name")
                                if isinstance(env, dict) else resolved_name)
                    if env_name:
                        _register_ida_open(
                            ctx, env_name,
                            path or call_args.get("path", ""),
                            async_open=(action == "open_async"),
                            engine="ghidra")
                elif action == "close":
                    _register_ida_close(ctx, resolved_name or name,
                                        engine="ghidra")
                elif action not in ("list", "schemas", "tools", "open_status",
                                    "ghidra_log", "ghidra_job_status",
                                    "ghidra_job_list", "ghidra_job_cancel",
                                    "ghidra_result", "ghidra_job_start"):
                    _register_ida_action(ctx, resolved_name or name, action,
                                         call_args, engine="ghidra")
            except Exception as _bc_exc:  # pragma: no cover
                log.debug("ghidra_manage breadcrumb dropped: %s", _bc_exc)
            if mru_autofilled and resolved_name is not None:
                try:
                    payload: Any = json.loads(result)
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload = {"text": result}
                if not isinstance(payload, dict):
                    payload = {"value": payload}
                env = _envelope_ok(
                    payload,
                    kind=_resolve_kind("ghidra_manage", action),
                    tool="ghidra_manage",
                    action=action,
                    warnings=[
                        f"ghidra_manage(action={action!r}): session name "
                        f"auto-filled from MRU: {resolved_name!r} — "
                        "pass name=... explicitly to override"
                    ],
                )
                return _j(env)
            if action in _DECOMPILER_COVERAGE_ACTIONS:
                # Provider returned a result → complete; shim-reported
                # warnings/unresolved → partial (provider_warnings).
                try:
                    parsed = json.loads(result)
                except (TypeError, ValueError):
                    parsed = None
                if isinstance(parsed, dict):
                    warns = parsed.get("warnings") or parsed.get("unresolved")
                    parsed.setdefault("coverage", _coverage.coverage(
                        "decompiler",
                        "partial" if warns else "complete",
                        *(["provider_warnings"] if warns else [])))
                    result = json.dumps(parsed, indent=2, default=str)
            return result

        return await _guard(ctx, "ghidra_manage", action, args,
                            _ev_with(ctx, "ghidra_manage", action, args, run,
                                     _ev_detail))
