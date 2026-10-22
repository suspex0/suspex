"""Ida tool registration for the suspex0 MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
# Part 3 evidence envelope (detail=/retention) — passthrough actions only.
from ..evidence.store import split_detail as _ev_split_detail
from ..evidence.store import with_evidence as _ev_with
from .. import _coverage
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)


# Passthrough shim verbs whose results carry decompiler coverage
# (decompile + xref per the provenance/coverage plan).
_DECOMPILER_COVERAGE_ACTIONS = frozenset({
    "decompile", "decompile_function", "xrefs", "list_xrefs",
})


# v0.22: curated one-liners for the short verbs. The action list is open —
# any unknown verb is passed through verbatim to the shim — so this tool
# deliberately has no schema enum and no _unknown_action gate.
_IDA_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "ida_manage(action='actions')"},
    "open": {"one_liner": "open a binary in an IDA session (named)",
             "key_args": "path, name, share",
             "example": "ida_manage(action='open', path='x.sys')"},
    "open_async": {"one_liner": "start open in background; poll "
                                "open_status/list for readiness",
                   "key_args": "path, name, share, return_after_s",
                   "example": "ida_manage(action='open_async', "
                              "path='big.sys')"},
    "open_status": {"one_liner": "poll an async open",
                    "key_args": "name",
                    "example": "ida_manage(action='open_status', "
                               "name='big.sys')"},
    "close": {"one_liner": "close an IDA session",
              "key_args": "name, force",
              "example": "ida_manage(action='close', name='x.sys')"},
    "list": {"one_liner": "list open sessions + available bridge tools",
             "key_args": "none",
             "example": "ida_manage(action='list')"},
    "schemas": {"one_liner": "fetch per-tool inputSchema from the bridge "
                             "(args_json={\"tools\":[...]} filters)",
                "key_args": "args_json",
                "example": "ida_manage(action='schemas')"},
    "tools": {"one_liner": "light inventory — bridge tool names + "
                           "one-liners",
              "key_args": "none",
              "example": "ida_manage(action='tools')"},
    "health": {"one_liner": "probe shim/backend liveness (no db open)",
               "key_args": "none",
               "example": "ida_manage(action='health')"},
    "dump_layout": {"one_liner": "dump struct/enum layout into the "
                                 "orchestrator's pdb_layout_cache "
                                 "(feeds symbols_manage layout verbs)",
                    "key_args": "args_json={\"names\":[...]}",
                    "example": "ida_manage(action='dump_layout', "
                               "args_json='{\"names\":[\"_EPROCESS\"]}')"},
    "<passthrough>": {
        "one_liner": "any other action is forwarded verbatim to the "
                     "idalib-mcp shim (decompile, disasm, xrefs, names, "
                     "strings, imports, exports, functions, segments, "
                     "search, annotate, bytes, callers, callees, structs, "
                     "struct_offsets, stack_frame, get_entry_points, "
                     "declare_c_type, ...)",
        "key_args": "args_json — per-tool args (see action='schemas')",
        "example": "ida_manage(action='decompile', "
                   "args_json='{\"func\":\"0x140001000\"}')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``ida_manage`` tool on *mcp*, using *ctx* for state."""
    # --------------------------------------------------------------- ida_manage --

    class IdaArgs(BaseModel):
        action: str = Field(description=(
            "open|open_async|open_status|list|schemas|tools|close|"
            "ida_job_*|<any idalib-mcp tool name — passthrough; "
            "action='schemas' lists the full inventory"))
        name: str = Field(default="", description="session name / database id from open")
        path: str = ""
        args_json: str = Field(default="{}", description=(
            "JSON object of tool arguments; addresses as '0x...' or "
            "decimal"))
        share: bool = Field(default=False, description=(
            "open/open_async: join a same-(name,path) session as co-owner"))
        force: bool = Field(default=False, description=(
            "close: bypass the ownership check"))

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def ida_manage(action: str, name: str = "", path: str = "", args_json: str = "{}",
                         share: bool = False, force: bool = False,
                         detail: str = "complete") -> str:
        """IDA analysis proxied to headless idalib-mcp — open/open_async/
        open_status manage persistent idb sessions; every other action is
        an idalib tool name forwarded verbatim (action='schemas' lists the
        full inventory, 'tools' a light one). Slow/oversize calls convert
        to background jobs (ida_job_*).

        **Never hand-decode PE/structured binary — open it here.**
        Per-verb help: ida_manage(action='actions')."""
        args = {"action": action, "name": name, "path": path}
        # Part 3: detail="summary" bounds the inline payload to counts;
        # both modes retain the complete record (artifacts/evidence/).
        _ev_detail, _ = _ev_split_detail(detail)

        async def run() -> str:
            cid = current_client_id()
            if action == "actions":
                # v0.22: pure-compute discovery — curated help for the
                # short verbs; the shim also accepts any idalib-mcp tool
                # name verbatim (see action='schemas' for the full set).
                return _actions_help("ida_manage", _IDA_ACTION_HELP)
            if action == "list":
                tools = await ctx.bridge.list_tools()
                try:
                    await ctx.bridge.refresh_sessions()
                except Exception:  # noqa: BLE001 - stale cache is not fatal
                    pass
                return _j({"tools": sorted(t["name"] for t in tools),
                           "sessions": ctx.bridge.sessions_snapshot(cid)})
            if action == "schemas":
                # Re-fetch: startup inventory has generic schemas until
                # the shim has cached them from a live backend.
                await ctx.bridge.refresh_tools()
                # C2-1a: optional `tools=[...]` filter in args_json — a
                # full dump is ~25 KB (30% of a session's context in one
                # call), so a caller reaching for a single tool's
                # inputSchema now pays only for that tool.
                wanted = _parse_ida_schemas_filter(args_json)
                rows = _filter_ida_schemas(ctx.bridge.tool_schemas(), wanted)
                return _j({"count": len(rows),
                           "filtered": bool(wanted),
                           "tools": rows})
            if action == "tools":
                # C2-1b: light inventory — name + one-liner only. A full
                # `schemas` call is expensive; this is the discovery
                # step callers can use to pick which tool's schema to
                # fetch next. Emits a single-sentence description
                # (hard-capped) so the payload stays under a few KB
                # even with 60+ tools.
                await ctx.bridge.refresh_tools()
                rows = [{"name": t.get("name"),
                         "one_liner": _one_line_desc(t.get("description", ""))}
                        for t in ctx.bridge.tool_schemas()]
                return _j({"count": len(rows), "tools": rows})
            call_args = json.loads(args_json) | ({"path": path} if path else {})
            # share/force are meta-level flags the bridge pops from the
            # args dict; inject them here so ida_manage() sees the same
            # shape whether the caller used the top-level kwargs or
            # embedded them in args_json (args_json wins on conflict).
            if action in ("open", "open_async"):
                call_args.setdefault("share", share)
            elif action == "close":
                call_args.setdefault("force", force)
            # v0.17 C1-3: session-scoped actions with no explicit name
            # fall back to the bridge's MRU. Returned marker
            # `autofilled_name` gets folded into a top-level warning so
            # the caller can see (and course-correct) which session
            # actually served the request.
            resolved_name, mru_autofilled = ctx.bridge.autofill_session_name(
                action, name or None,
            )
            if mru_autofilled and resolved_name is None:
                # No MRU exists — surface a typed error instead of
                # letting the shim raise a confusing bad-database
                # complaint downstream.
                raise IdaBridgeError(
                    f"ida_manage {action}: no session name given and no MRU "
                    "session; call ida_manage(action='open', path=...) "
                    "first, or pass name=... explicitly"
                )
            result = await ctx.bridge.ida_manage(
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
                        # claim() is idempotent: a share=True open into
                        # an already-tagged session leaves the primary
                        # owner tag intact, so this is safe to call on
                        # every successful open path (fresh open,
                        # collision-suffixed peer, or co-owner join).
                        await ctx.ownership.claim(
                            "ida_session", env_name, cid)
                elif action == "close" and name:
                    await ctx.ownership.release("ida_session", name)
            # v0.18 auto-breadcrumbs: register open/close in ida_sessions +
            # emit a tool_events row for the passthrough actions so a
            # peer's about(sha=…) surfaces "agent-X ran decompile" etc.
            try:
                if action in ("open", "open_async"):
                    try:
                        env = json.loads(result)
                    except (TypeError, ValueError):
                        env = None
                    env_name = (env.get("name")
                                if isinstance(env, dict) else resolved_name)
                    if env_name:
                        _register_ida_open(ctx, env_name, path or call_args.get("path", ""),
                                           async_open=(action == "open_async"))
                elif action == "close":
                    _register_ida_close(ctx, resolved_name or name)
                elif action not in ("list", "schemas", "tools", "open_status",
                                    "ida_log", "ida_job_status", "ida_job_list",
                                    "ida_job_cancel", "ida_result",
                                    "ida_job_start"):
                    _register_ida_action(ctx, resolved_name or name, action, call_args)
            except Exception as _bc_exc:  # pragma: no cover
                log.debug("ida_manage breadcrumb dropped: %s", _bc_exc)
            if mru_autofilled and resolved_name is not None:
                # Fold the autofill into a top-level warning on the
                # response envelope. The shim response may be raw text
                # or a JSON dict; either way we wrap into a success
                # envelope with warnings so _coerce_to_envelope sees
                # the "already-envelope" fast path and passes through.
                try:
                    payload: Any = json.loads(result)
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload = {"text": result}
                if not isinstance(payload, dict):
                    payload = {"value": payload}
                # A5's warn() helper isn't shipped yet; envelope_ok
                # accepts a `warnings=` iterable directly, which is
                # the same slot warn() will write into.
                env = _envelope_ok(
                    payload,
                    kind=_resolve_kind("ida_manage", action),
                    tool="ida_manage",
                    action=action,
                    warnings=[
                        f"ida_manage(action={action!r}): session name "
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

        return await _guard(ctx, "ida_manage", action, args,
                            _ev_with(ctx, "ida_manage", action, args, run,
                                     _ev_detail))
