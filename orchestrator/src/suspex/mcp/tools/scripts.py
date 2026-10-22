"""Scripts tool registration for the suspex0 MCP server.

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


# v0.22: module-level so the lazy action-enum annotation resolves — the
# schema enum + _unknown_action share this one source of truth.
SCRIPT_ACTIONS = ["list", "run", "history", "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``script_manage`` tool on *mcp*, using *ctx* for state."""
    # ---------------------------------------------------------- script_manage --

    _SCRIPT_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "script_manage(action='actions')"},
        "list": {"one_liner": "enumerate plugins under plugins/ "
                              "(bad manifests surface under bad_plugins)",
                 "key_args": "none",
                 "example": "script_manage(action='list')"},
        "run": {"one_liner": "run a plugin in a subprocess with the SDK "
                             "injected; result auto-filed as evidence",
                "key_args": "name, params_json",
                "example": "script_manage(action='run', name='pidddb_scan', "
                           "params_json='{\"recipe\":\"mm_unloaded_drivers\","
                           "\"source\":\"pdb\"}')"},
        "history": {"one_liner": "list past plugin findings (filter by "
                                 "name=)",
                    "key_args": "name, limit/offset/fields/summary",
                    "example": "script_manage(action='history')"},
    }

    class ScriptArgs(BaseModel):
        action: str = Field(description="list|run|history")
        name: str = Field(default="", description="plugin directory name (plugins/<name>)")
        params_json: str = Field(default="{}", description="params, validated against plugin.yaml")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def script_manage(action: Annotated[str, Field(json_schema_extra={"enum": SCRIPT_ACTIONS})],
                            name: str = "", params_json: str = "{}",
                            # v0.14 unified paging (Layer 3)
                            limit: int = 0,
                            offset: int = 0,
                            max_results: int = 0,
                            cursor: str = "",
                            verbosity: str = "normal",
                            fields: list[str] | None = None,
                            filter: Any = "",
                            summary: bool = False) -> str:
        """Run user plugins (plugins/<name>): list available plugins, run one
        (SDK injected in a subprocess, result auto-filed as finding evidence), or
        list past plugin findings."""
        args = {"action": action, "name": name}

        async def run() -> str:
            if action not in SCRIPT_ACTIONS:
                return _unknown_action("script_manage", action, SCRIPT_ACTIONS, _SCRIPT_ACTION_HELP)
            if action == "actions":
                return _actions_help("script_manage", _SCRIPT_ACTION_HELP)
            if action == "list":
                # v0.9.4: discover() no longer raises on a malformed
                # manifest; the plugin is skipped and the parse error
                # is surfaced in `bad_plugins` so the caller sees what
                # was excluded without losing the whole listing.
                from suspex.plugins import bad_manifests
                metas = discover(ctx.cfg)
                bad = bad_manifests()
                out = {"ok": True,
                       "plugins": [meta_dict(m) for m in metas]}
                if bad:
                    out["bad_plugins"] = bad
                return _j(out)
            if action == "run":
                params = json.loads(params_json or "{}")
                cid = current_client_id()
                cur_sid = ctx.get_current_session_id(cid)
                result = await run_plugin(ctx.cfg, ctx.session, ctx.ledger,
                                          cur_sid, name, params)
                filed = file_result(ctx.ledger, cur_sid, name, result)
                if not cur_sid:
                    ctx.set_current_session_id(cid, filed["session_id"])
                try:
                    _script_run_breadcrumb(
                        ctx, name=name,
                        target=ctx.session.cfg.target_endpoint,
                        params_json=params_json or "{}",
                    )
                except Exception as _bc_exc:  # pragma: no cover
                    log.debug("script_manage breadcrumb dropped: %s", _bc_exc)
                return _j({"ok": True, "plugin": name, "result": result, **filed})
            if action == "history":
                rows = [f.__dict__ for f in ctx.ledger.list_findings(None, None)
                        if f.refs.startswith("plugin:")]
                if name:
                    rows = [r for r in rows if r["refs"] == f"plugin:{name}"]
                eff_limit = limit or max_results
                return _j(_list_envelope(
                    rows, tool="script_manage", action="history",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ))
            return _unknown_action("script_manage", action, SCRIPT_ACTIONS, _SCRIPT_ACTION_HELP)

        return await _guard(ctx, "script_manage", action, args, run)
