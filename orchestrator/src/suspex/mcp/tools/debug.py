"""Debug tool registration for the suspex0 MCP server.

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


# v0.22: module-level so the lazy action-enum annotation resolves.
DEBUG_ACTIONS = ["launch", "attach", "detach", "continue", "step_into",
                 "step_over", "regs", "set_regs", "threads", "stacktrace",
                 "read", "write", "regions", "events", "cmd", "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``debug_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ debug_manage --

    _DEBUG_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "debug_manage(action='actions')"},
        "launch": {"one_liner": "spawn a process under dbgeng",
                   "key_args": "cmdline, workdir",
                   "example": "debug_manage(action='launch', "
                              "cmdline='C:\\\\lab\\\\target.exe')"},
        "attach": {"one_liner": "attach dbgeng to pid (or image=); "
                                "per-pid lease, busy envelope if held",
                   "key_args": "pid, image, wait_s",
                   "example": "debug_manage(action='attach', pid=1234)"},
        "detach": {"one_liner": "release the debug session (leases freed)",
                   "key_args": "pid",
                   "example": "debug_manage(action='detach')"},
        "continue": {"one_liner": "resume the debugee",
                     "key_args": "none",
                     "example": "debug_manage(action='continue')"},
        "step_into": {"one_liner": "single-step into",
                      "key_args": "count",
                      "example": "debug_manage(action='step_into')"},
        "step_over": {"one_liner": "single-step over calls",
                      "key_args": "count",
                      "example": "debug_manage(action='step_over')"},
        "regs": {"one_liner": "read the register bank",
                 "key_args": "none",
                 "example": "debug_manage(action='regs')"},
        "set_regs": {"one_liner": "write registers from a JSON map",
                     "key_args": "regs_json",
                     "example": "debug_manage(action='set_regs', "
                                "regs_json='{\"rip\":\"0x140001000\"}')"},
        "threads": {"one_liner": "list debugee threads",
                    "key_args": "none",
                    "example": "debug_manage(action='threads')"},
        "stacktrace": {"one_liner": "backtrace the current/all threads",
                       "key_args": "max_frames",
                       "example": "debug_manage(action='stacktrace')"},
        "read": {"one_liner": "read debugee memory (hex)",
                 "key_args": "address, size",
                 "example": "debug_manage(action='read', "
                            "address='0x140001000', size=64)"},
        "write": {"one_liner": "write debugee memory",
                  "key_args": "address, data_hex",
                  "example": "debug_manage(action='write', "
                             "address='0x140001000', data_hex='90 90')"},
        "regions": {"one_liner": "list debugee memory regions",
                    "key_args": "none",
                    "example": "debug_manage(action='regions')"},
        "events": {"one_liner": "dbgeng event history; from_seq= for "
                                "replay",
                   "key_args": "from_seq",
                   "example": "debug_manage(action='events', from_seq=0)"},
        "cmd": {"one_liner": "raw dbgeng command passthrough",
                "key_args": "command",
                "example": "debug_manage(action='cmd', command='!peb')"},
    }

    class DebugArgs(BaseModel):
        action: str = Field(description="|".join(DEBUG_ACTIONS))
        cmdline: str = ""
        workdir: str = ""
        pid: int = 0
        image: str = Field(default="", description="attach: process image name (pid resolved)")
        kill: bool = False
        count: int = 1
        regs_json: str = ""
        address: int | str = Field(default=0,
                                   description="int, '0x...' hex, or "
                                               "'module+offset'")
        size: int = 64
        data_hex: str = ""
        max_frames: int = 32
        command: str = Field(default="", description="cmd: raw dbgeng command")
        from_seq: int = Field(default=0, description="events: replay from sequence number")
        force: bool = Field(default=False,
                            description="mutating actions: override a "
                                        "foreign-owner debug lease")
        wait_s: float = Field(default=0.0,
                              description="attach: wait seconds for the "
                                          "pid lease before kind='busy'")
        name: str = Field(default="",
                          description="target view: '' = focused/default "
                                      "machine's kernel view; "
                                      "'<machine>.<kind>' or '<machine>' "
                                      "to pick")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def debug_manage(action: Annotated[str, Field(json_schema_extra={"enum": DEBUG_ACTIONS})],
                           cmdline: str = "", workdir: str = "", pid: int = 0,
                           image: str = "", kill: bool = False, count: int = 1,
                           regs_json: str = "", address: int | str = 0, size: int = 64,
                           data_hex: str = "", max_frames: int = 32, command: str = "",
                           from_seq: int = 0,
                           # v0.15 per-pid ownership + lease knobs (see DebugArgs)
                           force: bool = False,
                           wait_s: float = 0.0,
                           # v0.14 unified paging (Layer 3)
                           limit: int = 0,
                           offset: int = 0,
                           cursor: str = "",
                           verbosity: str = "normal",
                           fields: list[str] | None = None,
                           filter: Any = "",
                           summary: bool = False,
                           # Legacy alias for `limit` on list-returning actions.
                           max_results: int = 0,
                           name: str = "") -> str:
        """User-mode debugging via DbgEng: launch/attach, steps, regs, threads, stacks, memory,
        raw dbgeng commands, and event history (from_seq replay).

        Address fields accept int OR '0x...' hex strings."""
        args = {"action": action, "pid": pid, "cmdline": cmdline,
                "address": address,
                # Forward verbosity so finalize honors it (threads/stacktrace/
                # regions row-collapse opt-out via full/raw).
                "verbosity": verbosity}

        async def run() -> str:
            if action not in DEBUG_ACTIONS:
                return _unknown_action("debug_manage", action, DEBUG_ACTIONS, _DEBUG_ACTION_HELP)
            if action == "actions":
                return _actions_help("debug_manage", _DEBUG_ACTION_HELP)
            c = ctx.session.require_client(name)
            # dbgeng attaches to a user pid; module+offset resolves in the
            # attached process's module list.
            addr = await _addr_resolve(address, c, kernel=False,
                                       pid=pid, name="address")
            # v0.15: helpers for the per-pid ownership gate. The lease resource
            # name is namespaced by view so a peer holding kernel-view pid=1234
            # doesn't spuriously block a user-view attach with the same pid.
            view = ctx.session.resolve_view_name(name)
            owner = current_client_id()

            def _lease_key(target_pid: int) -> str:
                return f"debug:{view}:pid={target_pid}"

            def _own_attached_pid() -> int:
                # Any (view, pid) in _attach_leases whose handle we hold is our
                # "currently attached" pid on this view. Zero means no lease —
                # the mutating gate then falls through if the caller passed pid
                # explicitly, or proceeds unguarded (no pid means no key to check).
                if ctx.leases is None:
                    return 0
                for (v, p), h in ctx._attach_leases.items():
                    if v == view and h.owner == owner:
                        return int(p)
                return 0

            async def _gate_mutation(target_pid: int) -> str | None:
                """Return a JSON error string when the caller does not own the
                debug lease on ``target_pid``. Returns ``None`` to proceed.
                No-op when leases are disabled, when force=True, or when the
                target pid is unknown (0) — in that last case we simply have no
                key to check ownership against."""
                if ctx.leases is None or force or target_pid <= 0:
                    return None
                holder = ctx.leases.who_holds(_lease_key(target_pid))
                if holder is None or holder == owner:
                    return None
                return _j({"ok": False, "kind": "foreign_owned",
                           "owner": holder, "pid": target_pid,
                           "resource": _lease_key(target_pid),
                           "hint": "pass force=true to override"})

            if action == "launch":
                result = await c.debug_launch(cmdline, workdir, break_on_entry=True)
                launched_pid = result.get("pid") if isinstance(result, dict) else None
                if (ctx.leases is not None and isinstance(launched_pid, int)
                        and launched_pid > 0):
                    # launch just created the pid; no one else can hold it —
                    # a non-blocking acquire is correct and cheap.
                    acq = await ctx.leases.acquire(
                        _lease_key(launched_pid), owner, wait_s=0)
                    if isinstance(acq, BusyInfo):
                        # Extremely unlikely (stale lease from a prior process
                        # id reuse); surface it rather than silently overwrite.
                        result["lease_warning"] = {
                            "held_by": acq.held_by,
                            "since_iso": acq.since_iso,
                        }
                    else:
                        ctx._attach_leases[(view, launched_pid)] = acq
                        result["lease_owner"] = owner
                        if ctx.clients is not None:
                            await ctx.clients.held_attach_add(
                                owner, view, launched_pid)
                return _j(result)
            if action == "attach":
                target_pid = pid
                if not target_pid and image:
                    procs = await c.mem_processes()
                    want = image.lower()
                    matches = [p for p in procs
                               if want in str(p.get("image_name", "")).lower()]
                    if not matches:
                        return _j({"ok": False,
                                   "error": f"no process matches image {image!r}"})
                    if len(matches) > 1:
                        return _j({"ok": False, "error": "ambiguous image name",
                                   "matches": [p.get("pid") for p in matches]})
                    target_pid = int(matches[0].get("pid", 0))
                if not target_pid:
                    return _j({"ok": False,
                               "error": "attach requires pid or image"})
                if ctx.leases is not None:
                    eff_wait = (wait_s if wait_s > 0
                                else ctx.cfg.leases.attach_timeout_s)
                    acq = await ctx.leases.acquire(
                        _lease_key(target_pid), owner, wait_s=eff_wait)
                    if isinstance(acq, BusyInfo):
                        return _j({"ok": False, "kind": "busy",
                                   "held_by": acq.held_by,
                                   "since_iso": acq.since_iso,
                                   "waited_s": acq.waited_s,
                                   "pid": target_pid,
                                   "resource": _lease_key(target_pid)})
                    result = await c.debug_attach(target_pid)
                    if isinstance(result, dict) and not result.get("ok", True):
                        # Attach failed on the agent side — release the lease
                        # so we don't leak it against a pid we never actually
                        # attached to.
                        await ctx.leases.release(acq)
                        return _j(result)
                    ctx._attach_leases[(view, target_pid)] = acq
                    if ctx.clients is not None:
                        await ctx.clients.held_attach_add(
                            owner, view, target_pid)
                    if isinstance(result, dict):
                        result["lease_owner"] = owner
                    return _j(result)
                return _j(await c.debug_attach(target_pid))
            if action == "detach":
                result = await c.debug_detach(kill)
                if ctx.leases is not None:
                    released: list[int] = []
                    for (v, p), h in list(ctx._attach_leases.items()):
                        if v != view or h.owner != owner:
                            continue
                        await ctx.leases.release(h)
                        ctx._attach_leases.pop((v, p), None)
                        if ctx.clients is not None:
                            await ctx.clients.held_attach_remove(owner, v, p)
                        released.append(p)
                    if released and isinstance(result, dict):
                        result["released_pids"] = released
                return _j(result)
            if action == "continue":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                return _j(await c.debug_continue())
            if action == "step_into":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                return _j(await c.debug_step(over=False, count=count))
            if action == "step_over":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                return _j(await c.debug_step(over=True, count=count))
            if action == "regs":
                regs = await c.debug_regs()
                regs = {k: (hex(v) if isinstance(v, int) else v) for k, v in regs.items()}
                return _hexify_dict(_envelope_ok(
                    regs, kind="regs",
                    tool="debug_manage", action="regs",
                ), add_int_mirror=True)
            if action == "set_regs":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                return _j(await c.debug_set_regs(**json.loads(regs_json or "{}")))
            if action == "threads":
                rows = await c.debug_threads()
                return _list_envelope(
                    rows, tool="debug_manage", action="threads",
                    kind="threads",
                    limit=limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                )
            if action == "stacktrace":
                frames = await c.debug_stacktrace(max_frames)
                # v0.14 Layer 3: unified list envelope. `max_frames` still
                # accepted as an alias for `limit` for one release.
                eff_limit = limit or max_frames
                return _hexify_dict(_list_envelope(
                    frames, tool="debug_manage", action="stacktrace",
                    kind="backtrace",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ), add_int_mirror=True)
            if action == "read":
                data = await c.debug_read(addr, size)
                return _j({"address": hex(addr), "hex": data.hex(), "ascii": _ascii(data)})
            if action == "write":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                return _j(await c.debug_write(addr, bytes.fromhex(data_hex)))
            if action == "regions":
                rows = await c.debug_regions()
                rows = _decode_list(rows, "region")
                eff_limit = limit or max_results
                return _hexify_dict(_list_envelope(
                    rows, tool="debug_manage", action="regions",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ), add_int_mirror=True)
            if action == "events":
                # v0.9.4: Event is a dataclass, not a dict — the prior
                # `e["data"]` raised TypeError the moment any debug
                # event landed in the bus. Access via attribute.
                # v0.23: surface pump liveness — a dead pump means "no
                # events" is a lie; restart it when possible.
                if not ctx.event_pump_alive():
                    ctx.start_event_pump()
                events = [e.data for e in c.bus.recent if e.kind == "debug"]
                if from_seq:
                    events = [e for e in events if int(e.get("seq", 0)) >= from_seq]
                # v0.14 Layer 3: newest-first + uniform paging envelope.
                # Default limit 64 preserves the historical `events[-64:]`
                # window; callers may raise via `limit=` / `max_results=`.
                events = list(reversed(events))
                eff_limit = limit or max_results
                env = _list_envelope(
                    events, tool="debug_manage", action="events",
                    kind="events",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    default_limit=64,
                )
                env["pump_alive"] = ctx.event_pump_alive()
                return _hexify_dict(env, add_int_mirror=True)
            if action == "cmd":
                if not command:
                    return _j({"ok": False, "error": "cmd requires 'command'"})
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                output = await c.dbg_cmd(command)
                return _j({"ok": True, "output": output})
            return _unknown_action("debug_manage", action, DEBUG_ACTIONS, _DEBUG_ACTION_HELP)

        return await _guard(ctx, "debug_manage", action, args, run)
