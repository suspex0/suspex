"""Target tool registration for the suspex0 MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from ...session import VIEW_KINDS
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


# Late-bound AgentClient factory: tests monkey-patch
# ``suspex.mcp.tools.AgentClient`` and expect that patch to reach the
# ``probe_client = AgentClient(...)`` inside ``wait_connectable`` below.
# The star-import above snapshotted ``AgentClient`` into this module's
# globals, so a direct bare reference would bypass the patch. Rebind
# ``AgentClient`` to a factory that resolves the class through the
# package namespace at call time.
def AgentClient(*args, **kwargs):  # noqa: N802 — deliberately shadows the class name
    import suspex.mcp.tools as _pkg
    return _pkg.AgentClient(*args, **kwargs)


def _monitor_poll_s(ctx) -> float:
    """Boot-monitor poll interval.

    WP3 owns ``config.py`` — when a ``monitor.boot_poll_s`` section lands
    it's honored; absent config degrades to the spec default of 5 s
    (default ON — silent BSODs are the pain point being fixed). An
    explicit ``0``/negative is the documented disable.
    """
    mon = getattr(ctx.cfg, "monitor", None)
    if mon is None:
        return 5.0
    try:
        return float(getattr(mon, "boot_poll_s", 5.0))
    except (TypeError, ValueError):
        return 5.0


def _monitor_scan_idle_s(ctx) -> float:
    """Idle cadence for the folded-in minidump-dir watch (60 s default;
    too chatty to run every tick)."""
    mon = getattr(ctx.cfg, "monitor", None)
    try:
        v = float(getattr(mon, "dump_scan_idle_s", 60.0)) if mon else 60.0
    except (TypeError, ValueError):
        return 60.0
    return v if v > 0 else 60.0


def _auto_arm_cfg_status(ctx) -> dict[str, Any]:
    """``watchdog.auto_arm`` config status, for responses that touch the
    auto-arm seam — the hook is config-gated and silent otherwise, so
    callers can tell "protected" from "nobody configured it"."""
    wdg = getattr(ctx.cfg, "watchdog", None)
    spec = (getattr(wdg, "auto_arm", None) or {}) \
        if wdg is not None else {}
    if not spec or not (spec.get("id") or 0):
        return {
            "configured": False,
            "note": "watchdog.auto_arm is UNCONFIGURED — no automatic "
                    "re-arm across driver_load/reboot. Set [watchdog."
                    "auto_arm] {id, deadline_ms, interval_ms} in config.",
        }
    return {
        "configured": True,
        "id": int(spec.get("id") or 0),
        "deadline_ms": int(spec.get("deadline_ms") or 45000),
        "interval_ms": int(spec.get("interval_ms") or 10000),
        "label": str(spec.get("label") or "auto_arm"),
    }


async def _auto_arm_after_load(ctx, client, view: str) -> dict | None:
    """WP3 seam — ``snapshot.auto_arm_after_load(ctx, client, view)``.

    WP1 inserts the call sites per the _shared.md contract (watchdog
    auto-arm after driver_load, plus the post-reboot reconnect path
    where the driver survived); when WP3's snapshot module hasn't landed
    yet — or lacks the hook — the call is a silent no-op. Errors are
    swallowed: re-arming must never fail the driver_load that just
    succeeded. Returns the hook's result dict (or None) so callers can
    surface what happened in their response.
    """
    try:
        from ... import snapshot as _snapshot
    except ImportError:
        return None
    fn = getattr(_snapshot, "auto_arm_after_load", None)
    if fn is None:
        return None
    try:
        res = fn(ctx, client, view)
        import inspect as _inspect
        if _inspect.isawaitable(res):
            res = await res
        return res if isinstance(res, dict) else None
    except Exception:  # noqa: BLE001 — best-effort hook
        return None


async def _monitor_pull_minidump(ctx, view: str, *,
                                 boot_epoch_ms: int = 0) -> dict | None:
    """Best-effort pull+parse of the newest target minidump — shared by
    the boot monitor's on_change/on_scan hooks and the connect path.

    Returns the parse dict (with ``source``), or None when no dump exists
    or the pull failed. Also re-seeds the dir-watch's seen-set from the
    ListDir result so a just-pulled dump doesn't re-notify on the next
    idle scan.
    """
    client = ctx.session.clients.get(view)
    if client is None:
        return None
    try:
        from . import dump as _dump
        got = await _dump._latest_minidump(ctx, client)
        if got is None:
            return None
        entries = got.pop("entries", None) or []
        ctx.session._dump_seen.setdefault(view, set()).update(
            str(e.get("name") or "") for e in entries)
        res = await _dump._parse_artifact(
            ctx, client, got["local_path"],
            boot_epoch_ms=int(boot_epoch_ms or 0))
        res["source"] = {k: got[k] for k in
                         ("remote_path", "local_path", "name",
                          "mtime_unix", "size", "dir")}
        return res
    except Exception:  # noqa: BLE001 — monitor work is best-effort
        return None


def _park_minidump_notice(ctx, view: str, res: dict, *, source: str) -> None:
    """Attach a parsed-dump result to the view's parked boot notice, or
    park a standalone ``kind:"minidump"`` notice when none exists — the
    next status()/wait_boot_change call drains it."""
    pending = ctx.session.pending_boot_notices.get(view)
    if pending is not None:
        pending["minidump"] = res
    else:
        # No ``kind`` field on purpose: boot-change notices discriminate
        # on it; the ``minidump`` key alone marks this as a dump notice.
        ctx.session.pending_boot_notices[view] = {
            "view": view, "source": source, "minidump": res}


def _maybe_start_boot_monitor(ctx, view: str) -> None:
    """Wire the session boot monitor for ``view`` (idempotent) with the
    WP1 hooks: state sweep + parked notice on boot change, opportunistic
    minidump pull, and the ~60 s idle dir-watch."""
    async def _on_change(name: str, change: dict) -> None:
        try:
            change["swept"] = await ctx.sweep_view_state(name)
        except Exception:  # noqa: BLE001 — sweep is best-effort here
            pass
        if change.get("kind") == "new_boot":
            # A service-loaded driver survived the reboot — WP3's hook
            # re-arms watchdog.auto_arm when it reports loaded; a no-op
            # otherwise (absent driver / unconfigured).
            await _auto_arm_after_load(
                ctx, ctx.session.clients.get(name), name)
        res = await _monitor_pull_minidump(
            ctx, name,
            boot_epoch_ms=int(change.get("boot_epoch_ms") or 0))
        if res is not None:
            change["minidump"] = res

    async def _on_scan(name: str, boot_epoch_ms: int) -> None:
        client = ctx.session.clients.get(name)
        if client is None:
            return
        from . import dump as _dump
        dumps = await _dump._list_dumps(client)
        if not dumps:
            return
        seen = ctx.session._dump_seen.setdefault(name, set())
        if not seen:
            # First scan after monitor start — seed without notifying;
            # the dumps may be ancient history.
            seen.update(str(e.get("name") or "") for e in dumps)
            return
        fresh = [e for e in dumps
                 if str(e.get("name") or "") not in seen
                 and (not boot_epoch_ms
                      or int(e.get("mtime_unix") or 0) * 1000
                      >= boot_epoch_ms)]
        seen.update(str(e.get("name") or "") for e in dumps)
        if not fresh:
            return
        res = await _monitor_pull_minidump(
            ctx, name, boot_epoch_ms=boot_epoch_ms)
        if res is not None:
            _park_minidump_notice(ctx, name, res, source="boot_monitor")

    ctx.session.start_boot_monitor(
        view, _monitor_poll_s(ctx), on_change=_on_change,
        on_scan=_on_scan, scan_idle_s=_monitor_scan_idle_s(ctx))


TARGET_ACTIONS = ["connect", "disconnect", "reconnect", "use",
                  "status", "targets",
                  "parity", "driver_load", "driver_unload",
                  "sysinfo", "host_info", "recent_ops",
                  "recent_ops_agent", "crash_state",
                  "wait_connectable", "wait_boot_change",
                  "whoami", "list_peers", "release_peer",
                  "subscribe_peers",
                  # v0.22 discoverability
                  "actions", "tool_index",
                  # v0.28 post-reboot choreography
                  "boot_recover",
                  # v0.30 machine registry (purpose/note/trust metadata)
                  "machines_register", "machines_set",
                  "machines_unregister", "machines",
                  # v1.0.1 Phase 1.6: merged timeline view
                  # (boot identity + agent restarts + watchdog events +
                  #  recent ops + crash state + new minidumps)
                  "timeline",
                  # v1.0.1 Phase 2.4: rediscover a machine's endpoint via
                  # parallel probe of configured/observed/alt_hosts +
                  # hostname resolution; swaps the live view on match.
                  "rediscover"]

_TARGET_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "target_manage(action='actions')"},
    "tool_index": {"one_liner": "global surface map — every registered "
                                "MCP tool + its action enum",
                   "key_args": "none",
                   "example": "target_manage(action='tool_index')"},
    "connect": {"one_liner": "connect a target view — machine= connects "
                             "lab2.kernel (views='both' adds .user)",
                "key_args": "machine|name ('<machine>.<kind>'), host, "
                            "port, token, views, force",
                "example": "target_manage(action='connect', "
                           "machine='lab2', views='both')"},
    "use": {"one_liner": "set this chat's current machine (focus) — "
                         "bare name= calls route there",
            "key_args": "machine ('lab2'|'lab2.user'|'none')",
            "example": "target_manage(action='use', machine='lab2')"},
    "disconnect": {"one_liner": "drop a view's client (refcount-aware)",
                   "key_args": "name",
                   "example": "target_manage(action='disconnect', "
                              "name='kernel')"},
    "reconnect": {"one_liner": "swap a wedged client for a fresh channel, "
                               "keeping co-owner refs",
                  "key_args": "name",
                  "example": "target_manage(action='reconnect', "
                             "name='kernel')"},
    "status": {"one_liner": "session/client status for a view",
               "key_args": "name",
               "example": "target_manage(action='status')"},
    "targets": {"one_liner": "list configured targets + live views",
                "key_args": "none",
                "example": "target_manage(action='targets')"},
    "parity": {"one_liner": "cross-check kernel vs user view byte-for-byte",
               "key_args": "pid, address, read_bytes, samples",
               "example": "target_manage(action='parity', pid=1234, "
                          "address='0x...')"},
    "driver_load": {"one_liner": "load suspex_driver.sys on the target "
                                 "(destructive, permission-gated)",
                    "key_args": "method",
                    "example": "target_manage(action='driver_load')"},
    "driver_unload": {"one_liner": "unload the driver (destructive, "
                                   "permission-gated)",
                      "key_args": "none",
                      "example": "target_manage(action='driver_unload')"},
    "sysinfo": {"one_liner": "OS/build/arch summary from the agent",
                "key_args": "name",
                "example": "target_manage(action='sysinfo')"},
    "host_info": {"one_liner": "host hardware/security-product inventory",
                  "key_args": "name, include_security_products, "
                              "include_hardware",
                  "example": "target_manage(action='host_info')"},
    "recent_ops": {"one_liner": "orchestrator op-log tail (audit trail)",
                   "key_args": "limit, persistent, op_owner, since_iso",
                   "example": "target_manage(action='recent_ops')"},
    "recent_ops_agent": {"one_liner": "agent-side op log (post-crash "
                                      "forensics)",
                         "key_args": "name, limit",
                         "example": "target_manage(action='recent_ops_agent')"},
    "crash_state": {"one_liner": "post-crash state snapshot — breadcrumb "
                                 "+ kernel log tail + newest minidump on "
                                 "new_boot",
                    "key_args": "name, include_dump",
                    "example": "target_manage(action='crash_state')"},
    "timeline": {"one_liner": "merged window: boot identity, agent "
                              "restarts, watchdog arms/fires, recent "
                              "ops tail, crash state, new minidumps",
                 "key_args": "name, since_iso, until_iso, limit",
                 "example": "target_manage(action='timeline', "
                            "since_iso='2026-10-23T00:00:00Z')"},
    "rediscover": {"one_liner": "re-probe a machine's endpoints "
                                "(configured + observed + alt_hosts) in "
                                "parallel; swaps the live view on match",
                   "key_args": "machine, timeout_s",
                   "example": "target_manage(action='rediscover', "
                              "machine='lab2')"},
    "wait_connectable": {"one_liner": "block until a target answers gRPC "
                                      "(keep timeout_s <= 60 — the MCP "
                                      "host's own request deadline kills "
                                      "longer calls; loop instead)",
                         "key_args": "host, port, timeout_s",
                         "example": "target_manage(action='wait_connectable', "
                                    "host='10.0.0.5', timeout_s=60)"},
    "wait_boot_change": {"one_liner": "block until the view's boot identity "
                                      "changes (reboot / agent restart)",
                         "key_args": "name, timeout_s",
                         "example": "target_manage(action='wait_boot_change', "
                                    "timeout_s=120)"},
    "whoami": {"one_liner": "this client's id/owner record",
               "key_args": "none",
               "example": "target_manage(action='whoami')"},
    "list_peers": {"one_liner": "other agents/clients on this orchestrator",
                   "key_args": "none",
                   "example": "target_manage(action='list_peers')"},
    "boot_recover": {"one_liner": "post-reboot choreography in one call — "
                                  "verify/restore the view, sweep stale "
                                  "boot state, load the driver if it did "
                                  "not survive, re-arm watchdog.auto_arm, "
                                  "pull + parse the newest minidump",
                     "key_args": "name, load_driver, method, include_dump, "
                                 "host, port, token",
                     "example": "target_manage(action='boot_recover')"},
    "release_peer": {"one_liner": "release a stale peer's leases "
                                  "(destructive, gated)",
                     "key_args": "peer_id",
                     "example": "target_manage(action='release_peer', "
                                "peer_id='...')"},
    "subscribe_peers": {"one_liner": "peer join/leave feed snapshot",
                        "key_args": "none",
                        "example": "target_manage(action='subscribe_peers')"},
    "machines_register": {"one_liner": "persist a machine (host/ports/token "
                                       "+ purpose/note/trust/tags) in the "
                                       "registry — usable immediately, no "
                                       "restart",
                          "key_args": "machine, host, port, user_port, "
                                      "token, trust, purpose, note, tags",
                          "example": "target_manage(action="
                                     "'machines_register', machine='lab3', "
                                     "host='10.0.2.20', port=50074, "
                                     "token='${LAB3_TOKEN}', trust='lab', "
                                     "purpose='delta rig')"},
    "machines_set": {"one_liner": "update machine metadata/endpoints in the "
                                  "registry (YAML aliases: metadata only "
                                  "unless force=true)",
                     "key_args": "machine, purpose, note, trust, tags, "
                                 "host, port, token, force",
                     "example": "target_manage(action='machines_set', "
                                "machine='lab3', trust='lab', "
                                "note='testsigning on')"},
    "machines_unregister": {"one_liner": "remove a machine from the registry",
                            "key_args": "machine, force",
                            "example": "target_manage(action="
                                       "'machines_unregister', "
                                       "machine='lab3')"},
    "machines": {"one_liner": "one call, when wanted: every machine with "
                              "trust/purpose/note/tags/endpoints + "
                              "connection state",
                 "key_args": "none",
                 "example": "target_manage(action='machines')"},
}


def _attach_machine_info(ctx, cid: str, view: str) -> dict | None:
    """v0.30 one-time machine_info banner: the first time a caller touches
    a machine, its trust/purpose/notes/endpoints ride along on the connect
    response. Subsequent connects to the same machine stay silent — full
    detail is always one call away via target_manage(action='machines').
    Never raises.

    Dedup bucket: callers with a real session id get per-client dedup;
    stateless transports synthesise a rotating ``anon-*`` id per call, so
    those land in ONE stable 'anonymous' bucket (once per machine per
    orchestrator process — the banner is not re-spammed per call)."""
    if not view:
        return None
    try:
        label = ctx.session.machine_of(view)
    except Exception:
        return None
    bucket = cid if (cid and not str(cid).startswith("anon-")) else "anonymous"
    seen = ctx._machine_info_seen.setdefault(bucket, set())
    if label.lower() in seen:
        return None
    seen.add(label.lower())
    try:
        info = ctx.registry.describe(label, cfg=ctx.cfg)
    except Exception:
        return None
    if info is None:
        return None
    try:
        info["computer_name"] = str(
            ctx.session.machine_label(view).get("computer_name") or "")
    except Exception:
        pass
    return info


def register(mcp, ctx: Context) -> None:
    """Register the ``target_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ target_manage --

    class TargetArgs(BaseModel):
        action: str = Field(description="connect|disconnect|reconnect|use|"
                                        "status|targets|parity|"
                                        "driver_load|driver_unload|sysinfo|"
                                        "host_info|"
                                        "recent_ops|recent_ops_agent|"
                                        "crash_state|"
                                        "wait_connectable|wait_boot_change|"
                                        "whoami|list_peers|release_peer|"
                                        "subscribe_peers")
        name: str = Field(default="",
                          description="target view selector: '' = focus/"
                                      "default, 'kernel'|'user'|'<machine>'|"
                                      "'<machine>.<kind>'")
        machine: str = Field(default="",
                             description="machine alias/name — selects the "
                                         "box; '<machine>.<kind>' names a "
                                         "view; use/connect")
        views: str = Field(default="",
                           description="connect only: 'kernel'|'user'|"
                                       "'both', empty='kernel'")
        host: str = ""
        port: int = 0
        token: str = ""
        method: str = Field(default="service", description="driver_load: service|manual_map")
        pid: int = Field(default=0, description="parity: target process")
        samples: int = Field(default=16, description="parity: regions to sample")
        read_bytes: int = Field(default=4096, description="parity: bytes per sample")
        include_security_products: bool = Field(
            default=False,
            description="host_info: enumerate WSC products (heavier, needs SYSTEM)")
        include_hardware: bool = Field(
            default=True,
            description="host_info: CPU brand/cores/mem/hypervisor tag")
        force: bool = Field(
            default=False,
            description="seize/override a foreign-held view, driver "
                        "reference, or peer's holdings")
        focus: bool = Field(
            default=True,
            description="connect only: set this chat's focus to the "
                        "newly-connected view (v1.0.1+); false preserves "
                        "an existing focus")
        peer_id: str = Field(
            default="",
            description="release_peer: the client_id to release")
        timeout_s: float = Field(
            default=15.0,
            description="wait_connectable/wait_boot_change: overall "
                        "deadline (s)")
        include_dump: bool = Field(
            default=False,
            description="crash_state/boot_recover: pull+parse the newest "
                        "minidump (auto when rebooted)")
        load_driver: bool = Field(
            default=True,
            description="boot_recover: load the driver when status "
                        "reports it absent")
        # v0.17 E-2c: persistent recent_ops query surface.
        persistent: bool = Field(
            default=False,
            description="recent_ops: query the on-disk audit JSONL")
        op_method: str = Field(
            default="",
            description="recent_ops(persistent): filter by action/tool")
        op_owner: str = Field(
            default="",
            description="recent_ops(persistent): filter by client_id")
        since_iso: str = Field(
            default="",
            description="recent_ops(persistent): ISO-8601 lower bound")
        until_iso: str = Field(
            default="",
            description="recent_ops(persistent): ISO-8601 upper bound")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def target_manage(action: Annotated[str, Field(json_schema_extra={"enum": TARGET_ACTIONS})],
                            name: str = "", machine: str = "",
                            views: str = "", host: str = "",
                            port: int = 0, token: str = "", method: str = "service",
                            pid: int = 0, samples: int = 16, read_bytes: int = 4096,
                            include_security_products: bool = False,
                            include_hardware: bool = True,
                            force: bool = False,
                            peer_id: str = "",
                            timeout_s: float = 15.0,
                            include_dump: bool = False,
                            load_driver: bool = True,
                            persistent: bool = False,
                            op_method: str = "",
                            op_owner: str = "",
                            since_iso: str = "",
                            until_iso: str = "",
                            purpose: str = "", note: str = "",
                            trust: str = "", tags: str = "",
                            operator: str = "",
                            user_port: int = 0,
                            focus: bool = True) -> str:
        """All views are '<machine>.<view>'; 'use' sets your per-chat current machine.
        Connect/disconnect target views (kernel agent + usermode umagent), status,
        driver load/unload, and kernel-vs-usermode memory parity runs.
        boot_recover runs the whole post-reboot choreography (connect +
        sweep + driver_load + watchdog auto-arm + minidump pull) in one
        call. First use: target_manage(action='tool_index') maps every
        tool; wait_connectable keeps timeout_s <= 60 (MCP host deadline
        kills longer calls — loop instead)."""
        args = {"action": action, "name": name, "machine": machine,
                "host": host, "port": port, "method": method}

        async def run() -> str:
            # v0.22: pure-compute discovery verbs — before any session or
            # client work so they answer even with nothing connected.
            if action == "actions":
                return _actions_help("target_manage", _TARGET_ACTION_HELP)
            if action == "tool_index":
                tools = await mcp.list_tools()
                rows = []
                for t in sorted(tools, key=lambda t: t.name or ""):
                    props = (t.parameters or {}).get("properties", {})
                    act = props.get("action") or {}
                    enum = act.get("enum")
                    rows.append({
                        "tool": t.name,
                        "actions": enum if enum else "<passthrough>",
                        "one_liner": _one_line_desc(t.description or ""),
                    })
                return _j({"ok": True, "count": len(rows), "tools": rows})
            if action == "use":
                # Per-chat focus: bare/empty name= selectors on later calls
                # resolve to this machine. 'none'/'off'/'clear' drops it.
                cid = current_client_id()
                sel = (machine or name or "").strip()
                if sel.lower() in ("none", "off", "clear"):
                    return _j({"ok": True, "focus": None,
                               "cleared": ctx.session.clear_focus(cid)})
                try:
                    # v1.0.1 Phase 1.1: this used to assign to a local
                    # named `focus`, which shadowed the connect-path's
                    # focus= parameter in the enclosing scope. Rename to
                    # keep run()'s closures to the kwarg clean.
                    focus_info = ctx.session.set_focus(cid, sel)
                except RuntimeError as exc:
                    return _j({"ok": False, "kind": "bad_target",
                               "error": str(exc)})
                # set_focus's dict already carries machine/kind/view plus
                # the machine_label fields (computer_name, endpoint).
                return _j({"ok": True, "client_id": cid,
                           "focus": focus_info,
                           "computer_name": focus_info.get("computer_name", ""),
                           "hint": ("bare/empty name= selectors now resolve "
                                    "to this machine; target_manage(action="
                                    "'use', machine='none') clears")})
            if action in ("machines_register", "machines_set",
                          "machines_unregister", "machines"):
                # v0.30 machine registry — persisted in
                # artifacts/targets.json, hot-reloadable, no restart.
                reg = ctx.registry
                alias = (machine or name or "").strip()
                tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                if action == "machines":
                    rows: list[dict] = []
                    seen: set[str] = set()

                    def _row(a: str) -> dict:
                        r = reg.describe(a, cfg=ctx.cfg) or {"machine": a}
                        r["connected_views"] = sorted(
                            ctx.session.machines().get(
                                str(r.get("machine") or a), []))
                        return r

                    for a in list(reg.all().keys()) + list(
                            (getattr(ctx.cfg, "machines", None) or {}).keys()):
                        if a.lower() not in seen:
                            seen.add(a.lower())
                            rows.append(_row(a))
                    for m in sorted(ctx.session.machines()):
                        if m.lower() not in seen:
                            seen.add(m.lower())
                            rows.append(_row(m))
                    if not rows and getattr(ctx.cfg.target, "host", ""):
                        rows.append(_row("default"))
                    return _j({"ok": True, "count": len(rows),
                               "machines": rows,
                               "min_trust_actuator": getattr(
                                   ctx.cfg.security, "min_trust_actuator",
                                   "untrusted")})
                if not alias and action == "machines_set":
                    # empty selector annotates the caller's machine
                    try:
                        alias = ctx.session.machine_of(
                            ctx.session.resolve_view_name(""))
                    except Exception:
                        alias = "default"
                if not alias:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"{action}: machine= (alias) "
                                        "is required"})
                # v1.0.1 Phase 1.1: alias hygiene. If the caller registers
                # a machine whose alias looks like an IPv4 (or ends in a
                # digit cluster that matches a live view's computer_name
                # suffix), warn: this is the k205/k207/k206 litter — the
                # same box ends up with multiple aliases because the IP
                # changed between runs. The call still succeeds; the
                # response's warnings[] names the live alias instead.
                dup_hint: str | None = None
                if action == "machines_register":
                    def _looks_like_ip(s: str) -> bool:
                        parts = s.split(".")
                        return (len(parts) == 4
                                and all(p.isdigit() and 0 <= int(p) <= 255
                                        for p in parts))
                    def _digit_tail(s: str) -> str:
                        i = len(s)
                        while i > 0 and s[i - 1].isdigit():
                            i -= 1
                        return s[i:]
                    live_label: str | None = None
                    tail = _digit_tail(alias)
                    for key in ctx.session.clients:
                        mi = ctx.session.machine_label(key)
                        cn = str(mi.get("computer_name") or "")
                        m_label = str(mi.get("machine") or "")
                        if not cn:
                            continue
                        if _looks_like_ip(alias) and alias in (
                                getattr(ctx.session.clients[key],
                                        "endpoint", "") or ""):
                            live_label = m_label
                            break
                        if tail and len(tail) >= 2 and cn.lower().endswith(
                                tail.lower()):
                            live_label = m_label
                            break
                    if live_label and live_label.lower() != alias.lower():
                        dup_hint = (f"alias {alias!r} looks like it points "
                                    f"at a machine already known as "
                                    f"{live_label!r}; consider "
                                    f"target_manage(action='machines_set', "
                                    f"machine={live_label!r}, host=...) "
                                    "instead of a fresh alias — multiple "
                                    "aliases for one box fragment history")
                try:
                    if action == "machines_register":
                        info = reg.register(
                            alias, host=host, kernel_port=port,
                            user_port=user_port, token=token,
                            trust=trust, purpose=purpose, note=note,
                            operator=operator, tags=tag_list,
                            force=bool(force))
                    elif action == "machines_set":
                        info = reg.set(
                            alias, host=host or None,
                            kernel_port=port or None,
                            user_port=user_port or None,
                            token=token or None,
                            trust=trust or None, purpose=purpose or None,
                            note=note or None, operator=operator or None,
                            tags=tag_list if tags else None,
                            force=bool(force))
                    else:
                        removed = reg.unregister(alias, force=bool(force))
                        return _j({"ok": bool(removed), "machine": alias,
                                   "removed": removed})
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": str(exc)})
                out: dict[str, Any] = {"ok": True, "machine_info": info}
                if dup_hint:
                    out["warnings"] = [dup_hint]
                return _j(out)
            if action == "connect":
                cid = current_client_id()

                async def _connect_one(sel: str) -> dict:
                    """One view connect + post-connect bookkeeping. The
                    stored key (``status['view']``) is '<machine>.<kind>' —
                    *sel* is only the requested selector."""
                    # connect() resolves the endpoint via target_for +
                    # check_target internally now.
                    status = await ctx.session.connect(
                        host or None, port or None, token or None,
                        name=sel, machine=machine or None,
                        owner=cid, force=bool(force),
                        focus=bool(focus))
                    view = status.get("view") or sel
                    status["resolved_address"] = getattr(
                        ctx.session.clients.get(view), "endpoint", "")
                    status["target_name"] = sel
                    # v14: connect is where a post-reboot reconnect lands —
                    # sweep the orphaned follows/shells/handles the moment
                    # the boot change is confirmed, same as the status path.
                    change = status.get("boot_change")
                    if change:
                        status["swept"] = await ctx.sweep_view_state(
                            change.get("view") or view)
                        status["warnings"] = [
                            f"view {view!r}: "
                            f"{change['kind'].replace('_', ' ')} detected — "
                            "stale shells/follows/watchdog arms/detached "
                            "handles were swept; resX artifacts predate "
                            "this boot." +
                            (" Reload the driver before kernel ops."
                             if change["kind"] == "new_boot" else "")]
                    if change and change.get("kind") == "new_boot":
                        # _shared contract: a service-loaded driver survives
                        # the reboot the caller just reconnected through —
                        # WP3's hook re-arms watchdog.auto_arm when the
                        # driver reports loaded. No-op when the driver is
                        # absent or auto_arm is unconfigured.
                        await _auto_arm_after_load(
                            ctx, ctx.session.clients.get(view), view)
                    if view == ctx.session.primary:
                        ctx.start_event_pump()
                        # v0.25 WP1: timely reboot detection — the status
                        # poll inside the monitor makes a silent BSOD
                        # surface as a parked new_boot notice on the next
                        # status call, instead of waiting for someone to
                        # notice lazily.
                        _maybe_start_boot_monitor(ctx, view)
                    if change and view == ctx.session.primary:
                        # The connect path just saw the reboot — the
                        # monitor (just started) won't re-fire for an
                        # identity it already recorded, so kick the
                        # best-effort minidump pull here; the parse parks
                        # as a pending notice and the next status() drains it.
                        async def _pull() -> None:
                            res = await _monitor_pull_minidump(
                                ctx, view,
                                boot_epoch_ms=int(
                                    change.get("boot_epoch_ms") or 0))
                            if res is not None:
                                _park_minidump_notice(ctx, view, res,
                                                      source="connect")
                        try:
                            asyncio.create_task(_pull())
                        except Exception:  # noqa: BLE001 — best-effort
                            pass
                    if ctx.clients is not None:
                        await ctx.clients.register(cid, transport="http")
                        await ctx.clients.refcount_add(cid, view)
                    if not ctx.get_current_session_id(cid):
                        ctx.set_current_session_id(
                            cid, ctx.ledger.start_session(
                                ctx.session.cfg.target_endpoint))
                    # v1.0.1 Phase 1.2 + 2.1: self-heal — the endpoint that
                    # just answered is now registry-known for this machine,
                    # and every IPv4 the agent sees on an up-adapter joins
                    # it (so a flap to another lease self-heals in one
                    # step). YAML aliases participate (observed_endpoints
                    # is pure learned metadata, never overrides reviewed
                    # endpoints).
                    try:
                        ep = str(status.get("resolved_address") or "")
                        mlabel = ctx.session.machine_of(view)
                        boot_ms = int(status.get("boot_epoch_ms") or 0)
                        ep_p = 0
                        if ":" in ep:
                            eh, ep_s = ep.rsplit(":", 1)
                            try:
                                ep_p = int(ep_s)
                            except ValueError:
                                ep_p = 0
                            if eh and ep_p:
                                ctx.registry.record_observed_endpoint(
                                    mlabel, host=eh, port=ep_p,
                                    boot_epoch_ms=boot_ms)
                        # If the agent reports an ipv4[] list on Status,
                        # record every live address under the same port.
                        for a in (status.get("ipv4") or []):
                            if isinstance(a, dict) and a.get("up") \
                                    and a.get("address"):
                                ctx.registry.record_observed_endpoint(
                                    mlabel, host=str(a["address"]),
                                    port=ep_p or 0,
                                    boot_epoch_ms=boot_ms)
                    except Exception:  # noqa: BLE001 — self-heal is best-effort
                        pass
                    return status

                sel = (machine or name or "").strip()
                views_l = (views or "").strip().lower()
                if views_l in ("both", "all"):
                    # Fan out over every view kind; a kind whose endpoint
                    # can't be resolved (KeyError) is skipped, not fatal.
                    out: dict[str, Any] = {"ok": True, "views": {}}
                    for kind in VIEW_KINDS:
                        try:
                            vst = await _connect_one(
                                f"{sel}.{kind}" if sel else kind)
                            out["views"][kind] = vst
                            if "machine_info" not in out:
                                mi = _attach_machine_info(
                                    ctx, cid, str(vst.get("view") or ""))
                                if mi:
                                    out["machine_info"] = mi
                        except KeyError as exc:
                            out["views"][kind] = {"ok": False,
                                                  "skipped": True,
                                                  "error": str(exc)}
                        except Exception as exc:  # noqa: BLE001 — per-view
                            out["ok"] = False
                            out["views"][kind] = {"ok": False,
                                                  "error": str(exc)}
                    return _j(out)
                kind = views_l if views_l in VIEW_KINDS else ""
                status = await _connect_one(
                    f"{sel}.{kind}" if sel and kind else sel or kind)
                mi = _attach_machine_info(ctx, cid, str(status.get("view") or ""))
                if mi:
                    status["machine_info"] = mi
                return _j(status)
            if action == "disconnect":
                cid = current_client_id()
                # Empty name keeps the historical 'release every view I
                # hold' behavior; a selector resolves to its view key.
                result = await ctx.session.disconnect(
                    ctx.session.resolve_view_name(name) if name else None,
                    owner=cid)
                if ctx.clients is not None:
                    for n in list(result.get("disconnected", [])) + \
                             list(result.get("partial_release", [])):
                        await ctx.clients.refcount_remove(cid, n)
                return _j(result)
            if action == "reconnect":
                # v0.17 E-3b: replace a wedged / stale client for a view
                # without going through the disconnect → connect dance
                # (which drops all co-owner refs). The current endpoint +
                # co-owner refcounts are preserved; the gRPC channel is
                # torn down and a fresh AgentClient is built.
                #
                # Anything in flight on the old channel is cancelled by
                # ``close()`` — a caller should wait for its prior call
                # to error out before invoking reconnect.
                cid = current_client_id()
                view = ctx.session.resolve_view_name(name)
                old_client = ctx.session.clients.get(view)
                if old_client is None:
                    return _j({"ok": False,
                               "kind": "no_target",
                               "error": (f"reconnect: view {view!r} is "
                                         "not currently connected"),
                               "hint": (f"call target_manage(action="
                                        f"'connect', name={view!r}) first")})
                # Preserve endpoint + co-owner refs so the fresh client
                # points at the same target and other peers keep their
                # references. host/port/token defaults fall back to
                # config via Session.connect().
                endpoint = getattr(old_client, "endpoint", "") or ""
                r_host, r_port = "", 0
                if ":" in endpoint:
                    try:
                        r_host, port_s = endpoint.rsplit(":", 1)
                        r_port = int(port_s)
                    except ValueError:
                        r_host, r_port = "", 0
                old_refs = dict(ctx.session.refs.get(view, {}))
                # Tear down: close the channel + drop bookkeeping.
                try:
                    await old_client.close()
                except Exception:  # noqa: BLE001 - best-effort teardown
                    pass
                ctx.session.clients.pop(view, None)
                ctx.session.owners.pop(view, None)
                ctx.session.refs.pop(view, None)
                # Fresh connect for the current owner. The token is always
                # a string (never None): a learned-label machine has no
                # config TargetConfig for connect()'s `t.token` fallback
                # to dereference, and the old client's token is the one
                # that was actually in effect.
                new_status = await ctx.session.connect(
                    (host or r_host) or None,
                    (port or r_port) or None,
                    token or getattr(old_client, "token", "") or "",
                    name=view,
                    owner=cid,
                    force=False,
                )
                # Preserve co-owner refs — a peer that held a ref before
                # reconnect keeps it; only its next call sees the new
                # channel. This is by design: a peer that had a live
                # co-lease shouldn't get a spurious "not connected"
                # error just because someone else pressed reconnect.
                refs = ctx.session.refs.setdefault(view, {})
                for owner_id, count in old_refs.items():
                    if owner_id == cid:
                        continue
                    refs[owner_id] = count
                # v14: a reconnect across a reboot carries the boot_change
                # marker in new_status — sweep now, while the caller still
                # expects churn, rather than on the next status call.
                change = new_status.get("boot_change")
                swept = None
                if change:
                    swept = await ctx.sweep_view_state(view)
                data = {"action": "reconnect", "view": view,
                        "reconnected": True,
                        "endpoint": getattr(
                            ctx.session.clients.get(view), "endpoint", ""),
                        "coowner_refs": {o: c for o, c in old_refs.items()
                                          if o != cid},
                        "status": new_status}
                if swept is not None:
                    data["swept"] = swept
                mi = _attach_machine_info(ctx, cid, view)
                if mi:
                    data["machine_info"] = mi
                env = _envelope_ok(
                    data,
                    kind=_resolve_kind("target_manage", "reconnect"),
                    tool="target_manage",
                    action="reconnect",
                )
                from .._envelope import warn as _envelope_warn
                _envelope_warn(env,
                    f"target_manage(reconnect): view {view!r} was torn "
                    f"down and re-established; anything in flight on the "
                    "old channel was cancelled. Co-owner refcounts "
                    "preserved.")
                if change:
                    _envelope_warn(env,
                        f"view {view!r}: {change['kind'].replace('_', ' ')} "
                        "detected — shells/follows/watchdog arms/detached "
                        "handles from the previous lifetime are dead" +
                        ("; reload the driver before kernel ops."
                         if change["kind"] == "new_boot" else "."))
                return _j(env)
            if action == "targets":
                # Phase 0.2: configured endpoint + last_seen_ts per view so
                # reconnect after a wedge is deterministic. Backwards-compat:
                # `connected` list preserved for callers that only cared
                # about which names are up.
                machines = {
                    m: {"computer_name": ctx.session.machine_label(
                            keys[0]).get("computer_name", ""),
                        "views": keys}
                    for m, keys in ctx.session.machines().items()}
                return _j({"ok": True,
                           "connected": sorted(ctx.session.clients),
                           "primary": ctx.session.primary,
                           "views": ctx.session.all_views(),
                           "machines": machines,
                           "focus": ctx.session.focus_of(
                               current_client_id())})
            if action == "status":
                view = ctx.session.resolve_view_name(name)
                client = ctx.session.require_client(view)
                s = await client.status()
                # v14: boot-epoch tracking. A changed boot_epoch_ms means the
                # target rebooted — driver state, shells, follows, watchdog
                # arms and detached handles from the last lifetime are all
                # orphaned; a changed agent_instance_id on the same boot is
                # an agent restart (same orphans minus the driver). Either
                # way the stale orchestrator-side state gets swept so stale
                # session_id / handle_id errors stop masquerading as live
                # resources.
                view_name = view
                change = ctx.session.note_boot_identity(view_name, s)
                if change:
                    s["swept"] = await ctx.sweep_view_state(view_name)
                    s["boot_change"] = change
                    kind = change["kind"]
                    s["warnings"] = [
                        f"view {view_name!r}: {kind.replace('_', ' ')} "
                        "detected — every shell, follow, watchdog arm and "
                        "detached handle from the previous lifetime is dead; "
                        "spilled resX artifacts predate this boot. "
                        + ("Reload the driver before kernel ops."
                           if kind == "new_boot" else
                           "Reconnect debug sessions; driver state survived.")
                    ]
                # v0.25 WP1: drain notices parked by the boot monitor — a
                # reboot the monitor saw first surfaces here exactly as if
                # the lazy detector above had caught it (sweep already ran
                # inside the monitor); a standalone minidump notice attaches
                # its parsed dump under `minidump`.
                pending = ctx.session.pending_boot_notices.pop(view_name, None)
                if pending is not None:
                    if change is None and pending.get("kind") in (
                            "new_boot", "agent_restart"):
                        s["boot_change"] = pending
                        s["warnings"] = [
                            f"view {view_name!r}: "
                            f"{pending['kind'].replace('_', ' ')} detected "
                            "by the boot monitor — stale shells/follows/"
                            "watchdog arms/detached handles were swept at "
                            "detection time; resX artifacts predate this "
                            "boot."
                            + (" Reload the driver before kernel ops."
                               if pending["kind"] == "new_boot" else "")]
                    if pending.get("minidump") is not None:
                        s["minidump"] = pending["minidump"]
                # Phase 0.1: honest driver-absent envelope on driver-sourced
                # fields so the LLM stops treating pre-load defaults as truth.
                driver_present = str(s.get("driver_state", "")).upper() in (
                    "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
                s["driver_present"] = driver_present
                if not driver_present:
                    for field_name in ("testsigning", "hvci", "secureboot",
                                       "patchguard_expected", "driver_version"):
                        if field_name in s and not isinstance(s[field_name], dict):
                            s[field_name] = {
                                "value": s[field_name],
                                "confidence": "driver-absent-default",
                                "note": "value from agent bring-up path; "
                                        "only trustworthy after a successful driver_load",
                            }
                # v0.13 dev-feedback #2: promote key host_info fields into
                # the slim status response so a first `status` call shows
                # HVCI, MSFT-driver-blocklist, KVA shadow, PC uptime, and
                # the suspex-driver health block. These require agent v8+
                # for the HostInfo RPC; fall back cleanly if unavailable.
                try:
                    hi = await client.host_info(include_hardware=False)
                except Exception as exc:
                    hi = {"ok": False, "error": str(exc)}
                if hi.get("ok"):
                    sec = hi.get("security") or {}
                    uptime = hi.get("uptime") or {}
                    def _val(pair, default=None):
                        return pair.get("value", default) if isinstance(pair, dict) else pair
                    # HVCI: overwrite the driver-absent placeholder with the
                    # host_info-verified value when we have one (registry /
                    # api / driver — never the slim default).
                    hvci_pair = sec.get("hvci")
                    if isinstance(hvci_pair, dict) and hvci_pair.get("source") not in (
                            None, "unknown", "driver-absent-default"):
                        s["hvci"] = hvci_pair
                    # Newly-surfaced fields:
                    s["memory_integrity"] = hvci_pair       # alias — user-facing name
                    s["driver_blocklist_on"] = sec.get("driver_blocklist_on")
                    s["kva_shadow"] = sec.get("kva_shadow")  # populated when agent has the probe
                    s["vbs_enabled"] = sec.get("vbs_enabled")
                    s["credential_guard"] = sec.get("credential_guard")
                    s["lsa_protected"] = sec.get("lsa_protected")
                    s["kernel_debugger"] = sec.get("kernel_debugger")
                    s["secureboot"] = sec.get("secureboot") if isinstance(sec.get("secureboot"), dict) \
                                       else s.get("secureboot")
                    s["pc_uptime_ms"] = uptime.get("pc_uptime_ms")
                    s["service_uptime_ms"] = uptime.get("service_uptime_ms")
                    s["patchguard_state"] = sec.get("patchguard_state")
                    # Multi-machine: self-label the reply and refresh the
                    # cached identity so machine-alias resolution stays
                    # current when a box's address changes.
                    s["machine"] = ctx.session.machine_of(view)
                    s["computer_name"] = (
                        (hi.get("identity") or {}).get("computer_name")
                        or "")
                    ctx.session.note_machine_identity(
                        view, computer_name=s["computer_name"],
                        endpoint=getattr(client, "endpoint", ""))
                else:
                    s["host_info_hint"] = ("HostInfo RPC unavailable (agent < v8?) — "
                                            "run target_manage(action='host_info') for the "
                                            "richer view once the agent is rebuilt")
                # v0.13 dev-feedback #1: suspex-driver-specific health.
                # Explains WHY driver_state might say DRIVER_ABSENT.
                try:
                    from .._suspex_driver_probe import probe_suspex_driver
                    s["suspex_driver_health"] = await probe_suspex_driver(
                        client, driver_state=s.get("driver_state"))
                except Exception as exc:
                    s["suspex_driver_health"] = {"ok": False,
                                                  "error": f"probe failed: {exc}"}
                # v0.17 E-3c: degraded-view warn banner. Sweep every
                # connected view and warn on any that has been silent
                # longer than SUSPX_DEGRADED_WARN_MS (default 5000 ms).
                # A stale channel doesn't necessarily mean anything is
                # broken — the caller may just not have used it — but
                # when it happens on the primary view during active
                # tool use it's a strong hint that a reconnect is due.
                try:
                    warn_ms = int(os.environ.get(
                        "SUSPX_DEGRADED_WARN_MS") or 5000)
                except (TypeError, ValueError):
                    warn_ms = 5000
                degraded = []
                for v in ctx.session.all_views():
                    if not v.get("connected"):
                        continue
                    idle_s = v.get("seconds_since_last_op") or 0
                    if idle_s and idle_s > (warn_ms / 1000.0):
                        degraded.append((v["name"], idle_s))
                if not degraded:
                    return _j(s)
                # Build the envelope explicitly so we can attach warns
                # via _envelope.warn() — a raw dict returned by _j would
                # lose the warnings slot (envelope_from_result packs
                # extras under `data`).
                env = _envelope_ok(
                    s,
                    kind=_resolve_kind("target_manage", "status"),
                    tool="target_manage",
                    action="status",
                )
                from .._envelope import warn as _envelope_warn
                for vname, idle_s in degraded:
                    _envelope_warn(env,
                        f"view {vname!r} has been silent for {idle_s}s — "
                        f"consider target_manage(action='reconnect', "
                        f"name={vname!r}) if calls to it are hanging.")
                return _j(env)
            if action == "driver_load":
                cid = current_client_id()
                view = ctx.session.resolve_view_name(name)
                if ctx.leases is None:
                    result = await ctx.session.require_client(view).driver_load(method=method)
                    merged = await _merge_driver_state(ctx, result, verb="driver_load",
                                                       view=view)
                    if merged.get("ok") is not False:
                        # _shared contract: WP3's watchdog auto-arm hook.
                        arm = await _auto_arm_after_load(
                            ctx, ctx.session.clients.get(view),
                            view)
                        merged["watchdog_auto_arm"] = (
                            arm if arm is not None
                            else _auto_arm_cfg_status(ctx))
                    return _j(merged)
                wait_s = getattr(ctx.cfg.leases, "driver_timeout_s", 10.0)
                lease = await ctx.leases.acquire("driver", cid, wait_s=wait_s)
                if isinstance(lease, BusyInfo):
                    return _j({"ok": False, "kind": "busy",
                               "error": f"driver_load: lease held by {lease.held_by}",
                               "held_by": lease.held_by,
                               "since_iso": lease.since_iso,
                               "waited_s": lease.waited_s,
                               "hint": "another peer is currently loading/unloading "
                                       "the driver; retry, or use target_manage(action="
                                       "'list_peers') to see who holds it"})
                try:
                    result = await ctx.session.require_client(view).driver_load(method=method)
                    merged = await _merge_driver_state(ctx, result, verb="driver_load",
                                                       view=view)
                    if merged.get("ok") is not False:
                        arm = await _auto_arm_after_load(
                            ctx, ctx.session.clients.get(view),
                            view)
                        merged["watchdog_auto_arm"] = (
                            arm if arm is not None
                            else _auto_arm_cfg_status(ctx))
                    return _j(merged)
                finally:
                    await ctx.leases.release(lease)
            if action == "driver_unload":
                cid = current_client_id()
                view = ctx.session.resolve_view_name(name)
                refs = ctx.session.refs.get(view, {})
                other_owners = [o for o in refs if o != cid]
                # v0.24: session.refs and the ClientRegistry can disagree
                # (crashed peer, release_peer leftover) — a peer the
                # registry shows as user-view-only (umagent) must not block
                # a driver unload. Cross-check every ref-holder against
                # the live registry before refusing.
                blocking: list[str] = []
                stale_refs: list[str] = []
                peer_holds: dict[str, dict] = {}
                for o in other_owners:
                    info = (await ctx.clients.get(o)
                            if ctx.clients is not None else None)
                    view_n = int(info.refs.get(view, 0)) if info else 0
                    attach = sorted(p for v, p in (info.held_attach or set())
                                    if v == view) if info else []
                    if view_n > 0 or attach:
                        blocking.append(o)
                        peer_holds[o] = {
                            "view_refs": view_n,
                            "held_attach_pids": attach,
                        }
                    else:
                        stale_refs.append(o)
                if blocking and not force:
                    return _j({"ok": False, "kind": "busy",
                               "error": "driver_unload: kernel view still in use "
                                        "by other peers",
                               "in_use_by": blocking,
                               "held_by": peer_holds,
                               "stale_refs_ignored": stale_refs,
                               "hint": "wait for peers to disconnect, or pass "
                                       "force=true to override (they will lose "
                                       "the kernel view on the next call)"})
                for o in stale_refs:
                    # Registry agrees the peer is gone — drop the dead ref so
                    # session.refs stops blocking future unloads.
                    ctx.session.drop_view_ref(view, o)
                if stale_refs and not blocking:
                    log.info("driver_unload: pruned stale kernel-view refs "
                             "from %s (registry shows no kernel view)",
                             stale_refs)
                if ctx.leases is None:
                    result = await ctx.session.require_client(view).driver_unload()
                    return _j(await _merge_driver_state(ctx, result, verb="driver_unload",
                                                        view=view))
                wait_s = getattr(ctx.cfg.leases, "driver_timeout_s", 10.0)
                lease = await ctx.leases.acquire("driver", cid, wait_s=wait_s)
                if isinstance(lease, BusyInfo):
                    return _j({"ok": False, "kind": "busy",
                               "error": f"driver_unload: lease held by {lease.held_by}",
                               "held_by": lease.held_by,
                               "since_iso": lease.since_iso,
                               "waited_s": lease.waited_s,
                               "hint": "another peer is currently loading/unloading "
                                       "the driver; retry, or use target_manage(action="
                                       "'list_peers') to see who holds it"})
                try:
                    result = await ctx.session.require_client(view).driver_unload()
                    return _j(await _merge_driver_state(ctx, result, verb="driver_unload",
                                                        view=view))
                finally:
                    await ctx.leases.release(lease)
            if action == "sysinfo":
                view = ctx.session.resolve_view_name(name)
                s = await ctx.session.require_client(view).status()
                driver_present = str(s.get("driver_state", "")).upper() in (
                    "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
                def _honest(v):
                    if driver_present:
                        return v
                    return {"value": v, "confidence": "driver-absent-default",
                            "note": "load the driver before trusting this field"}
                return _j({
                    "ok": True,
                    "driver_present": driver_present,
                    "os": s.get("os_version"),
                    "build": s.get("os_build"),
                    "testsigning": _honest(s.get("testsigning")),
                    "hvci": _honest(s.get("hvci")),
                    "driver_state": s.get("driver_state"),
                    "patchguard_expected": _honest(s.get("patchguard_expected")),
                    "agent_uptime_ms": s.get("agent_uptime_ms"),
                })
            if action == "host_info":
                # v8: broad target-machine fingerprint. Grouped payload with
                # identity / os / security / hardware / uptime, and each
                # posture bit is a {value, source} pair — we lift that into
                # the confidence-envelope shape callers already know from
                # sysinfo. Older agents come back with a clean ok:false so
                # the LLM sees a real gap instead of a fabricated default.
                view = ctx.session.resolve_view_name(name)
                client = ctx.session.require_client(view)
                raw = await client.host_info(
                    include_security_products=include_security_products,
                    include_hardware=include_hardware,
                )
                if not raw.get("ok"):
                    return _j(raw)
                sec = raw.get("security") or {}
                def _wrap(pair):
                    if not isinstance(pair, dict):
                        return pair
                    src = pair.get("source") or "unknown"
                    confidence = {
                        "driver": "driver-verified",
                        "registry": "usermode-registry",
                        "api": "usermode-api",
                        "unknown": "unknown",
                    }.get(src, src)
                    return {"value": pair.get("value"),
                            "confidence": confidence,
                            "source": src}
                wrapped_security = {k: (_wrap(v) if isinstance(v, dict) else v)
                                    for k, v in sec.items()}
                raw["security"] = wrapped_security
                return _j(raw)
            if action == "parity":
                # The kernel/user pair always comes from ONE machine —
                # name= (or the caller's focus) picks which.
                view = ctx.session.resolve_view_name(name)
                p_machine = ctx.session.machine_of(view)
                kernel_client = ctx.session.require_client(
                    ctx.session._view_for(p_machine, "kernel"))
                user_client = ctx.session.require_client(
                    ctx.session._view_for(p_machine, "user"))
                report = await run_parity(kernel_client, user_client, pid,
                                          samples=samples, read_bytes=read_bytes)
                severity, reason = verdict(report)
                cid = current_client_id()
                sid = ctx.get_current_session_id(cid) or ctx.ledger.start_session(
                    ctx.session.cfg.target_endpoint)
                if not ctx.get_current_session_id(cid):
                    ctx.set_current_session_id(cid, sid)
                fid = ctx.ledger.record(
                    sid, severity,
                    f"parity pid={pid}: kernel vs usermode",
                    reason, refs="parity_check", agent_id=cid,
                )
                ctx.ledger.add_evidence(fid, "parity_report", _j(report))
                # v0.18 breadcrumb: attribute the parity run itself
                try:
                    ctx.ledger.event(
                        "target_manage", "parity", agent_id=cid, session_id=sid,
                        target=ctx.session.cfg.target_endpoint,
                        summary=f"pid={pid} verdict={severity} finding={fid}",
                    )
                except Exception:  # pragma: no cover
                    pass
                return _j({"ok": True, "finding_id": fid, "severity": severity,
                           "reason": reason, "summary": report["summary"],
                           "checks": report["checks"][:8]})
            if action == "recent_ops":
                # v0.17 E-2c: persistent=True routes the query to the
                # on-disk JSONL sink so callers can reconstruct the
                # tool history across orchestrator restarts and
                # per-client ring wipes. `op_method` / `op_owner` /
                # since_iso / until_iso filter; `samples` caps rows.
                if persistent:
                    from ...audit import query as _audit_query
                    limit = int(samples or 500)
                    if limit <= 0:
                        limit = 500
                    rows = _audit_query(
                        session_id=ctx.session.audit_session_id(),
                        owner=op_owner or None,
                        method=op_method or None,
                        since_iso=since_iso or None,
                        until_iso=until_iso or None,
                        limit=limit,
                    )
                    return _j({"ok": True, "persistent": True,
                                "session_id": ctx.session.audit_session_id(),
                                "count": len(rows),
                                "ops": rows})
                # Post-crash forensics: what did the orchestrator send to
                # the agent right before it wedged? Doesn't require the
                # agent to be reachable now.
                client = ctx.session.get_client(name) if hasattr(
                    ctx.session, "get_client") else None
                if client is None:
                    try:
                        client = ctx.session.require_client(name)
                    except Exception:
                        client = None
                # Fall back to the primary target when name isn't connected
                # (so 'recent_ops' answers even mid-outage on the alias).
                if client is None:
                    for view in ctx.session.clients.values() if hasattr(
                            ctx.session, "clients") else []:
                        client = view
                        break
                if client is None:
                    return _j({"ok": False,
                               "error": "no client instance available; "
                                        "the ring is per-client. Try after a connect."})
                return _j({"target": getattr(client, "endpoint", "?"),
                           "ops": client.recent_ops(samples or 32)})
            if action == "recent_ops_agent":
                # Persistent breadcrumb on the target's disk. Survives an
                # agent crash — `prior.status_kind == "wedged"` marks the
                # calls in flight when the previous lifetime died.
                view = ctx.session.resolve_view_name(name)
                try:
                    client = ctx.session.require_client(view)
                except Exception as exc:
                    return _j({"ok": False, "error": str(exc)})
                return _j(await client.recent_ops_agent(
                    limit=samples or 32, include_prior=True))
            if action == "crash_state":
                # Phase 0.3: one-call post-mortem. Composes recent_ops_agent
                # (agent-side persistent breadcrumb) + kernel log tail + a
                # reboot-detection heuristic (agent_uptime vs last-seen delta).
                import time as _time
                view = ctx.session.resolve_view_name(name)
                out: dict[str, Any] = {"ok": True, "target": view}
                # 1. recent_ops_agent (durable). If agent < v5, degrades cleanly.
                try:
                    c = ctx.session.require_client(view)
                    r = await c.recent_ops_agent(limit=samples or 32,
                                                 include_prior=True)
                    out["breadcrumb"] = r
                    now = _time.time()
                    last_op = c.last_op_ts
                    # If agent uptime_ms < (now - last_op)*1000, the agent
                    # restarted between our last call and now. Attach a hint.
                    if r.get("agent_start_epoch_ms") and last_op:
                        agent_start_s = r["agent_start_epoch_ms"] / 1000.0
                        if agent_start_s > last_op:
                            out["rebooted"] = True
                            out["wedge_window_s"] = round(agent_start_s - last_op, 2)
                        else:
                            out["rebooted"] = False
                except Exception as exc:
                    out["breadcrumb_error"] = str(exc)
                # 2. kernel log tail (32 KiB by default; read_bytes overrides).
                tail_bytes = (read_bytes if read_bytes and read_bytes > 0
                              else 32 * 1024)
                log_path = r"C:\Users\Public\Desktop\suspex_kernel.log"
                try:
                    c = ctx.session.require_client(view)
                    out["kernel_log_tail"] = await c.file_tail(
                        log_path, bytes_wanted=tail_bytes, line_align=True)
                except Exception as exc:
                    out["kernel_log_error"] = str(exc)
                # 3. Recent orchestrator-side ops for context (per-client ring).
                try:
                    c = ctx.session.require_client(view)
                    out["recent_orch_ops"] = c.recent_ops(samples or 16)
                except Exception:
                    pass
                # 4. v0.25 WP1: newest crash dump, parsed in-line. Runs when
                # the breadcrumb heuristic says the far end restarted
                # (rebooted=True) or the caller passed include_dump — the
                # post-BSOD "what just killed the box" answer without a
                # manual download. Failure attaches `minidump_error`; the
                # breadcrumb/log-tail data above always survives.
                try:
                    c = ctx.session.require_client(view)
                    if out.get("rebooted") or include_dump:
                        from . import dump as _dump
                        got = await _dump._latest_minidump(
                            ctx, c, _dump.DEFAULT_DUMP_DIR)
                        if got is None:
                            out["minidump_error"] = (
                                "no parseable .dmp files in "
                                f"{_dump.DEFAULT_DUMP_DIR}")
                        else:
                            entries = got.pop("entries", None)
                            res = await _dump._parse_artifact(
                                ctx, c, got["local_path"],
                                boot_epoch_ms=await _dump._boot_epoch_ms(c))
                            res["source"] = {
                                k: got[k] for k in
                                ("remote_path", "local_path", "name",
                                 "mtime_unix", "size", "dir")}
                            res["source"]["dumps_seen"] = len(entries or [])
                            out["minidump"] = res
                except Exception as exc:
                    out["minidump_error"] = str(exc)
                return _j(out)
            if action == "timeline":
                # v1.0.1 Phase 1.6: merged chronological view of a target
                # that stitches together the pieces already recorded
                # elsewhere — boot identity, agent restarts, watchdog
                # arms/fires, recent orchestrator ops, crash state, and
                # fresh minidumps. Windowed by since_iso/until_iso when
                # the caller passes them; defaults to the current ring.
                import datetime as _dt
                try:
                    view = ctx.session.resolve_view_name(name) if name \
                        else ctx.session.primary
                except Exception:
                    view = ctx.session.primary
                events: list[dict[str, Any]] = []

                def _parse_iso(s: str) -> float:
                    if not s:
                        return 0.0
                    try:
                        if s.endswith("Z"):
                            s = s[:-1] + "+00:00"
                        return _dt.datetime.fromisoformat(s).timestamp()
                    except Exception:
                        return 0.0
                lo = _parse_iso(since_iso)
                hi = _parse_iso(until_iso)

                def _in_window(ts: float) -> bool:
                    if lo and ts < lo:
                        return False
                    if hi and ts > hi:
                        return False
                    return True
                # Boot identity (last-seen only — no persistent ring yet)
                bid = ctx.session.boot_identity(view)
                if bid:
                    boot_ms = int(bid.get("boot_epoch_ms") or 0)
                    boot_ts = boot_ms / 1000.0 if boot_ms else 0.0
                    if _in_window(boot_ts) or not boot_ts:
                        events.append({
                            "ts": boot_ts,
                            "kind": "boot_identity",
                            "view": view,
                            "boot_epoch_ms": boot_ms,
                            "agent_instance_id": bid.get("agent_instance_id"),
                        })
                # Recent orchestrator ops (ring).
                for call in list(ctx.session.tool_log)[-200:]:
                    ts = float(call.ts or 0)
                    if not _in_window(ts):
                        continue
                    events.append({
                        "ts": ts,
                        "kind": "op",
                        "tool": call.tool,
                        "action": call.action,
                        "ok": call.ok,
                        "destructive": call.destructive,
                        "error": call.error if not call.ok else "",
                    })
                # Watchdog state (live).
                try:
                    client = ctx.session.clients.get(view)
                    if client is not None:
                        listing = await client.watchdog_list()
                        rows = listing.get("entries", []) \
                            if isinstance(listing, dict) else (listing or [])
                        for r in rows or []:
                            events.append({
                                "ts": 0.0,  # driver side; no epoch
                                "kind": "watchdog_armed",
                                "id": r.get("id"),
                                "deadline_ms": r.get("deadline_ms"),
                                "label": r.get("label"),
                            })
                except Exception:  # noqa: BLE001 — watchdog list best-effort
                    pass
                # Pending boot notice (parked by boot monitor).
                pending = ctx.session.pending_boot_notices.get(view)
                if pending:
                    boot_ms = int(pending.get("boot_epoch_ms") or 0)
                    events.append({
                        "ts": boot_ms / 1000.0 if boot_ms else 0.0,
                        "kind": "boot_notice",
                        "notice": dict(pending),
                    })
                # Sort newest-first, cap.
                events.sort(key=lambda e: float(e.get("ts") or 0),
                            reverse=True)
                cap = int(samples) if samples else 100
                events = events[:cap]
                return _j({
                    "ok": True,
                    "action": "timeline",
                    "view": view,
                    "since_iso": since_iso,
                    "until_iso": until_iso,
                    "count": len(events),
                    "events": events,
                    "hint": ("timeline merges boot_identity, orchestrator "
                             "op log, watchdog state, and pending boot "
                             "notices. Use target_manage(action="
                             "'crash_state') for full post-crash detail."),
                })
            if action == "rediscover":
                # v1.0.1 Phase 2.4: re-probe a machine's known endpoints
                # in parallel. Scope here (Phase 1 half): registry
                # observed_endpoints + configured + alt_hosts +
                # hostname resolution via getaddrinfo. On success,
                # update observed_endpoints; the caller can then
                # target_manage(action='reconnect') (or wait for the
                # next connect() to pick it up).
                import asyncio as _asyncio
                import socket as _socket
                mlabel_in = (machine or name or "").strip()
                if not mlabel_in:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "rediscover: machine= required"})
                mlabel = ctx.session._match_machine(mlabel_in) or mlabel_in
                # Candidate hosts (strings) + port guess.
                hosts: list[str] = []
                port_guess: int = 50099
                try:
                    tc = ctx.session.cfg.target_for(mlabel)
                    if tc.host:
                        hosts.append(tc.host)
                    if tc.port:
                        port_guess = int(tc.port)
                    for h in (getattr(tc, "alt_hosts", None) or []):
                        if h and h not in hosts:
                            hosts.append(h)
                except Exception:
                    pass
                for o in ctx.registry.observed_endpoints(mlabel):
                    oh = o.get("host")
                    if oh and oh not in hosts:
                        hosts.append(str(oh))
                    if o.get("port"):
                        port_guess = port_guess or int(o["port"])
                # Hostname resolution — add every A record we see.
                try:
                    for info in _socket.getaddrinfo(
                            mlabel, port_guess, _socket.AF_INET,
                            _socket.SOCK_STREAM):
                        ip = info[4][0]
                        if ip and ip not in hosts:
                            hosts.append(ip)
                except Exception:
                    pass
                if not hosts:
                    return _j({"ok": False, "kind": "no_candidates",
                               "machine": mlabel,
                               "error": "rediscover: nothing to probe — "
                                        "configured, observed, alt_hosts, "
                                        "and DNS all empty"})
                probe_s = max(1.0, float(timeout_s) if timeout_s else 2.0)

                async def _probe(h: str) -> tuple[str, bool, str]:
                    try:
                        from ...session import _probe_tcp
                        await _probe_tcp(h, port_guess, timeout_s=probe_s)
                        return h, True, ""
                    except Exception as exc:  # noqa: BLE001
                        return h, False, str(exc)
                probed = await _asyncio.gather(
                    *(_probe(h) for h in hosts), return_exceptions=False)
                answered = [(h, "ok") for h, ok, _ in probed if ok]
                failures = [{"host": h, "error": e}
                            for h, ok, e in probed if not ok]
                for h, _ in answered:
                    try:
                        ctx.registry.record_observed_endpoint(
                            mlabel, host=h, port=port_guess)
                    except Exception:  # noqa: BLE001
                        pass
                return _j({
                    "ok": bool(answered),
                    "action": "rediscover",
                    "machine": mlabel,
                    "port": port_guess,
                    "tried": hosts,
                    "answered": [h for h, _ in answered],
                    "failed": failures,
                    "hint": ("record_observed_endpoint updated for every "
                             "live host; call target_manage(action="
                             f"'reconnect', name={mlabel!r}) to swap the "
                             "channel, or just wait for the next connect "
                             "(the candidate list now sees the new IP)"),
                })
            if action == "boot_recover":
                # v0.28: the post-reboot choreography as one call —
                # verify/restore the view connection, sweep stale boot
                # state, load the driver if it did not survive, re-arm
                # watchdog.auto_arm, pull + parse the newest minidump.
                # Every step degrades honestly; the report shows which
                # steps ran and which failed.
                cid = current_client_id()
                view = ctx.session.resolve_view_name(name) if name \
                    else ctx.session.primary
                out: dict[str, Any] = {"ok": True, "action": "boot_recover",
                                       "view": view}
                client = ctx.session.clients.get(view)
                was_connected = client is not None
                reachable = False
                if client is not None:
                    try:
                        st = await client.status()
                        reachable = bool(st.get("ok", True))
                        out["status"] = {
                            k: st.get(k) for k in
                            ("boot_epoch_ms", "agent_instance_id",
                             "driver_state", "os_version", "os_build")
                            if k in st}
                    except Exception as exc:
                        out["status_error"] = str(exc)
                boot_change = None
                if not reachable:
                    try:
                        st2 = await ctx.session.connect(
                            host or None, port or None, token or None,
                            name=view, owner=cid, force=False)
                        boot_change = st2.get("boot_change")
                        out["connect"] = {
                            "was_connected": was_connected,
                            "endpoint": getattr(
                                ctx.session.clients.get(view), "endpoint",
                                ""),
                            "boot_change": boot_change,
                        }
                    except Exception as exc:
                        e = _enrich_error("target_manage", "connect",
                                          str(exc))
                        out["ok"] = False
                        out["connect"] = {"was_connected": was_connected,
                                          "error": e}
                        out["error"] = (
                            f"boot_recover: view {view!r} unreachable — "
                            "restore connectivity, then retry")
                        return _j(out)
                else:
                    out["connect"] = {"was_connected": True,
                                      "boot_change": None}
                # Stale-state sweep on a boot change (shells, follows,
                # watchdog arms, detached handles).
                if boot_change:
                    try:
                        out["swept"] = await ctx.sweep_view_state(view)
                    except Exception as exc:
                        out["sweep_error"] = str(exc)
                # Driver check + optional load.
                drv: dict[str, Any] = {}
                try:
                    c = ctx.session.require_client(view)
                    st = await c.status()
                    state = str(st.get("driver_state", "")).upper()
                    drv["state"] = st.get("driver_state")
                    present = state in ("DRIVER_SERVICE",
                                        "DRIVER_MANUAL_MAPPED",
                                        "SERVICE", "MANUAL_MAPPED")
                    drv["present"] = present
                    if not present and load_driver:
                        lease = None
                        try:
                            if ctx.leases is not None:
                                wait_s = getattr(
                                    ctx.cfg.leases, "driver_timeout_s",
                                    10.0)
                                lease = await ctx.leases.acquire(
                                    "driver", cid, wait_s=wait_s)
                                if isinstance(lease, BusyInfo):
                                    drv["load_error"] = (
                                        "driver lease held by "
                                        f"{lease.held_by}")
                                    lease = None
                            if lease is not None or ctx.leases is None:
                                r = await c.driver_load(method=method)
                                merged = await _merge_driver_state(
                                    ctx, r, verb="driver_load", view=view)
                                drv["loaded"] = merged.get("ok") is not False
                                drv["load_result"] = {
                                    k: v for k, v in merged.items()
                                    if k in ("ok", "driver_state",
                                             "error")}
                        finally:
                            if lease is not None:
                                await ctx.leases.release(lease)
                    # Auto-arm after (re)load or on a driver that
                    # survived the reboot.
                    if (not drv.get("present")) or load_driver or \
                            boot_change is not None:
                        arm = await _auto_arm_after_load(
                            ctx, ctx.session.clients.get(view), view)
                        drv["watchdog_auto_arm"] = (
                            arm if arm is not None
                            else _auto_arm_cfg_status(ctx))
                except Exception as exc:
                    drv["error"] = str(exc)
                out["driver"] = drv
                # Newest minidump — the "what killed the box" answer.
                # Default on for the post-reboot case (fresh connect or
                # a boot change); include_dump forces it otherwise.
                if include_dump or boot_change or not was_connected:
                    res = await _monitor_pull_minidump(ctx, view)
                    if res is not None:
                        out["crash_dump"] = {
                            "bugcheck": res.get("bugcheck"),
                            "params": res.get("params"),
                            "faulting_module": res.get("faulting_module"),
                            "resolution": res.get("resolution"),
                            "source": res.get("source"),
                            "hint": "dump_manage(action='stack', "
                                    "path=<source.local_path>) walks "
                                    "the saved stack offline",
                        }
                    else:
                        out["crash_dump"] = None
                return _j(out)
            if action == "wait_connectable":
                # v0.17 F-1c: poll a TCP handshake + gRPC status roundtrip
                # until the deadline, using bounded exponential backoff.
                # Distinct from action="connect" (which fails hard on the
                # first probe): wait_connectable is what you call after
                # `driver_load` or an agent restart when the target is
                # expected to come up but not there yet.
                import time as _t
                from ...session import _probe_tcp
                # name= picks the configured view endpoint ('lab2' ->
                # 'lab2.kernel'); an explicit host/port path is untouched.
                view = ctx.session.resolve_view_name(name) if name else ""
                try:
                    t = ctx.session.cfg.target_for(view or None)
                except KeyError:
                    # Learned/raw view with no config entry — fall back to
                    # the primary target's endpoint defaults.
                    t = ctx.session.cfg.target_for(None)
                probe_host = host or t.host
                probe_port = int(port or t.port)
                probe_token = token if token else t.token
                # Validate allowlist before any network activity; this
                # raises TargetNotAllowedError which the guard maps.
                ctx.session.check_target(probe_host)
                deadline_s = float(timeout_s) if timeout_s and timeout_s > 0 else 15.0
                mcp_deadline_note = (
                    f"timeout_s={deadline_s:g} exceeds ~60s — the MCP "
                    "host's own request deadline usually kills the call "
                    "first (error -32001); prefer timeout_s<=60 and "
                    "re-call in a loop"
                    if deadline_s > 60 else "")
                deadline = _t.monotonic() + deadline_s
                delay = 0.3
                attempts = 0
                last_err: str = ""
                last_kind: str = ""
                started = _t.monotonic()
                while _t.monotonic() < deadline:
                    attempts += 1
                    remaining = max(0.0, deadline - _t.monotonic())
                    probe_budget = min(2.0, remaining) if remaining > 0 else 0.2
                    try:
                        await _probe_tcp(probe_host, probe_port,
                                          timeout_s=probe_budget)
                    except OSError as exc:  # noqa: BLE001 - reraised via enrich_error
                        last_err = str(exc)
                        # classify so callers can branch on the *why* of
                        # the failure even while we keep polling.
                        _kind, _hint = _classify(str(exc))
                        last_kind = _kind
                    else:
                        # TCP up — attempt a real gRPC status roundtrip
                        # so a listening-but-broken agent still fails the
                        # readiness check.
                        probe_client = AgentClient(
                            probe_host, probe_port, probe_token,
                            t.connect_timeout_ms, max_inflight=t.max_inflight)
                        try:
                            await probe_client.connect()
                            st = await probe_client.status()
                            await probe_client.close()
                            elapsed_s = round(_t.monotonic() - started, 3)
                            ok_out = {
                                "ok": True,
                                "action": "wait_connectable",
                                "view": view or PRIMARY_TARGET,
                                "endpoint": f"{probe_host}:{probe_port}",
                                "attempts": attempts,
                                "elapsed_s": elapsed_s,
                                "status": st,
                            }
                            if mcp_deadline_note:
                                ok_out["note"] = mcp_deadline_note
                            return _j(ok_out)
                        except Exception as exc:  # noqa: BLE001 - polled retry
                            last_err = str(exc)
                            _kind, _hint = _classify(str(exc))
                            last_kind = _kind
                            try:
                                await probe_client.close()
                            except Exception:  # noqa: BLE001 - best-effort close
                                pass
                    remaining = deadline - _t.monotonic()
                    if remaining <= 0:
                        break
                    await asyncio.sleep(min(delay, max(0.05, remaining)))
                    delay = min(delay * 1.7, 3.0)
                elapsed_s = round(_t.monotonic() - started, 3)
                timeout_out = {
                    "ok": False,
                    "action": "wait_connectable",
                    "view": view or PRIMARY_TARGET,
                    "endpoint": f"{probe_host}:{probe_port}",
                    "attempts": attempts,
                    "elapsed_s": elapsed_s,
                    "kind": "wait_timeout",
                    "error": (
                        f"wait_connectable timed out after {attempts} "
                        f"attempt(s) over {elapsed_s}s: {last_err or 'no probe attempted'}"
                    ),
                    "last_probe_kind": last_kind or "unknown",
                    "hint": (
                        "target still not reachable; check the agent service, "
                        "network reachability, and firewall — the last probe "
                        f"classified as {last_kind or 'unknown'}. "
                        "See _error_enrich HINT_RULES for the net-layer "
                        "classifier docs."
                    ),
                }
                if mcp_deadline_note:
                    timeout_out["note"] = mcp_deadline_note
                return _j(timeout_out)
            if action == "wait_boot_change":
                # v0.25 WP1: block until the view's boot identity —
                # (boot_epoch_ms, agent_instance_id) — changes. Same
                # detector as status(), polled with the same bounded
                # backoff as wait_connectable (0.5s ramping to 3s).
                # A notice the boot monitor already parked also
                # satisfies the wait. Typical use: driver_load → trigger
                # a test that may BSOD → wait_boot_change →
                # wait_connectable → crash_state has the parsed dump.
                import time as _t
                view = ctx.session.resolve_view_name(name)
                client = ctx.session.require_client(view)
                deadline_s = float(timeout_s) if timeout_s and timeout_s > 0 else 15.0
                deadline = _t.monotonic() + deadline_s
                started = _t.monotonic()
                delay = 0.5
                attempts = 0
                last_kind = ""
                while _t.monotonic() < deadline:
                    attempts += 1
                    try:
                        s = await client.status()
                    except Exception:  # noqa: BLE001 — target may be mid-reboot
                        last_kind = "status_error"
                    else:
                        last_kind = "ok"
                        change = ctx.session.note_boot_identity(view, s)
                        pending = ctx.session.pending_boot_notices.pop(
                            view, None)
                        if pending is not None:
                            if change is None:
                                if pending.get("kind") in (
                                        "new_boot", "agent_restart"):
                                    # Monitor won the race — report
                                    # what it parked.
                                    change = pending
                                else:
                                    # A parked minidump result isn't a
                                    # boot change; re-park it so
                                    # status() still drains it.
                                    ctx.session.pending_boot_notices[
                                        view] = pending
                            elif pending.get("minidump") is not None:
                                change.setdefault("minidump",
                                                  pending["minidump"])
                        if change is not None:
                            elapsed_s = round(_t.monotonic() - started, 3)
                            swept = None
                            if "swept" not in change:
                                swept = await ctx.sweep_view_state(view)
                            return _j({
                                "ok": True,
                                "action": "wait_boot_change",
                                "view": view,
                                "boot_change": change,
                                "swept": change.get("swept", swept),
                                "minidump": change.get("minidump"),
                                "attempts": attempts,
                                "elapsed_s": elapsed_s,
                            })
                    remaining = deadline - _t.monotonic()
                    if remaining <= 0:
                        break
                    await asyncio.sleep(min(delay, max(0.05, remaining)))
                    delay = min(delay * 1.7, 3.0)
                elapsed_s = round(_t.monotonic() - started, 3)
                return _j({
                    "ok": False,
                    "action": "wait_boot_change",
                    "view": view,
                    "attempts": attempts,
                    "elapsed_s": elapsed_s,
                    "kind": "wait_timeout",
                    "error": (
                        f"wait_boot_change: view {view!r} showed no boot "
                        f"identity change after {attempts} poll(s) over "
                        f"{elapsed_s}s"),
                    "last_status_kind": last_kind or "unknown",
                    "boot_identity": ctx.session.boot_identity(view),
                    "hint": (
                        "the view's (boot_epoch_ms, agent_instance_id) "
                        "pair never changed — no reboot/agent restart "
                        "seen. For 'did it crash' triage use "
                        "target_manage(action='crash_state'); to force a "
                        "check now, status() runs the same detector."),
                })
            if action == "whoami":
                cid = current_client_id()
                return _j({"ok": True, "client_id": cid,
                           "focus": ctx.session.focus_of(cid)})
            if action == "list_peers":
                if ctx.clients is None:
                    return _j({"ok": True, "peers": []})
                peers = await ctx.clients.list_peers()
                # v0.24: surface the session-ledger refs next to the
                # registry's connected_views — when the two disagree,
                # driver_unload busy-blocks are diagnosable from list_peers
                # alone instead of "it just says busy".
                session_refs = ctx.session.refs
                for row in peers:
                    pid_ = row.get("client_id")
                    row["session_view_refs"] = {
                        v: n for v, owners in session_refs.items()
                        if (n := owners.get(pid_, 0)) > 0}
                    row["focus"] = ctx.session.focus_of(pid_)
                return _j({"ok": True, "peers": peers})
            if action == "release_peer":
                if not peer_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "release_peer: peer_id is required",
                               "hint": "target_manage(action='list_peers') to "
                                       "enumerate active peers"})
                if not force:
                    return _j({"ok": False, "kind": "confirm_required",
                               "error": "release_peer: pass force=true to release "
                                        "another peer's leases and view refs",
                               "peer_id": peer_id})
                released_leases: list[str] = []
                if ctx.leases is not None:
                    released_leases = await ctx.leases.release_by_owner(peer_id)
                released_views = await ctx.session.release_by_owner(peer_id)
                return _j({"ok": True, "peer_id": peer_id,
                           "released_leases": released_leases,
                           "released_views": released_views,
                           "hint": "the ClientRegistry entry is left in place; "
                                    "the idle reaper will drop it once its "
                                    "last_op ages out"})
            if action == "subscribe_peers":
                # MCP tool responses can't stream; return a point-in-time
                # snapshot. Live SSE lives on the dashboard.
                peers = await ctx.clients.list_peers() if ctx.clients is not None else []
                for row in peers:
                    row["focus"] = ctx.session.focus_of(
                        row.get("client_id"))
                leases = ctx.leases.snapshot() if ctx.leases is not None else {}
                return _j({"ok": True, "peers": peers, "leases": leases,
                           "hint": "snapshot only; wire the dashboard SSE "
                                    "feed for live join/leave/lease events"})
            return _unknown_action("target_manage", action, TARGET_ACTIONS, _TARGET_ACTION_HELP)

        return await _guard(ctx, "target_manage", action, args, run,
                            kind=("machines" if action in
                                  ("machines_register", "machines_set",
                                   "machines_unregister", "machines")
                                  else None))
