"""Watchdog tool registration for the suspex0 MCP server.

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
WDG_ACTIONS = ["arm", "kick", "disarm", "list",
               "auto_kick", "auto_stop", "auto_status", "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``watchdog_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ watchdog_manage --

    _WDG_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "watchdog_manage(action='actions')"},
        "arm": {"one_liner": "arm a wedge→bugcheck watchdog id on the "
                             "driver (claims ownership for the view)",
                "key_args": "id, deadline_ms, bugcheck_code, label, replace",
                "example": "watchdog_manage(action='arm', id=1, "
                           "deadline_ms=45000, label='stage1')"},
        "kick": {"one_liner": "pet a watchdog once (extends its deadline)",
                 "key_args": "id",
                 "example": "watchdog_manage(action='kick', id=1)"},
        "disarm": {"one_liner": "disarm + release the id so a peer can "
                                "re-arm it",
                   "key_args": "id",
                   "example": "watchdog_manage(action='disarm', id=1)"},
        "list": {"one_liner": "list armed ids with owner/foreign + kicker "
                              "columns",
                 "key_args": "none",
                 "example": "watchdog_manage(action='list')"},
        "auto_kick": {"one_liner": "arm + attach an orchestrator-side "
                                   "interval kicker (hands-off protection)",
                      "key_args": "id, deadline_ms, interval_ms",
                      "example": "watchdog_manage(action='auto_kick', id=1, "
                                 "deadline_ms=45000, interval_ms=10000)"},
        "auto_stop": {"one_liner": "detach the auto-kicker (watchdog stays "
                                   "armed)",
                      "key_args": "id",
                      "example": "watchdog_manage(action='auto_stop', id=1)"},
        "auto_status": {"one_liner": "show an auto-kicker's kick history + "
                                     "last result",
                        "key_args": "id",
                        "example": "watchdog_manage(action='auto_status', id=1)"},
    }

    def _auto_arm_cfg_status() -> dict[str, Any]:
        """watchdog.auto_arm config status — the re-arm-on-driver_load /
        new_boot hook is config-gated and silent when unconfigured, so
        every watchdog response surfaces whether it would fire."""
        wdg = getattr(ctx.cfg, "watchdog", None)
        spec = (getattr(wdg, "auto_arm", None) or {}) \
            if wdg is not None else {}
        if not spec or not (spec.get("id") or 0):
            return {
                "configured": False,
                "note": "watchdog.auto_arm is UNCONFIGURED — wedges are "
                        "not auto-protected across driver_load/reboot. "
                        "Set [watchdog.auto_arm] {id, deadline_ms, "
                        "interval_ms, ...} in config, or arm + auto_kick "
                        "manually after every boot.",
            }
        return {
            "configured": True,
            "id": int(spec.get("id") or 0),
            "deadline_ms": int(spec.get("deadline_ms") or 45000),
            "interval_ms": int(spec.get("interval_ms") or 10000),
            "label": str(spec.get("label") or "auto_arm"),
            "note": "re-arms + re-attaches the kicker on driver_load "
                    "and on connect-after-new-boot",
        }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def watchdog_manage(action: Annotated[str, Field(json_schema_extra={"enum": WDG_ACTIONS})],
                              id: int = 0,
                              deadline_ms: int = 45000,
                              interval_ms: int = 10000,
                              bugcheck_code: int = 0,
                              cookie: int = 0,
                              label: str = "",
                              replace: bool = False,
                              name: str = "",
                              unsafe_without_kicker: bool = False) -> str:
        """Wedge → bugcheck watchdog: the driver KeBugCheckEx()'s the
        target (0xE2) when an armed deadline passes without a kick — a
        silent wedge becomes an analyzable dump. auto_kick arms + kicks
        from an orchestrator task (recommended). watchdog.auto_arm config
        re-arms on driver_load and post-reboot reconnect — it is
        config-gated and OFF when unconfigured; watchdog_manage(
        action='list') reports its status in auto_arm. Per-verb help:
        watchdog_manage(action='actions')."""
        args = {"action": action, "id": id, "deadline_ms": deadline_ms}

        async def run() -> str:
            # v0.31 Phase 1.4: `id` may be rebound inside the arm branch
            # when the caller passes 0 and we auto-allocate a free slot.
            nonlocal name, id
            if action not in WDG_ACTIONS:
                return _unknown_action("watchdog_manage", action, WDG_ACTIONS, _WDG_ACTION_HELP)
            if action == "actions":
                return _actions_help("watchdog_manage", _WDG_ACTION_HELP)
            # v0.27: name= resolves machine.view — rebind to the canonical
            # key so the ownership/kicker namespaces below don't split
            # across selector spellings ('' vs 'lab2.kernel').
            name = ctx.session.resolve_view_name(name)
            c = ctx.session.require_client(name)
            if action == "arm":
                cid = current_client_id()
                # v0.31 Phase 1.4: id=0 now auto-allocates the first free
                # slot instead of hard-erroring. We keep the chosen value
                # in a local to avoid reassigning the `id` closure (which
                # would make `id` a local of run() everywhere).
                nonlocal_id = id
                if not nonlocal_id:
                    try:
                        existing = await c.watchdog_list()
                    except Exception as exc:  # noqa: BLE001
                        return _j({"ok": False, "kind": "watchdog_list_failed",
                                   "error": f"watchdog arm: id auto-allocate "
                                            f"needed watchdog_list and it "
                                            f"failed: {exc}",
                                   "hint": "pass id=<small int> explicitly"})
                    rows = existing.get("entries", []) \
                        if isinstance(existing, dict) else (existing or [])
                    used = {int(r.get("id") or 0) for r in rows}
                    for cand in range(1, 65):
                        if cand not in used:
                            nonlocal_id = cand
                            break
                    else:
                        return _j({"ok": False, "kind": "watchdog_full",
                                   "error": "watchdog arm: no free id in "
                                            "1..64 (all slots armed)",
                                   "hint": "disarm an unused id first"})
                # Shadow `id` with the resolved value for the rest of this
                # branch. Since every subsequent reference reads `id`, and
                # we assigned to it above only when it was 0, this
                # rebinding is safe inside the `arm` branch only.
                id = nonlocal_id
                cat = f"watchdog:{name}"
                key = str(id)
                # v0.17 E-1c: ownership guard. A peer that armed id=N owns
                # it; another peer trying a bare arm of the same id would
                # otherwise silently steal it (or race on driver-side
                # STATUS_OBJECT_NAME_COLLISION). Refuse foreign arms
                # unless the caller explicitly asked for replace=true.
                if ctx.ownership is not None and not replace:
                    foreign = await ctx.ownership.is_foreign_or_none(
                        cat, key, cid)
                    if foreign is True:
                        existing_owner = await ctx.ownership.owner_of(cat, key)
                        return _j({"ok": False,
                                   "kind": "foreign_owned",
                                   "error": (f"watchdog id={id} on view "
                                             f"{name!r} is owned by peer "
                                             f"{existing_owner!r}"),
                                   "owner": existing_owner,
                                   "hint": ("pass replace=true to steal, "
                                            "or pick a different id — "
                                            "watchdog_manage(action='list') "
                                            "enumerates armed slots")})
                # v0.17 E-1c: bare-arm collision. A caller re-arming an
                # id the driver already has surfaces as
                # STATUS_OBJECT_NAME_COLLISION deep in the driver — turn
                # that into a first-class refusal at the orchestrator so
                # the caller sees WHY (and gets the auto_kick nudge).
                if not replace:
                    existing = await c.watchdog_list()
                    # watchdog_list() returns the wrapper dict
                    # {ok, error, now_us, count, entries:[...]} — iterate
                    # entries, not the wrapper (iterating the dict used to
                    # yield string keys and crash on r.get).
                    existing_rows = existing.get("entries", []) \
                        if isinstance(existing, dict) else (existing or [])
                    armed = any(int(r.get("id", 0) or 0) == id
                                for r in existing_rows)
                    if armed:
                        return _j({"ok": False,
                                   "kind": "watchdog_collision",
                                   "error": (f"watchdog id={id} already "
                                             f"armed on view {name!r}; "
                                             "pass replace=true to reset "
                                             "the deadline, or use "
                                             "auto_kick for hands-off "
                                             "protection"),
                                   "hint": ("watchdog_manage("
                                            "action='auto_kick', "
                                            f"id={id}, ...) arms + "
                                            "orchestrator kicks every "
                                            "interval_ms so the target "
                                            "survives as long as the "
                                            "orchestrator is running")})
                flags = 1 if replace else 0
                result = await c.watchdog_arm(id, deadline_ms,
                                                bugcheck_code=bugcheck_code,
                                                flags=flags, cookie=cookie,
                                                label=label)
                # v0.17 E-1c: claim the tag on a successful arm so a
                # follow-up foreign arm hits the refusal above.
                if (ctx.ownership is not None
                        and isinstance(result, dict) and result.get("ok")):
                    await ctx.ownership.claim(cat, key, cid)
                # v0.31 Phase 1.4: bare arm without a kicker now REFUSES
                # by default (breaking change from v0.17's warning-only
                # path). An armed deadline with nothing kicking it
                # eventually bugchecks the target; a scripted workflow
                # that genuinely wants the fire-and-forget behavior
                # passes unsafe_without_kicker=true. This runs AFTER the
                # arm succeeds, so the slot is held — disarm it before
                # returning the refusal so the caller isn't surprised by
                # a lingering watchdog they didn't commit to.
                if (isinstance(result, dict) and result.get("ok")
                        and _auto_key(name, id) not in ctx._auto_kicks
                        and not unsafe_without_kicker):
                    try:
                        await c.watchdog_disarm(id)
                    except Exception:  # noqa: BLE001 — best-effort cleanup
                        pass
                    if ctx.ownership is not None:
                        await ctx.ownership.release(
                            f"watchdog:{name}", str(id))
                    return _j({
                        "ok": False,
                        "kind": "watchdog_no_kicker",
                        "id": id,
                        "error": (f"watchdog id={id} without a kicker was "
                                  "refused — the deadline would fire "
                                  "(bugcheck the target) if nothing kicks "
                                  f"within deadline_ms={deadline_ms}"),
                        "hint": (f"use watchdog_manage(action='auto_kick', "
                                 f"id={id}, deadline_ms={deadline_ms}, "
                                 "interval_ms=...) for hands-off "
                                 "protection, or pass "
                                 "unsafe_without_kicker=true to arm "
                                 "unprotected (fire-and-forget)"),
                    })
                return _j(result)
            if action == "kick":
                if not id:
                    return _j({"ok": False, "error": "watchdog kick: id != 0 required"})
                return _j(await c.watchdog_kick(id, deadline_ms=deadline_ms,
                                                 cookie=cookie))
            if action == "disarm":
                if not id:
                    return _j({"ok": False, "error": "watchdog disarm: id != 0 required"})
                # Also cancel any auto-kicker for this id so we don't leave a
                # background task pounding a disarmed slot.
                key = f"{name}:{id}"
                st = ctx._auto_kicks.pop(key, None)
                if st and st.get("task") and not st["task"].done():
                    st["task"].cancel()
                result = await c.watchdog_disarm(id)
                # v0.17 E-1d: release the ownership tag so a peer can
                # re-arm the same id without hitting foreign_owned.
                if ctx.ownership is not None:
                    await ctx.ownership.release(f"watchdog:{name}", str(id))
                return _j(result)
            if action == "list":
                listing = await c.watchdog_list()
                rows = (listing.get("entries", [])
                        if isinstance(listing, dict) else listing) or []
                # v0.17 E-1b: annotate each row with owner + kicker state
                # so callers can tell "armed and protected" from "armed
                # and un-kicked" without a second call.
                if ctx.ownership is not None:
                    cid = current_client_id()
                    cat = f"watchdog:{name}"
                    for r in (rows or []):
                        wid = r.get("id")
                        if isinstance(wid, int):
                            owner = await ctx.ownership.owner_of(cat, str(wid))
                            r["owner"] = owner
                            r["foreign"] = (owner is not None
                                            and owner != cid)
                for r in (rows or []):
                    wid = r.get("id")
                    if not isinstance(wid, int):
                        continue
                    st = ctx._auto_kicks.get(_auto_key(name, wid))
                    if st and not st.get("stopped") and st.get("task") \
                            and not st["task"].done():
                        r["kicker"] = "attached"
                        r["kicker_interval_ms"] = st.get("interval_ms")
                    else:
                        r["kicker"] = "none"
                return _j({"count": len(rows or []), "watchdogs": rows or [],
                           "auto_arm": _auto_arm_cfg_status()})
            if action == "auto_kick":
                if not id:
                    return _j({"ok": False, "error": "watchdog auto_kick: id != 0 required"})
                return _j(await _auto_kick_start(ctx, c, name, id, deadline_ms,
                                                  interval_ms, bugcheck_code,
                                                  cookie, label, replace))
            if action == "auto_stop":
                if not id:
                    return _j({"ok": False, "error": "watchdog auto_stop: id != 0 required"})
                return _j(await _auto_kick_stop(ctx, c, name, id))
            if action == "auto_status":
                return _j(_auto_kick_status(ctx))
            return _unknown_action("watchdog_manage", action, WDG_ACTIONS, _WDG_ACTION_HELP)

        return await _guard(ctx, "watchdog_manage", action, args, run)
