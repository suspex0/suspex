"""Event tool registration for the suspex0 MCP server (v0.20+).

``event_manage`` — the agent's "ears": target-originated kernel events
(process create/exit, thread create/exit, image load incl. driver
loads) delivered as they happen instead of by polling.

MCP clients cannot hold a gRPC stream, so the orchestrator owns it:
``subscribe`` starts a background consumer task that drains the agent's
Events.Stream into a bounded per-subscription buffer; ``poll`` re-serves
it with honest gap/drop accounting. Unsubscribe cancels the consumer and
unregisters the driver callbacks (when it is the last subscription).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

EVENT_ACTIONS = ["subscribe", "poll", "unsubscribe", "list", "stats",
                 "actions"]

# v0.22: per-verb help for action='actions'.
_EVENT_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "event_manage(action='actions')"},
    "subscribe": {"one_liner": "start consuming kernel notify events "
                               "(proc/thread/image load/bp_hit); needs "
                               "security.allow_event_stream; bit 6 "
                               "(bp_hit) also needs dangerous_ok",
                  "key_args": "kinds_mask, dangerous_ok",
                  "example": "event_manage(action='subscribe', kinds_mask=3)"},
    "poll": {"one_liner": "drain buffered events after since_seq; "
                          "dropped/gap fields are honest loss accounting",
             "key_args": "subscription_id, since_seq, limit",
             "example": "event_manage(action='poll', "
                        "subscription_id='sub1', since_seq=0)"},
    "unsubscribe": {"one_liner": "stop a subscription and unregister its "
                                 "kernel callbacks",
                    "key_args": "subscription_id",
                    "example": "event_manage(action='unsubscribe', "
                               "subscription_id='sub1')"},
    "list": {"one_liner": "list active subscriptions",
             "key_args": "none",
             "example": "event_manage(action='list')"},
    "stats": {"one_liner": "driver ring snapshot: buffered/dropped/seq + "
                           "registered classes",
              "key_args": "none",
              "example": "event_manage(action='stats')"},
}

# EventsKind bitmask values (proto enum values, bit = 1 << kind)
_CLASS_PROC = (1 << 1) | (1 << 2)          # proc create + exit
_CLASS_IMAGE = 1 << 3                      # image load (incl. drivers)
_CLASS_THREAD = (1 << 4) | (1 << 5)        # thread create + exit
_CLASS_BP = 1 << 6                         # v0.23: HW-BP hits (int1 hook)
_CLASS_ALL = _CLASS_PROC | _CLASS_IMAGE | _CLASS_THREAD | _CLASS_BP

_SUB_CAP = 4096      # per-subscription buffered events (overwrite-oldest)
_SUBS: dict[str, dict[str, Any]] = {}
_SEQ = [0]


def register(mcp, ctx: Context) -> None:
    """Register the ``event_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def event_manage(action: Annotated[str, Field(json_schema_extra={"enum": EVENT_ACTIONS})],
                           kinds_mask: int = 0,
                           since_seq: int = 0,
                           limit: int = 256,
                           subscription_id: str = "",
                           dangerous_ok: bool = False,
                           name: str = "") -> str:
        """Kernel event stream (process/thread/image-load notify + bp_hit)
        — subscribe/poll/unsubscribe/list/stats. Registers driver
        callbacks; gated by security.allow_event_stream. kinds_mask bit 6
        (bp_hit) installs the int1 hook — needs dangerous_ok=true.
        Per-verb help: event_manage(action='actions')."""
        args = {"action": action, "subscription_id": subscription_id}

        async def run() -> Any:
            if action not in EVENT_ACTIONS:
                return _unknown_action("event_manage", action, EVENT_ACTIONS, _EVENT_ACTION_HELP)
            if action == "actions":
                return _actions_help("event_manage", _EVENT_ACTION_HELP)
            c = ctx.session.require_client(name)

            if action == "subscribe":
                if c.events is None:
                    return _j({"ok": False, "kind": "agent_version",
                               "error": ("events: agent < v11 (Events "
                                         "service missing)"),
                               "hint": ("rebuild + redeploy the agent "
                                        "(scripts/update_target.py "
                                        "--component agent)")})
                if not getattr(ctx.cfg.security, "allow_event_stream", False):
                    return _j({"ok": False, "kind": "not_allowed",
                               "error": ("event subscribe is disabled "
                                         "(security.allow_event_stream=false) — "
                                         "it registers kernel notify callbacks"),
                               "hint": ("enable security.allow_event_stream in "
                                        "the orchestrator config once the "
                                        "target is known-good")})
                mask = int(kinds_mask) & 0xFFFFFFFF
                if mask & _CLASS_BP and not dangerous_ok:
                    return _j({"ok": False, "kind": "not_allowed",
                               "error": ("kinds_mask bit 6 (bp_hit) installs "
                                         "the driver's int1 hook"),
                               "hint": ("resend with dangerous_ok=true "
                                        "(PatchGuard-sensitive, lab-only)")})
                sid = f"ev{_SEQ[0]:04d}"
                _SEQ[0] += 1
                state: dict[str, Any] = {"id": sid, "events": [], "task": None,
                                         "kinds_mask": mask,
                                         "dropped_total": 0, "gap": False,
                                         "last_seq": 0,
                                         "target": ctx.session.resolve_view_name(name)}

                async def _consume() -> None:
                    try:
                        stream = c.events_stream(kinds_mask=mask,
                                                 dangerous_ok=dangerous_ok)
                        async for chunk in stream:
                            if chunk.dropped > state["dropped_total"]:
                                state["dropped_total"] = int(chunk.dropped)
                                state["gap"] = True
                            ts = int(time.time() * 1000)
                            for e in chunk.events:
                                state["events"].append({
                                    "seq": int(e.seq), "ts_ms": ts,
                                    "kind": int(e.kind), "pid": int(e.pid),
                                    "parent_pid": int(e.parent_pid),
                                    "tid": int(e.tid),
                                    "image": str(e.image),
                                    "dropped": bool(e.dropped),
                                    # v0.23 BP_HIT payload (0 for other kinds)
                                    "address": int(getattr(e, "address", 0)),
                                    "dr6": int(getattr(e, "dr6", 0)),
                                    "bp_id": int(getattr(e, "bp_id", 0)),
                                    "slot": int(getattr(e, "slot", 0)),
                                    "access": int(getattr(e, "access", 0)),
                                    "irql": int(getattr(e, "irql", 0))})
                                state["last_seq"] = int(e.seq)
                            if len(state["events"]) > _SUB_CAP:
                                del state["events"][:len(state["events"]) - _SUB_CAP]
                                state["gap"] = True
                            if chunk.done:
                                break
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        state["gap"] = True
                        state["error"] = str(exc)

                state["task"] = asyncio.create_task(
                    _consume(), name=f"suspex-events-{sid}")
                _SUBS[sid] = state
                return _j({"ok": True, "subscription_id": sid,
                           "kinds_mask": mask,
                           "note": ("orchestrator consumes the stream in the "
                                    "background; poll with "
                                    "event_manage(action='poll', "
                                    "subscription_id=...)")})

            if action == "poll":
                if not subscription_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "poll: subscription_id= is required"})
                state = _SUBS.get(subscription_id)
                if not state:
                    return _j({"ok": False, "kind": "not_found",
                               "error": f"unknown subscription {subscription_id!r}"})
                events = state["events"]
                start = 0
                if since_seq:
                    start = next((k for k, e in enumerate(events)
                                  if e["seq"] > since_seq), len(events))
                batch = events[start:start + max(1, limit)]
                return _j({"ok": True, "subscription_id": subscription_id,
                           "events": batch,
                           "last_seq": events[-1]["seq"] if events else state["last_seq"],
                           "dropped": state["dropped_total"],
                           "gap": state["gap"],
                           "stream_error": state.get("error", ""),
                           "buffered": len(events)})

            if action == "unsubscribe":
                if not subscription_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "unsubscribe: subscription_id= is required"})
                state = _SUBS.pop(subscription_id, None)
                if not state:
                    return _j({"ok": False, "kind": "not_found",
                               "error": f"unknown subscription {subscription_id!r}"})
                if state["task"]:
                    state["task"].cancel()
                # last subscription gone -> unregister the kernel notify
                # callbacks (kernel-visible state must not outlive the
                # orchestrator's interest). They live on the view the
                # subscription was created on — not necessarily the
                # caller's current focus.
                try:
                    c_sub = ctx.session.require_client(
                        state.get("target") or name)
                except Exception:
                    c_sub = None
                if not _SUBS and c_sub is not None and c_sub.events is not None:
                    try:
                        await c_sub.events_disable()
                    except Exception as exc:
                        pass  # driver may already be gone; unload cleans up
                return _j({"ok": True, "subscription_id": subscription_id,
                           "events_buffered": len(state["events"])})

            if action == "list":
                rows = [{"subscription_id": sid,
                         "kinds_mask": st["kinds_mask"],
                         "buffered": len(st["events"]),
                         "dropped_total": st["dropped_total"],
                         "gap": st["gap"],
                         "target": st["target"]}
                        for sid, st in _SUBS.items()]
                return _j({"ok": True, "subscriptions": rows,
                           "count": len(rows)})

            if action == "stats":
                if c.events is None:
                    return _j({"ok": False, "kind": "agent_version",
                               "error": ("events: agent < v11 (Events service "
                                         "missing)")})
                return _j(await c.events_stats())

            return _unknown_action("event_manage", action, EVENT_ACTIONS, _EVENT_ACTION_HELP)

        return await _guard(ctx, "event_manage", action, args, run)
