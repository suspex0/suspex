"""Dashboard REST + WebSocket routes, registered on the main FastAPI app
before the MCP mount takes the / fallback.

Read endpoints (status/config/findings/toollog) stay GET; the machine
registry gets a small write surface (register/set/unregister +
connect/disconnect) so the dashboard can manage targets without the
operator dropping to the MCP tool. Every write wraps ``ctx.registry`` /
``ctx.session`` — the same code paths ``target_manage`` uses — and tokens
are never echoed back (``token_set`` only)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from ..session import VIEW_KINDS

STATIC_DIR = Path(__file__).parent / "static"

# Owner tag for views the dashboard connects, so refcount bookkeeping can
# tell dashboard-initiated connects from MCP-client ones.
_DASH_OWNER = "dashboard"


def _tag_list(value) -> list[str]:
    """Accept tags as a JSON list or a comma-separated string."""
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def register_dashboard_routes(app, ctx) -> None:  # noqa: ANN001 - FastAPI app
    @app.get("/api/status")
    async def status() -> JSONResponse:
        sess = ctx.session
        out = {
            "connected": sess.connected,
            "target": sess.cfg.target_endpoint,
            "active_ida_sessions": ctx.bridge.sessions,
            "tool_calls": len(sess.tool_log),
        }
        if sess.client is not None and sess.connected:
            try:
                agent = await sess.client.status()
            except Exception as exc:
                out["agent_error"] = str(exc)
                return JSONResponse(out)
            # v0.13 dev-feedback: enrich the slim agent status with
            # host_info security fields + the suspex-driver health probe
            # so the dashboard shows HVCI / driver_blocklist / KVA shadow /
            # PC uptime and explains WHY driver_state might be ABSENT.
            driver_present = str(agent.get("driver_state", "")).upper() in (
                "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
            agent["driver_present"] = driver_present
            try:
                hi = await sess.client.host_info(include_hardware=False)
            except Exception as exc:
                hi = {"ok": False, "error": str(exc)}
            if hi.get("ok"):
                sec = hi.get("security") or {}
                uptime = hi.get("uptime") or {}
                # Overwrite HVCI with the host_info-verified value.
                hvci_pair = sec.get("hvci")
                if isinstance(hvci_pair, dict) and hvci_pair.get("source") not in (
                        None, "unknown"):
                    agent["hvci"] = hvci_pair
                agent["memory_integrity"] = hvci_pair
                agent["driver_blocklist_on"] = sec.get("driver_blocklist_on")
                agent["kva_shadow"] = sec.get("kva_shadow")
                agent["vbs_enabled"] = sec.get("vbs_enabled")
                agent["credential_guard"] = sec.get("credential_guard")
                agent["lsa_protected"] = sec.get("lsa_protected")
                agent["kernel_debugger"] = sec.get("kernel_debugger")
                agent["secureboot"] = sec.get("secureboot")
                agent["patchguard_state"] = sec.get("patchguard_state")
                agent["pc_uptime_ms"] = uptime.get("pc_uptime_ms")
                agent["service_uptime_ms"] = uptime.get("service_uptime_ms")
                agent["boot_time"] = (hi.get("os") or {}).get("boot_time")
                agent["os"] = hi.get("os") or agent.get("os")
            else:
                agent["host_info_hint"] = ("HostInfo RPC unavailable "
                                            "(agent < v8?) — rich fields skipped")
            # Suspex-driver health explains DRIVER_ABSENT.
            try:
                from ..mcp._suspex_driver_probe import probe_suspex_driver
                agent["suspex_driver_health"] = await probe_suspex_driver(
                    sess.client, driver_state=agent.get("driver_state"))
            except Exception as exc:
                agent["suspex_driver_health"] = {"ok": False,
                                                  "error": f"probe failed: {exc}"}
            out["agent"] = agent
        return JSONResponse(out)

    @app.get("/api/findings")
    async def findings() -> JSONResponse:
        return JSONResponse([f.__dict__ for f in ctx.ledger.list_findings()])

    @app.get("/api/toollog")
    async def toollog() -> JSONResponse:
        return JSONResponse([
            {
                "tool": c.tool,
                "action": c.action,
                "destructive": c.destructive,
                "ok": c.ok,
                "error": c.error,
                "ts": c.ts,
            }
            for c in ctx.session.tool_log[-100:]
        ])

    # -------------------------------------------------------- machines ----

    def _machine_rows() -> list[dict]:
        """Every known machine (registry + YAML + live) with its
        describe() block and connected view kinds — mirrors
        target_manage(action='machines')."""
        reg = ctx.registry
        rows: list[dict] = []
        seen: set[str] = set()
        live = ctx.session.machines()

        def _row(alias: str) -> dict:
            r = reg.describe(alias, cfg=ctx.cfg) or {"machine": alias}
            label = str(r.get("machine") or alias)
            views = live.get(label, [])
            r["connected_views"] = sorted(
                ctx.session.view_kind_of(v) for v in views)
            r["connected"] = bool(views)
            return r

        for a in list(reg.all().keys()) + list(
                (getattr(ctx.cfg, "machines", None) or {}).keys()):
            if a.lower() not in seen:
                seen.add(a.lower())
                rows.append(_row(a))
        for m in sorted(live):
            if m.lower() not in seen:
                seen.add(m.lower())
                rows.append(_row(m))
        if not rows and getattr(ctx.cfg.target, "host", ""):
            rows.append(_row("default"))
        return rows

    @app.get("/api/machines")
    async def machines_list() -> JSONResponse:
        return JSONResponse({
            "ok": True,
            "machines": _machine_rows(),
            "min_trust_actuator": getattr(
                ctx.cfg.security, "min_trust_actuator", "untrusted"),
            "focus": ctx.session.focus_of(_DASH_OWNER),
        })

    @app.post("/api/machines")
    async def machines_register(req: Request) -> JSONResponse:
        body = await req.json()
        alias = str(body.get("alias") or body.get("machine") or "").strip()
        if not alias:
            return JSONResponse({"ok": False, "error": "alias is required"},
                                status_code=400)
        try:
            info = ctx.registry.register(
                alias,
                host=str(body.get("host") or ""),
                kernel_port=int(body.get("kernel_port") or body.get("port") or 0),
                user_port=int(body.get("user_port") or 0),
                token=str(body.get("token") or ""),
                trust=str(body.get("trust") or ""),
                purpose=str(body.get("purpose") or ""),
                note=str(body.get("note") or ""),
                operator=str(body.get("operator") or ""),
                tags=_tag_list(body.get("tags")),
                force=bool(body.get("force")),
            )
        except (ValueError, TypeError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        return JSONResponse({"ok": True, "machine_info": info})

    @app.post("/api/machines/{alias}")
    async def machines_set(alias: str, req: Request) -> JSONResponse:
        body = await req.json()

        def _opt(key, cast=str):
            v = body.get(key)
            if v in (None, ""):
                return None
            try:
                return cast(v)
            except (ValueError, TypeError):
                return None

        # The edit form always prefills host/ports and submits them
        # unchanged. Registry.set treats ANY endpoint field as an endpoint
        # write, which YAML aliases reject (reviewed config) — so a pure
        # metadata edit (note/purpose/trust/tags) 400'd and "Save did
        # nothing". Drop endpoint fields that match the current effective
        # values; only real changes count.
        cur = ctx.registry.describe(alias, cfg=ctx.cfg) or {}
        cur_eps = cur.get("endpoints") or {}
        cur_kh, _, cur_kp = (cur_eps.get("kernel") or "").rpartition(":")
        cur_uh, _, cur_up = (cur_eps.get("user") or "").rpartition(":")
        host = _opt("host")
        kport = _opt("kernel_port", int) or _opt("port", int)
        uport = _opt("user_port", int)
        if host is not None and str(host) == str(cur_kh or ""):
            host = None
        if kport is not None and int(kport) == int(cur_kp or 0):
            kport = None
        if uport is not None and int(uport) == int(cur_up or 0):
            uport = None

        # Present-but-empty CLEARS a metadata field (the form sends every
        # key on every submit; _opt swallowing "" made clearing notes
        # impossible — save "did nothing"). Absent key = no change.
        def _meta(key):
            v = body.get(key)
            return None if v is None else str(v)

        try:
            info = ctx.registry.set(
                alias,
                host=host,
                kernel_port=kport,
                user_port=uport,
                token=_opt("token"),
                trust=_opt("trust"),
                purpose=_meta("purpose"),
                note=_meta("note"),
                operator=_meta("operator"),
                tags=_tag_list(body["tags"]) if "tags" in body else None,
                force=bool(body.get("force")),
            )
        except (ValueError, TypeError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        return JSONResponse({"ok": True, "machine_info": info})

    @app.delete("/api/machines/{alias}")
    async def machines_unregister(alias: str, force: bool = False) -> JSONResponse:
        try:
            removed = ctx.registry.unregister(alias, force=force)
        except (ValueError, TypeError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        # A machine card can outlive its registry entry while a session
        # still holds a live view of it (k223/k225 on the lab LAN: the
        # registry entries were gone, the cards stayed because the views
        # were connected). "Delete" clears both: the entry AND any live
        # views (owner=None — management override, same as Disconnect).
        dropped: list[str] = []
        for view in list(ctx.session.machines().get(alias, [])):
            try:
                r = await ctx.session.disconnect(view, owner=None)
                dropped.extend(r.get("disconnected", []))
            except Exception:  # noqa: BLE001 — best-effort
                pass
        return JSONResponse({"ok": True, "machine": alias,
                             "removed": removed, "disconnected": dropped})

    @app.post("/api/machines/{alias}/connect")
    async def machine_connect(alias: str, req: Request) -> JSONResponse:
        try:
            body = await req.json()
        except Exception:
            body = {}
        views = str(body.get("views") or "kernel").strip().lower()
        kinds = list(VIEW_KINDS) if views in ("both", "all") \
            else [views if views in VIEW_KINDS else "kernel"]
        out: dict = {"ok": True, "views": {}}
        for kind in kinds:
            sel = f"{alias}.{kind}"
            try:
                st = await ctx.session.connect(
                    None, None, None, name=sel, machine=alias,
                    owner=_DASH_OWNER, force=bool(body.get("force")))
                out["views"][kind] = {
                    "ok": True,
                    "view": st.get("view") or sel,
                    "endpoint": getattr(
                        ctx.session.clients.get(st.get("view") or sel),
                        "endpoint", ""),
                }
            except KeyError as exc:
                out["views"][kind] = {"ok": False, "skipped": True,
                                      "error": str(exc)}
            except Exception as exc:  # noqa: BLE001 — per-view
                out["ok"] = False
                out["views"][kind] = {"ok": False, "error": str(exc)}
        return JSONResponse(out)

    @app.post("/api/machines/{alias}/disconnect")
    async def machine_disconnect(alias: str) -> JSONResponse:
        # Drop every connected view of this machine. owner=None force-closes
        # the named view regardless of which peer connected it — the
        # dashboard "Disconnect" button is a management override.
        live = ctx.session.machines().get(alias, [])
        if not live:
            return JSONResponse({"ok": True, "disconnected": [],
                                 "note": "no connected views"})
        dropped: list[str] = []
        for view in list(live):
            try:
                r = await ctx.session.disconnect(view, owner=None)
                dropped.extend(r.get("disconnected", []))
            except Exception as exc:  # noqa: BLE001
                return JSONResponse({"ok": False, "error": str(exc)},
                                    status_code=400)
        return JSONResponse({"ok": True, "disconnected": dropped})

    @app.post("/api/machines/{alias}/use")
    async def machine_use(alias: str) -> JSONResponse:
        try:
            if alias.lower() in ("none", "off", "clear"):
                return JSONResponse({"ok": True, "focus": None,
                                     "cleared": ctx.session.clear_focus(
                                         _DASH_OWNER)})
            focus = ctx.session.set_focus(_DASH_OWNER, alias)
        except (RuntimeError, ValueError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        return JSONResponse({"ok": True, "focus": focus})

    # ------------------------------------------------------- websocket ----

    @app.websocket("/ws")
    async def ws(ws: WebSocket) -> None:  # noqa: ANN001
        await ws.accept()
        sub_id = None
        queue = None
        if ctx.session.client is not None:
            sub_id, queue = ctx.session.client.bus.subscribe()
        try:
            while True:
                payload = {
                    "type": "snapshot",
                    "connected": ctx.session.connected,
                    "toollog": [
                        {"tool": c.tool, "action": c.action, "destructive": c.destructive,
                         "ok": c.ok, "error": c.error, "ts": c.ts}
                        for c in ctx.session.tool_log[-30:]
                    ],
                    "events": [e.data for e in ctx.session.client.bus.recent[-30:]]
                    if ctx.session.client else [],
                    "ida_sessions": ctx.bridge.sessions,
                }
                await ws.send_text(json.dumps(payload))
                if queue is not None:
                    try:
                        await asyncio.wait_for(queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        pass
                else:
                    await asyncio.sleep(1.0)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if sub_id is not None and ctx.session.client is not None:
                ctx.session.client.bus.unsubscribe(sub_id)

    # Always revalidate the static assets. They are tiny and change on
    # every dashboard edit; without this a browser heuristically caches
    # app.js/style.css and serves a stale build against a fresh index.html
    # (new layout, dead panels). ETag/Last-Modified still make the
    # revalidation a cheap 304 when nothing changed.
    _NO_CACHE = {"Cache-Control": "no-cache"}

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers=_NO_CACHE)

    @app.get("/app.js")
    async def app_js() -> FileResponse:
        return FileResponse(STATIC_DIR / "app.js", media_type="text/javascript",
                            headers=_NO_CACHE)

    @app.get("/style.css")
    async def style_css() -> FileResponse:
        return FileResponse(STATIC_DIR / "style.css", media_type="text/css",
                            headers=_NO_CACHE)
