"""suspex-server entry: one uvicorn app hosting the MCP endpoint (streamable
HTTP), the dashboard REST/WS, and the findings ledger."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from .caller import install_caller_middleware
from .clients import ClientRegistry
from .config import load_config
from .findings import FindingsLedger
from .ida_bridge import IdaBridge, IdaConfigLite
from .ghidra_bridge import GhidraBridge, GhidraConfigLite
from .leases import LeaseManager
from .mcp.tools import Context, build_server
from .ownership import OwnershipRegistry
from .session import Session

# Bumped by hand on any behavior-visible tool-surface change so clients
# know a re-connect (and tool-schema refresh) may be required.
SERVER_VERSION = "1.0.0-2026-10-22"  # v1.0: first public release (feature surface as of v0.29)
# v0.28: ghidra_manage — second analysis engine (orchestrator only; off by default).
# v0.25: engagement round — dump_manage(parse|latest) + crash_state minidump auto-parse + wait_boot_change + boot monitor; mem_rw resolve_range/dps + dt + idt; file_manage read + recursive download + snapshot pump + watchdog.auto_arm + exec background=true/timeout_s; ABI v12 write_path/STRICT_VA + cr3 va_translate+write + IdtList; kdnet docs; tool-schema slimming (~2x catalog reduction). Driver+agent rebuild (ABI v12).
# v0.24: engagement-feedback round — symbols resolve/lookup hex-mirrored RVAs; read_pdb_info parses VA-layout dump_module output (+ ensure pdb_guid=/pdb_age= override); open_status carries open_elapsed_s + stale-apply warning; ida_manage open/open_async accept artifacts-relative paths; driver_unload cross-checks ref-holders against the ClientRegistry (umagent-only peers no longer block; stale refs pruned; list_peers gains session_view_refs); list_artifacts covers spill/+dumps/+ingested/ with cached sha256; knowledge_manage about accepts path=; shim validation errors append expected arg names; struct_info/resolve_member/enum_info accept empty/partial build_id; agent dumper emits per-section residency map (DumpHeader.sections, proto v13). Orchestrator + agent rebuild; no driver change.
# v0.20: agent primitives round (ABI v11) — hands: `device_manage ioctl` (usermode DeviceIoControl send, gated by security.allow_ioctl_send) + `value_manage ioctl_decode/ioctl_encode`; eyes: `mem_rw threads` (system-wide per-thread inventory, agent-side + driver-enriched win32_start_va/teb) and `mem_rw obj_enum` (kernel object-directory walk \Device|\Driver|\FileSystem|\BaseNamedObjects|\Callback|\ObjectTypes via ZwOpen/QueryDirectoryObject); ears: `event_manage` (driver PsSet{CreateProcess,CreateThread,LoadImage}NotifyRoutine ring -> Events gRPC stream -> orchestrator-buffered subscribe/poll/unsubscribe/list/stats, gated by security.allow_event_stream, honest dropped/gap accounting); telemetry: `device_manage etw_providers|etw_sessions` (query-only). Driver+agent rebuild + redeploy required (ABI v10 wire structs).
# v0.19: knife-derived static-analysis layer — new `bin_manage` tool (artifact/sha256/live-memory sources; PE parse `info|sections|imports|exports|hashes|imphash|sec|caps`; byte surface `strings|iocs|entropy|scan`; capstone engine `funcs|disasm_func|cfg|xrefs|paths|callgraph`; driver passes `irp_surface|ioctl_surface`; `audit|diff|pseudo`) + `value_manage ioctl_decode/ioctl_encode` + `mem_rw strings|iocs|entropy` over live ranges + `irp_hook_check`/`code_integrity` plugins. Orchestrator-only, no ABI bump.
# v0.18: `findings_manage` renamed to `knowledge_manage` and expanded into a cross-agent shared knowledge base: findings + low-ceremony notes + sha256-keyed artifact index (with per-alias/per-version tracking so `about(alias='nvlddmkm.sys')` returns every version seen) + tool-event breadcrumbs auto-emitted by `file_manage dump_module` / `ida_manage open|*` / `mem_rw pattern_scan` / `script_manage run` / `parity` / yara + IDA-session records (which .i64 exists for which sha, live/closed, on-disk path) + FTS5 full-text search over findings/notes/evidence. Legacy `findings_manage` stays a deprecation alias for one release so Devin/Kilo sessions with stale skill docs still work. Additive schema migration runs idempotently on first open; new `about(artifact_sha=…|alias=…|module=…|address=…|target=…)` action answers "what do we know" in one call; `list` defaults to global scope; `record` dedupes on `(title, sha, address)` returning `duplicate_of` when an open match exists; `generate_report` action removed (returns `removed_action` with hint). `ArtifactsConfig.findings_db` new config field so absolute-path pinning avoids the pre-v0.18 cwd-drift that spawned two DBs. One-shot `scripts/migrate_findings_v2.py` consolidates pre-v0.18 knowledge (legacy DBs merged with dedup + refs-parsing, artifacts dir + friendly-name workdirs backfilled, historical .i64 databases in `temp_spoofer/` copied into canonical `artifacts/<sha>/<name>.i64` and registered as closed ida_sessions with `historical_ida_i64` notes carrying the reopen command, parity JSON snapshots imported as notes). Orchestrator-only, no ABI bump, hot-reloadable.


def _list_tool_names(mcp_server) -> list[str]:
    """Best-effort tool enumeration for the startup banner.

    FastMCP 4.x's `list_tools()` is a coroutine — call it via a
    throwaway event loop since build_app is sync. Older releases might
    expose a `_tool_manager` with a sync method; try that first."""
    import asyncio
    for attr in ("_tool_manager", "tool_manager"):
        mgr = getattr(mcp_server, attr, None)
        if mgr is None:
            continue
        listing = getattr(mgr, "list_tools", None)
        if listing is None:
            continue
        try:
            tools = listing()
            return sorted(getattr(t, "name", str(t)) for t in tools)
        except Exception:  # noqa: BLE001
            pass
    lister = getattr(mcp_server, "list_tools", None)
    if lister is None:
        return []
    try:
        tools = asyncio.run(lister())
        return sorted(getattr(t, "name", str(t)) for t in tools)
    except Exception:  # noqa: BLE001 - startup banner never blocks boot
        return []


class _VersionHeaderMiddleware:
    """Pure ASGI middleware that stamps X-Suspex-Server-Version on every
    response.

    BaseHTTPMiddleware (the `@app.middleware("http")` decorator) is
    well-documented to interfere with SSE/streaming responses
    (Starlette #1012, FastAPI #4544): it wraps the body iterator
    through an anyio memory-stream + task, which can add latency,
    break long-running streams, or deadlock. FastMCP's Streamable
    HTTP transport at /mcp uses SSE, so we mutate only the response
    start message and leave the body iterator untouched. This also
    naturally fires on error responses, whereas the old
    BaseHTTPMiddleware skipped its `response.headers[...] = ...`
    line when call_next raised.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _send(message):
            if message["type"] == "http.response.start":
                from starlette.datastructures import MutableHeaders

                MutableHeaders(scope=message)["X-Suspex-Server-Version"] = SERVER_VERSION
            await send(message)

        await self.app(scope, receive, _send)


def build_app(config_path: str | None):
    from fastapi import FastAPI

    from .dashboard.api import register_dashboard_routes

    cfg = load_config(config_path)
    cfg.artifacts_dir().mkdir(parents=True, exist_ok=True)
    cfg.reports_dir().mkdir(parents=True, exist_ok=True)
    cfg.spill_dir().mkdir(parents=True, exist_ok=True)

    session = Session(cfg)
    ledger = FindingsLedger(
        cfg.findings_db(),
        artifacts_dir=cfg.artifacts_dir(),
    )
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), cfg.artifacts_dir())
    # Ghidra engine is opt-in (cfg.ghidra.enabled, default false) — no
    # shim/backend proc is spawned until it is, so a box without Java /
    # Ghidra / pyghidra runs exactly as before. Dormant-but-wired keeps
    # the ghidra_manage tool registered; calls return a typed "disabled"
    # envelope until config flips.
    gbridge = (
        GhidraBridge(GhidraConfigLite.from_config(cfg.ghidra),
                     cfg.artifacts_dir())
        if getattr(cfg, "ghidra", None) is not None and cfg.ghidra.enabled
        else None
    )

    # In-process registries wired into every tool dispatch. Construction is
    # cheap and loop-free; ClientRegistry.start() (which spawns the
    # idle-reap Task) runs later inside the lifespan hook below, once the
    # event loop is up. The publish_event lambda captures clients_reg but
    # is only invoked from LeaseManager.acquire/release inside a running
    # tool call, so asyncio.create_task always has a running loop by the
    # time it fires.
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev))
    )

    ctx = Context(
        cfg=cfg,
        session=session,
        ledger=ledger,
        bridge=bridge,
        gbridge=gbridge,
        clients=clients_reg,
        leases=leases_mgr,
        ownership=ownership_reg,
    )

    mcp_server = build_server(ctx)
    # Stamp CLIENT_ID for every tools/call before any handler runs. Must be
    # installed on the FastMCP server (not the Starlette app) so it scopes
    # to a single JSON-RPC dispatch, not a whole HTTP connection.
    install_caller_middleware(mcp_server)
    mcp_app = None
    if hasattr(mcp_server, "http_app"):
        mcp_app = mcp_server.http_app(path="/mcp")
    elif hasattr(mcp_server, "streamable_http_app"):  # fastmcp < 2.3 fallback
        mcp_app = mcp_server.streamable_http_app()
    if mcp_app is None:
        raise RuntimeError("fastmcp does not expose a streamable-HTTP app factory")

    mcp_lifespan = getattr(mcp_app, "lifespan", None)

    @asynccontextmanager
    async def _lifespan(app_):
        # ClientRegistry.start() creates an asyncio.Task — it MUST run
        # after the event loop is up, which is why it lives here rather
        # than in build_app's synchronous body.
        idle_reap_s = getattr(
            getattr(cfg, "clients", None), "idle_reap_s", 300.0)
        await clients_reg.start(idle_reap_s=idle_reap_s)
        # v0.25: periodic pre-crash snapshot pump. Self-supervising —
        # each tick re-reads session.clients[view], so it idles while
        # the primary view is disconnected and resumes on reconnect
        # without needing a connect hook.
        snap_pump = None
        snap_cfg = getattr(cfg, "snapshots", None)
        if snap_cfg is not None and snap_cfg.enabled and snap_cfg.ranges:
            from .snapshot import SnapshotPump
            snap_pump = SnapshotPump(ctx, session.primary,
                                     snap_cfg.ranges, snap_cfg.interval_s)
            await snap_pump.start()
        try:
            if mcp_lifespan is not None:
                async with mcp_lifespan(app_):
                    yield
            else:
                yield
        finally:
            # Stop the reap task first so it can't fire during teardown;
            # then drop live target views. Both are best-effort — a
            # raising shutdown would mask the underlying reason uvicorn
            # is exiting.
            if snap_pump is not None:
                try:
                    await snap_pump.stop()
                except Exception:  # noqa: BLE001 - shutdown must not raise
                    pass
            try:
                await clients_reg.stop()
            finally:
                try:
                    await session.disconnect()
                except Exception:  # noqa: BLE001 - shutdown must not raise
                    pass

    app = FastAPI(title="suspex0", lifespan=_lifespan)

    tool_names = _list_tool_names(mcp_server)

    @app.get("/health")
    def _health() -> dict:
        # Cheap probe for auto-reconnecting clients / uptime checks. Also
        # publishes the effective server version so a client that cached a
        # stale tool schema knows to refresh after a mismatch.
        return {
            "ok": True,
            "server_version": SERVER_VERSION,
            "tool_count": len(tool_names),
            "tools": tool_names,
            "targets_connected": sorted(getattr(session, "clients", {})),
        }

    @app.get("/health/version")
    def _health_version() -> dict:
        # Minimal poll target for clients that only need the server
        # version string (e.g. a periodic drift check against the schema
        # they cached at connect time). Cheaper than /health because it
        # skips the tool enumeration and target listing.
        return {"server_version": SERVER_VERSION}

    # Advertise the server version on every response (including the
    # mounted MCP app under "/") via a pure ASGI middleware. See
    # `_VersionHeaderMiddleware` above for why BaseHTTPMiddleware is
    # unsafe next to FastMCP's Streamable HTTP / SSE transport.
    app.add_middleware(_VersionHeaderMiddleware)

    # Dashboard routes live on the MCP app (reachable at the MCP port's
    # root for back-compat) AND, when the dashboard has a distinct
    # address, on a dedicated app served on cfg.dashboard.port. The
    # dashboard app shares ctx/session in-process and carries no lifespan
    # of its own — the MCP app owns startup/shutdown.
    register_dashboard_routes(app, ctx)
    app.mount("/", mcp_app)

    dash_app = None
    dash = getattr(cfg, "dashboard", None)
    if dash is not None and dash.enabled and (
            dash.bind, dash.port) != (cfg.mcp.bind, cfg.mcp.port):
        dash_app = FastAPI(title="suspex0-dashboard")
        register_dashboard_routes(dash_app, ctx)
    app.state.dashboard_app = dash_app
    return app, cfg, tool_names


def _port_in_use(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((host, port))
            return True
    except OSError:
        return False


def _takeover(host: str, port: int) -> None:
    """Kill whatever is holding host:port, then wait until the port frees.

    Windows-first (netstat + taskkill) because that is where suspex0
    runs. Best-effort; failure just falls through to the normal bind
    error so operators still see the underlying problem."""
    log = logging.getLogger(__name__)
    try:
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"], text=True, timeout=5)
    except Exception as exc:  # noqa: BLE001
        log.warning("takeover: netstat failed: %s", exc)
        return
    needle = f"{host}:{port}"
    victim: int | None = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3] == "LISTENING":
            if needle in parts[1]:
                try:
                    victim = int(parts[4])
                except ValueError:
                    continue
                break
    if victim is None:
        log.warning("takeover: no listener found on %s:%s", host, port)
        return
    log.warning("takeover: killing pid=%s holding %s:%s", victim, host, port)
    subprocess.run(["taskkill", "/PID", str(victim), "/T", "/F"],
                   capture_output=True, timeout=10)
    for _ in range(20):  # up to 2s
        if not _port_in_use(host, port):
            return
        time.sleep(0.1)


def main() -> None:
    ap = argparse.ArgumentParser(prog="suspex-server")
    ap.add_argument("--config", default=None, help="YAML config path")
    ap.add_argument("--takeover", action="store_true",
                    help="if the MCP port is already bound, kill the "
                         "process holding it and bind anyway. Use when "
                         "iterating on tool code and the previous "
                         "instance's port is still cached by uvicorn.")
    ap.add_argument("--version", action="version",
                    version=f"suspex-server {SERVER_VERSION}")
    args = ap.parse_args()

    _logcfg = load_config(args.config).logging
    _handlers: list[logging.Handler] = [logging.StreamHandler()]
    if _logcfg.file:
        try:
            _handlers.append(logging.FileHandler(_logcfg.file))
        except OSError as exc:  # unwritable path — keep stderr, don't die
            logging.getLogger(__name__).warning(
                "log file %s unusable: %s", _logcfg.file, exc)
    logging.basicConfig(
        level=getattr(logging, str(_logcfg.level).upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=_handlers)

    # MCP clients that ignore ``structuredContent`` (e.g. the Devin
    # bridge, which renders only ``content[0].text``) otherwise see
    # empty tool responses — default to the dual-emit envelope. Set
    # =0 to opt back into the A-1 single-encode shape.
    os.environ.setdefault("SUSPX_MCP_LEGACY_DUAL_CONTENT", "1")

    import uvicorn

    app, cfg, tool_names = build_app(args.config)
    if args.takeover and _port_in_use(cfg.mcp.bind, cfg.mcp.port):
        _takeover(cfg.mcp.bind, cfg.mcp.port)
    if cfg.ida.enabled:
        try:
            IdaBridge(IdaConfigLite.from_config(cfg.ida), cfg.artifacts_dir()).precheck()
        except Exception as exc:
            logging.getLogger(__name__).warning("%s", exc)
    if getattr(cfg, "ghidra", None) is not None and cfg.ghidra.enabled:
        try:
            GhidraBridge(GhidraConfigLite.from_config(cfg.ghidra),
                         cfg.artifacts_dir()).precheck()
        except Exception as exc:
            logging.getLogger(__name__).warning("%s", exc)
    dash_app = getattr(app.state, "dashboard_app", None)
    if dash_app is not None:
        # Own port — what the config advertises.
        dash_url = f"http://{cfg.dashboard.bind}:{cfg.dashboard.port}/"
    elif getattr(cfg.dashboard, "enabled", False):
        # Collapsed onto the MCP port (same bind/port) — served at its root
        # next to the mounted MCP app.
        dash_url = f"http://{cfg.mcp.bind}:{cfg.mcp.port}/"
    else:
        dash_url = "disabled"
    print(f"suspex0 orchestrator {SERVER_VERSION}: {len(tool_names)} tools "
          f"({', '.join(tool_names) if tool_names else 'unknown'}), "
          f"MCP on http://{cfg.mcp.bind}:{cfg.mcp.port}/mcp "
          f"(health: /health), "
          f"dashboard on {dash_url}")
    if dash_app is None:
        uvicorn.run(app, host=cfg.mcp.bind, port=cfg.mcp.port, log_level="info")
        return
    # Two servers in one loop: the MCP server is authoritative; a failure
    # to bind the dashboard port (e.g. a stale instance holding it) is
    # logged but must NOT take the MCP server down with it.
    async def _serve_both() -> None:
        mcp_srv = uvicorn.Server(uvicorn.Config(
            app, host=cfg.mcp.bind, port=cfg.mcp.port, log_level="info"))
        dash_srv = uvicorn.Server(uvicorn.Config(
            dash_app, host=cfg.dashboard.bind, port=cfg.dashboard.port,
            log_level="warning"))

        async def _dash() -> None:
            # uvicorn raises SystemExit (not Exception) when it can't bind —
            # catch both so a taken dashboard port only logs and never
            # takes the MCP server down. CancelledError (BaseException, not
            # Exception/SystemExit) still propagates for clean shutdown.
            try:
                await dash_srv.serve()
            except (Exception, SystemExit) as exc:  # noqa: BLE001 — best-effort
                logging.getLogger(__name__).warning(
                    "dashboard server on %s:%s failed to start: %s",
                    cfg.dashboard.bind, cfg.dashboard.port, exc)

        await asyncio.gather(mcp_srv.serve(), _dash())

    asyncio.run(_serve_both())


if __name__ == "__main__":
    sys.exit(main())
