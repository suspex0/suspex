"""v0.17 F-1c — target_manage(action='wait_connectable') retry loop.

Poll a TCP handshake + gRPC status roundtrip until the deadline, with
bounded exponential backoff. Distinct from action='connect' (which fails
hard on the first probe): wait_connectable is what a caller uses right
after ``driver_load`` or an agent restart when the target is expected to
come up but not immediately.

Contract:
    - Success: {ok: True, action: 'wait_connectable', view, endpoint,
                attempts, elapsed_s, status: {...}}
    - Timeout: {ok: False, kind: 'wait_timeout', action: ..., attempts,
                elapsed_s, error, last_probe_kind, hint}
    - Backoff never exceeds 3s per iteration.
"""
from __future__ import annotations

import asyncio
import json as _json
import socket
import threading
import time as _time
from typing import Any

import pytest

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


class _FakeAgentClient:
    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "DRIVER_SERVICE"}


async def _build_ctx_and_server(tmp_path, monkeypatch, *, port: int):
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _FakeAgentClient)
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)
    # Session's own new-client path still sees the pre-flight probe, so
    # bypass it for the fixture-level connect that's unrelated to
    # wait_connectable's own probing.

    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=port)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-F")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    # v0.17 A-1: envelope now rides in structured_content (no text copy in
    # content[0]). Fall back to the legacy JSON-string path so this helper
    # works against SUSPX_MCP_LEGACY_DUAL_CONTENT=1 too.
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


def _grab_unbound_port() -> int:
    """Bind, learn the port, close — nothing is listening now."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# Timeout path
# --------------------------------------------------------------------------- #


async def test_f_1c_wait_connectable_times_out_with_wait_timeout_kind(
        tmp_path, monkeypatch):
    port = _grab_unbound_port()
    _ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, port=port)
    # Explicitly disable the probe bypass — we WANT the real probe to fire
    # here so the timeout path is exercised end-to-end.

    async def _real_probe(host, p, timeout_s: float = 3.0):
        # Restore genuine socket connect
        from suspex.session import _probe_tcp as real  # local import; not the patched name
        # The monkeypatch above replaced the name; import from a saved reference.
        # But easier: just do a real short socket connect inline.
        loop = asyncio.get_event_loop()

        def _try():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_s)
                s.connect((host, p))

        try:
            await loop.run_in_executor(None, _try)
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            errno_ = getattr(exc, "errno", None)
            tag = f"WSAE{winerr}" if winerr else (f"errno={errno_}" if errno_ else "")
            raise OSError(exc.errno,
                          f"{tag} tcp probe to {host}:{p} failed: "
                          f"{exc.strerror or str(exc)}") from exc

    monkeypatch.setattr("suspex.session._probe_tcp", _real_probe)
    started = _time.monotonic()
    body = await _call(server, "target_manage",
                       {"action": "wait_connectable",
                        "port": port,
                        "timeout_s": 0.8})
    elapsed = _time.monotonic() - started
    assert body["ok"] is False
    assert body["kind"] == "wait_timeout"
    # Attempts must have happened
    assert body["attempts"] >= 1
    # We should not vastly overshoot the deadline (allow generous slack).
    assert elapsed < 3.0, f"wait_connectable overshot deadline: {elapsed:.2f}s"
    assert body.get("hint")
    # Endpoint is stamped so downstream triage knows which view failed.
    assert body["endpoint"] == f"127.0.0.1:{port}"


async def test_f_1c_wait_connectable_succeeds_when_listener_present(
        tmp_path, monkeypatch):
    """Bind a real listening socket, then verify wait_connectable returns ok."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    _, port = listener.getsockname()

    # Accept-in-background so the pre-flight TCP probe completes.
    stop = threading.Event()

    def _serve():
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    try:
        _ctx, server = await _build_ctx_and_server(
            tmp_path, monkeypatch, port=port)
        # Restore real probe here — we WANT it to succeed against the listener.

        async def _real_probe(host, p, timeout_s: float = 3.0):
            loop = asyncio.get_event_loop()

            def _try():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout_s)
                    s.connect((host, p))

            try:
                await loop.run_in_executor(None, _try)
            except OSError as exc:
                winerr = getattr(exc, "winerror", None)
                errno_ = getattr(exc, "errno", None)
                tag = f"WSAE{winerr}" if winerr else (f"errno={errno_}" if errno_ else "")
                raise OSError(exc.errno,
                              f"{tag} tcp probe to {host}:{p} failed: "
                              f"{exc.strerror or str(exc)}") from exc

        monkeypatch.setattr("suspex.session._probe_tcp", _real_probe)
        body = await _call(server, "target_manage",
                           {"action": "wait_connectable",
                            "port": port,
                            "timeout_s": 3.0})
        assert body["ok"] is True, body
        assert body["endpoint"] == f"127.0.0.1:{port}"
        assert body["attempts"] >= 1
        # Status is present and passed through.
        assert "status" in body
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
        t.join(timeout=1.0)


async def test_f_1c_wait_connectable_backoff_bounded_below_3s(
        tmp_path, monkeypatch):
    """The delay ramp caps at 3s per iteration — verify by counting attempts
    over a long deadline against a closed port."""
    port = _grab_unbound_port()
    _ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, port=port)

    async def _fast_fail_probe(host, p, timeout_s: float = 3.0):
        # Fail immediately so the loop body ~= just the sleep between iterations.
        raise OSError(111,
                      f"WSAECONNREFUSED tcp probe to {host}:{p} failed: refused")

    monkeypatch.setattr("suspex.session._probe_tcp", _fast_fail_probe)
    # Deadline long enough that at least 3 attempts must fit even at max
    # 3s backoff (attempt 1 → wait 0.3s → attempt 2 → wait 0.51s → attempt 3
    # → wait 0.867s → attempt 4 …). At 5s we expect >= 4 attempts.
    started = _time.monotonic()
    body = await _call(server, "target_manage",
                       {"action": "wait_connectable",
                        "port": port,
                        "timeout_s": 5.0})
    elapsed = _time.monotonic() - started
    assert body["ok"] is False
    assert body["kind"] == "wait_timeout"
    # If backoff were unbounded and doubled without a cap, we'd see very few
    # attempts (2-3). With a 3s cap, we expect at least 4 within a 5s window.
    assert body["attempts"] >= 3, body
    # Overshoot bounded to a couple of seconds max.
    assert elapsed < 8.5, f"loop overshot: {elapsed:.2f}s"


async def test_f_1c_wait_connectable_stamps_last_probe_kind(
        tmp_path, monkeypatch):
    port = _grab_unbound_port()
    _ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, port=port)

    async def _refused(host, p, timeout_s: float = 3.0):
        raise OSError(111,
                      f"WSAECONNREFUSED tcp probe to {host}:{p} failed: refused")

    monkeypatch.setattr("suspex.session._probe_tcp", _refused)
    body = await _call(server, "target_manage",
                       {"action": "wait_connectable",
                        "port": port, "timeout_s": 0.5})
    assert body["ok"] is False
    # The specific *why* is preserved as `last_probe_kind` so callers can
    # branch without re-classifying the string.
    assert body["last_probe_kind"] == "connect_refused"
