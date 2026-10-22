"""v0.17 B-5 — `mem_rw write` `verify=true` atomic write-then-read-back.

Four cases exercised:

- write with verify=true; readback matches payload -> verified:true
- write with verify=true; readback differs -> verified:false + diff_offset,
  expected_hex, actual_hex, actionable hint
- write with verify=true; readback throws -> verified:false + read_back_error
  + hint about write-only / fenced ranges
- write with verify=true; payload > 64 KiB -> warning appended so callers know
  verify doubles bandwidth
"""
from __future__ import annotations

import asyncio
import json as _json
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


class _WriteVerifyFake:
    """Fake AgentClient — mem_write records the payload; mem_read replays
    whatever the test seeded via ``.seed_readback``. When
    ``.seed_readback_error`` is set, mem_read raises instead."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.writes: list[tuple[int, bytes]] = []
        self.seed_readback: bytes | None = None
        self.seed_readback_error: str = ""

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_write(self, pid: int, addr: int, data: bytes, space: str,
                        allow_map_write: bool = False, **kw: Any) -> int:
        self.writes.append((addr, bytes(data)))
        return len(data)

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        if self.seed_readback_error:
            raise RuntimeError(self.seed_readback_error)
        if self.seed_readback is None:
            # By default replay the last write so verify=true passes.
            _addr, buf = self.writes[-1] if self.writes else (0, b"")
            return buf[:size]
        return self.seed_readback[:size]


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls):
    monkeypatch.setattr("suspex.session.AgentClient", fake_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", fake_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
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
    """Return {data-fields..., ok, kind, warnings} merged from the envelope."""
    token = CLIENT_ID.set("peer-B")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
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
    # B-5: warnings are at the OUTER envelope level, not under data.
    if "warnings" in body:
        merged["warnings"] = body["warnings"]
    return merged


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


async def test_b_5_write_verify_pass(tmp_path, monkeypatch) -> None:
    """verify=true, readback == payload -> verified:true."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _WriteVerifyFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "write", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "data_hex": "deadbeefcafebabe",
        "verify": True,
    })
    assert body["ok"] is True
    assert body["verified"] is True
    assert body["written"] == 8
    # No warning under the 64 KiB threshold.
    assert not body.get("warnings")


async def test_b_5_write_verify_diff(tmp_path, monkeypatch) -> None:
    """verify=true, readback differs -> verified:false + diff_offset +
    expected_hex + actual_hex + actionable hint."""

    class _DiffFake(_WriteVerifyFake):
        pass

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, _DiffFake)
    await _call(server, "target_manage", {"action": "connect"})
    # Seed a readback that differs at byte 2.
    fake_client = ctx.session.require_client()
    fake_client.seed_readback = bytes.fromhex("deadff00cafebabe")
    body = await _call(server, "mem_rw", {
        "action": "write", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "data_hex": "deadbeefcafebabe",
        "verify": True,
    })
    assert body["ok"] is True
    assert body["verified"] is False
    assert body["diff_offset"] == 2
    # Expected first-16-byte window from the payload.
    assert body["expected_hex"].startswith("beef")
    # Actual first-16-byte window from the readback.
    assert body["actual_hex"].startswith("ff00")
    assert "readback" in body["hint"].lower() or "differs" in body["hint"].lower()


async def test_b_5_write_verify_readback_fails(tmp_path, monkeypatch) -> None:
    """verify=true, readback raises -> verified:false + read_back_error +
    fence/write-only hint."""

    class _ThrowFake(_WriteVerifyFake):
        pass

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, _ThrowFake)
    await _call(server, "target_manage", {"action": "connect"})
    fake_client = ctx.session.require_client()
    fake_client.seed_readback_error = "STATUS_ACCESS_VIOLATION"
    body = await _call(server, "mem_rw", {
        "action": "write", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "data_hex": "aabbccdd",
        "verify": True,
    })
    assert body["ok"] is True
    assert body["verified"] is False
    assert "STATUS_ACCESS_VIOLATION" in body.get("read_back_error", "")
    hint = body.get("hint", "").lower()
    assert "write-only" in hint or "fenced" in hint or "unmapped" in hint


async def test_b_5_write_verify_large_warns(tmp_path, monkeypatch) -> None:
    """A payload > 64 KiB with verify=true attaches a warning about the
    doubled bandwidth so the caller can drop verify for the large case."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _WriteVerifyFake)
    await _call(server, "target_manage", {"action": "connect"})
    # Craft a ~72 KiB hex payload.
    big = b"\xAB" * (72 * 1024)
    body = await _call(server, "mem_rw", {
        "action": "write", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "data_hex": big.hex(),
        "verify": True,
    })
    assert body["ok"] is True
    assert body["verified"] is True
    warnings = body.get("warnings") or []
    assert any("verify" in w.lower() and "bandwidth" in w.lower()
               for w in warnings), warnings


async def test_b_5_write_without_verify_matches_legacy(
        tmp_path, monkeypatch) -> None:
    """verify=false (default) preserves the pre-B-5 legacy response shape:
    {ok:true, written:N} with no verified/warnings keys."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _WriteVerifyFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "write", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "data_hex": "cafe",
    })
    assert body["ok"] is True
    assert body["written"] == 2
    assert "verified" not in body
