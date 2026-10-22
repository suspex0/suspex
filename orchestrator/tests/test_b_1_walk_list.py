"""v0.17 B-1c — `mem_rw walk_list` — follow a linked list by hopping
`next_offset` bytes into each node to read the next pointer.

Coverage:
- null-terminated list stops at 0.
- self-referential list stops at the first repeat.
- max_hops cap stops after N iterations.
- per-node decode= surfaces typed values on every node.
"""
from __future__ import annotations

import asyncio
import json as _json
import struct
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


class _WalkFake:
    """Fake AgentClient that serves a memory map from a dict[VA -> bytes]."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self.memory: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        # Look up the seeded region containing `addr`, then slice from the
        # offset — mimics the driver's arbitrary-range read.
        for base, buf in self.memory.items():
            if base <= addr < base + len(buf):
                offset = addr - base
                return buf[offset:offset + size]
        raise RuntimeError(f"unmapped VA 0x{addr:X}")


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _WalkFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _WalkFake)

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
    return merged


def _seed_linked_list(fake: _WalkFake, *, base: int, nexts: list[int],
                      next_off: int = 0) -> None:
    """Populate ``fake.memory`` with a linked list at ``base`` whose Flink
    is ``next_offset`` bytes into each node. Each entry in ``nexts`` is the
    Flink of the corresponding node; 0 terminates."""
    va = base
    for nxt in nexts:
        # Zero-pad the node up to next_off+8 so the mem_read for the ptr
        # succeeds. We also seed 8 bytes at the node start so a decode
        # request can pull a u64.
        node_bytes = bytearray(max(8, next_off + 8))
        # Node-start payload: mark the node with its base VA so decode can
        # verify it.
        struct.pack_into("<Q", node_bytes, 0, va)
        struct.pack_into("<Q", node_bytes, next_off, nxt)
        fake.memory[va] = bytes(node_bytes)
        if nxt == 0 or nxt == base:
            break
        va = nxt


async def test_b_1c_walk_list_null_terminated(tmp_path, monkeypatch) -> None:
    """A 0-terminated linked list stops at the null Flink."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    _seed_linked_list(fake, base=0x1000, nexts=[0x2000, 0x3000, 0], next_off=0)
    body = await _call(server, "mem_rw", {
        "action": "walk_list", "space": "kernel",
        "address": "0x1000", "value": "0",  # next_offset=0
    })
    assert body["ok"] is not False
    assert body["stopped_at"] == "null"
    vas = [n["va"] for n in body["nodes"]]
    assert vas == ["0x1000", "0x2000", "0x3000"]


async def test_b_1c_walk_list_self_loop(tmp_path, monkeypatch) -> None:
    """A circular list stops when we revisit a node."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    # 0x1000 -> 0x2000 -> 0x1000 (loop)
    _seed_linked_list(fake, base=0x1000, nexts=[0x2000, 0x1000], next_off=0)
    body = await _call(server, "mem_rw", {
        "action": "walk_list", "space": "kernel",
        "address": "0x1000", "value": "0",
    })
    assert body["ok"] is not False
    assert body["stopped_at"] == "self"
    vas = [n["va"] for n in body["nodes"]]
    assert vas == ["0x1000", "0x2000"]


async def test_b_1c_walk_list_max_hops(tmp_path, monkeypatch) -> None:
    """max_hops (via count=) caps the walk length."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    # 5-node null-terminated chain but we cap at 3.
    _seed_linked_list(fake, base=0x1000,
                      nexts=[0x2000, 0x3000, 0x4000, 0x5000, 0], next_off=0)
    body = await _call(server, "mem_rw", {
        "action": "walk_list", "space": "kernel",
        "address": "0x1000", "value": "0",
        "count": 3,
    })
    assert body["ok"] is not False
    assert body["stopped_at"] == "max_hops"
    assert body["node_count"] == 3


async def test_b_1c_walk_list_with_decode(tmp_path, monkeypatch) -> None:
    """decode='u64' pulls the node-start u64 (the base VA we seeded) on
    every node."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    _seed_linked_list(fake, base=0x1000,
                      nexts=[0x2000, 0], next_off=0x8)  # 8-byte header, 8-byte Flink
    body = await _call(server, "mem_rw", {
        "action": "walk_list", "space": "kernel",
        "address": "0x1000", "value": "0x8",
        "size": 8, "decode": "u64",
    })
    assert body["ok"] is not False
    # Each node's decode.values[0] equals its own base VA per the fixture.
    values = [n.get("values", [None])[0] for n in body["nodes"]]
    assert values == [0x1000, 0x2000]
