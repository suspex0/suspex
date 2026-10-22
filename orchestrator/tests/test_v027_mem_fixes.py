"""v0.27 mem_rw regression tests, end-to-end through the tool surface.

Two fixes exercised here:

1. `gle=59` (the Win32 projection of STATUS_UNEXPECTED_IO_ERROR and the
   MMIO/BAR read-failure family) classifies as ``invalid_address`` — the
   driver was loaded and healthy; the ADDRESS is the fault. Previously
   it fell through to the driver catch-all and told callers to run
   driver_load.
2. `pattern_scan` accepts nibble wildcards ('6?'/'?F'); on the
   whole-space (agent-side) path they're downgraded to '?' on the wire
   and each candidate is re-read + verified client-side.
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

pytestmark = pytest.mark.asyncio


class _MmioClient:
    """mem_read on the BAR-backed page fails like a real driver:
    'driver: DeviceIoControl gle=59 nt=0xc00000e9'."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:0",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_read(self, pid, addr, n, space, **kw):
        raise RuntimeError(
            "driver: DeviceIoControl gle=59 nt=0xc00000e9")


async def _server(tmp_path, monkeypatch, client_cls):
    monkeypatch.setattr("suspex.session.AgentClient", client_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", client_cls)

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
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(publish_event=lambda ev:
                                      asyncio.create_task(
                                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


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
        return {"raw": body}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    err = body.get("error")
    if isinstance(err, dict):
        merged.update(err)
    merged.setdefault("ok", body.get("ok"))
    return merged


async def test_gle59_kernel_read_is_invalid_address(tmp_path, monkeypatch):
    """The reported case: a page-table-valid kernel VA backed by a BAR —
    va_translate succeeds, mem_rw read fails gle=59, and the driver was
    never absent. The envelope must point at the address, not the
    driver."""
    _ctx, server = await _server(tmp_path, monkeypatch, _MmioClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0xffff830dac700000", "size": 8})
    assert body["ok"] is False, body
    assert body["kind"] == "invalid_address", body
    # The raw gle/nt text survives in the error string.
    assert "gle=59" in body["error"]
    assert "driver_load" not in body.get("hint", "")


# --- whole-space nibble scan ---------------------------------------------


class _ScanClient:
    """mem_scan honors the BYTE-granular wire mask ('?' vs exact) like a
    real agent; mem_read serves the underlying pages so the client-side
    nibble post-filter can verify candidates."""

    PAGES = {
        0x1000: (b"\x90" * 8 + b"\x4d\x6f\x8f\x00" + b"\x90" * 52),
        0x2000: (b"\x90" * 8 + b"\x4d\x70\x8f\x00" + b"\x90" * 52),
    }

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.wire_masks: list[str] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:0",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_read(self, pid, addr, n, space, **kw):
        page = self.PAGES.get(addr & ~0xFFF)
        if page is None:
            raise RuntimeError("STATUS_INVALID_ADDRESS")
        off = addr - (addr & ~0xFFF)
        return page[off:off + n]

    async def mem_scan(self, pid, pattern, mask, base, size,
                       max_results, space):
        self.wire_masks.append(mask)
        hits = []
        for start, page in self.PAGES.items():
            for i in range(len(page) - len(pattern) + 1):
                ok = True
                for j, b in enumerate(pattern):
                    if mask[j] != "?" and page[i + j] != b:
                        ok = False
                        break
                if ok:
                    hits.append(start + i)
        return hits[:max_results]


async def test_whole_space_nibble_scan_postfilters(tmp_path, monkeypatch):
    """'4D 6? ?F 00' — the wire mask goes out as 'x??x' (agent-side
    byte granularity), and only the true nibble hit survives."""
    ctx, server = await _server(tmp_path, monkeypatch, _ScanClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "pattern_scan", "space": "kernel",
        "pattern": "4D 6? ?F 00"})
    assert body["ok"] is True, body
    items = body.get("items") or []
    # 0x1008 matches (0x6F high-nibble=6, 0x8F low-nibble=F);
    # 0x2008 fails the high-nibble pin (0x70&0xF0=0x70).
    assert items == ["0x1008"], items
    c = None
    for cl in ctx.session.clients.values():
        c = cl
    assert c is not None and c.wire_masks == ["x??x"]


async def test_pool_scan_rejects_nibble_mask(tmp_path, monkeypatch):
    """pool_scan's driver matcher is byte-granular — a nibble mask must
    fail fast, not silently round to exact bytes."""
    _ctx, server = await _server(tmp_path, monkeypatch, _ScanClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "pool_scan", "space": "kernel",
        "pattern": "4D 6?", "size": 0x40})
    assert body["ok"] is False, body
    assert body["kind"] == "bad_arg"
    assert "nibble" in body["error"]
