"""v0.22 Phase 3 — physical-scan coverage reporting.

`pattern_scan` used to report only aggregate counters
(`bytes_scanned`/`chunks_skipped`), so a sweep over physical memory
couldn't say WHICH ranges were read vs skipped vs never reached. The
scanner now tracks the (start,end) interval of every read/skip and the
telemetry envelope carries a merged `coverage` map whose three lists
partition the caller's range:

    coverage.scanned   ∪ coverage.skipped   ∪ coverage.unscanned
                     = [start, end)
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any

import pytest

from suspex.sdk.scan import (_coverage_map, _scan_range_impl,
                             merge_coverage)

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


class _PagedView:
    """Reads `gran` pages; pages in `bad` raise like an unmapped page."""

    def __init__(self, bad: set[int], gran: int = 0x1000) -> None:
        self.bad = set(bad)
        self.gran = gran

    async def read(self, pid, addr, n, space):
        if addr & ~(self.gran - 1) in self.bad or addr in self.bad:
            raise RuntimeError("STATUS_INVALID_ADDRESS")
        # Any read that TOUCHES a bad page fails (the driver's
        # whole-chunk refusal semantics).
        for p in range(addr, addr + n, self.gran):
            if p in self.bad or (p & ~(self.gran - 1)) in self.bad:
                raise RuntimeError("STATUS_INVALID_ADDRESS")
        return b"\x90" * n


def _spans(rows):
    return [(int(r["start"], 16), int(r["end"], 16)) for r in rows]


async def test_coverage_partitions_range_with_hole() -> None:
    """One unreadable page -> scanned spans + skipped span + no
    unscanned tail."""
    view = _PagedView(bad={0x2000})
    hits, telem = await _scan_range_impl(
        view, 0, 0x0, 0x4000, b"\xAA", "", "physical",
        chunk=0x1000, max_results=64)
    cov = telem["coverage"]
    assert _spans(cov["skipped"]) == [(0x2000, 0x3000)]
    scanned = _spans(cov["scanned"])
    assert scanned == [(0x0, 0x2000), (0x3000, 0x4000)]
    assert _spans(cov["unscanned"]) == []
    assert cov["scanned_ranges"] == 2
    assert cov["skipped_ranges"] == 1


async def test_coverage_marks_unreached_tail() -> None:
    """max_results early-stop leaves the tail in `unscanned`."""
    view = _PagedView(bad=set())
    hits, telem = await _scan_range_impl(
        view, 0, 0x0, 0x4000, b"\x90", "", "physical",
        chunk=0x1000, max_results=1)   # hits on the first byte
    cov = telem["coverage"]
    assert telem["truncated"] is True
    unscanned = _spans(cov["unscanned"])
    assert unscanned and unscanned[-1][1] == 0x4000
    assert unscanned[0][0] >= 0x1000  # only the first chunk was read


async def test_coverage_partial_salvage_counts_as_scanned() -> None:
    """A chunk whose head pages read but tail fails records the salvaged
    prefix as scanned, the remainder as skipped."""
    view = _PagedView(bad={0x3000})
    hits, telem = await _scan_range_impl(
        view, 0, 0x0, 0x4000, b"\xAA", "", "physical",
        chunk=0x4000, max_results=64)
    # Whole-range read fails at 0x3000; per-page salvage keeps
    # [0,0x3000), then the outer loop skips [0x3000,0x4000).
    cov = telem["coverage"]
    assert _spans(cov["scanned"]) == [(0x0, 0x3000)]
    assert _spans(cov["skipped"]) == [(0x3000, 0x4000)]
    assert telem["partial_chunks"] == 1


def test_coverage_map_unit() -> None:
    cov = _coverage_map([(0, 0x1000), (0x800, 0x1800)],
                        [(0x2000, 0x3000)], 0x0, 0x4000)
    assert _spans(cov["scanned"]) == [(0x0, 0x1800)]
    assert _spans(cov["skipped"]) == [(0x2000, 0x3000)]
    assert _spans(cov["unscanned"]) == [(0x1800, 0x2000), (0x3000, 0x4000)]


def test_merge_coverage_drops_unscanned() -> None:
    a = _coverage_map([(0, 0x1000)], [], 0x0, 0x2000)
    b = _coverage_map([(0x5000, 0x6000)], [(0x6000, 0x7000)],
                      0x5000, 0x8000)
    merged = merge_coverage([a, b])
    assert _spans(merged["scanned"]) == [(0x0, 0x1000), (0x5000, 0x6000)]
    assert _spans(merged["skipped"]) == [(0x6000, 0x7000)]
    assert "unscanned" not in merged
    assert merged["merged_spans"] == 2


# --- end-to-end through mem_rw pattern_scan --------------------------------

class _PhysAgentClient:
    """mem_read fails on the 0x2000 page — like an unmapped PA hole."""

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
        for p in range(addr, addr + n, 0x1000):
            if p & ~0xFFF == 0x2000:
                raise RuntimeError("STATUS_INVALID_ADDRESS")
        return b"\x90" * n


async def _server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _PhysAgentClient)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _PhysAgentClient)

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
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    return merged


async def test_pattern_scan_physical_coverage_end_to_end(
        tmp_path, monkeypatch) -> None:
    """A physical pattern_scan over a hole reports scanned + skipped
    spans in the response extras."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    # '4D 5A' never appears in the \x90-filled fake pages, so the sweep
    # runs to the end instead of stopping on the max_results hit cap.
    body = await _call(server, "mem_rw", {
        "action": "pattern_scan", "space": "physical",
        "address": "0x0", "size": 0x4000, "pattern": "4D 5A"})
    assert body["ok"] is True, body
    cov = body.get("coverage")
    assert cov is not None, f"no coverage in {sorted(body)}"
    assert _spans(cov["skipped"]) == [(0x2000, 0x3000)]
    scanned = _spans(cov["scanned"])
    assert scanned[0] == (0x0, 0x2000)
    assert scanned[-1] == (0x3000, 0x4000)
    assert _spans(cov["unscanned"]) == []
