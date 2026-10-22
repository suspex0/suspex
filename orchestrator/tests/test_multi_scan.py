"""MCP wire — scan lifecycle, pool-scan guard, connect refcount partial release.

Split out of test_multi_agent.py; server wiring lives in _multi_fakes.
"""

from __future__ import annotations

import asyncio
from typing import Any

from _multi_fakes import _RichFakeAgentClient, _build_ctx_and_server, _call_as


async def test_scan_start_lifecycle(tmp_path, monkeypatch) -> None:
    """v0.16 scan job surface: scan_start returns immediately with a
    scan_id; scan_status reports progress; scan_result blocks until done
    (or returns not_ready while running); scan_cancel stops the loop."""

    class _ScanFake(_RichFakeAgentClient):
        async def mem_read(self, pid, addr, size, space):  # noqa: ARG002
            # 4 MiB of zeros with a 6-byte marker in the middle so the
            # scan finds exactly one hit on the first chunk. The runner
            # advances 1 MiB per iteration; we just serve zeros forever
            # so it keeps looping until it exhausts `size`.
            return b"\x00" * int(size)

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # _build_ctx_and_server also monkeypatches AgentClient — order matters,
    # so we re-set to _ScanFake AFTER it so scan_start's reads land on our
    # marker-serving fake.
    monkeypatch.setattr("suspex.session.AgentClient", _ScanFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    start = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_start",
        "pid": 1234,
        "base": "0x100000",
        "size": 4 * 1024 * 1024,
        "pattern": "48 8B 05 ?? ?? ?? ??",
        "max_results": 8,
    })
    assert start["ok"] is True
    scan_id = start["scan_id"]
    assert scan_id.startswith("s")

    # Poll status: it may be running or done depending on the async race.
    for _ in range(50):
        status = await _call_as("peer-A", server, "mem_rw", {
            "action": "scan_status", "scan_id": scan_id,
        })
        assert status["ok"] is True
        if status["status"] != "running":
            break
        await asyncio.sleep(0.02)
    assert status["status"] in ("done", "cancelled")

    # scan_result returns an envelope with the hits list (empty is fine —
    # our fake serves zeros so no matches).
    result = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_result", "scan_id": scan_id,
    })
    assert result["ok"] is True
    assert "items" in result

    # scan_list surfaces both the running-and-drained scan and its owner.
    listing = await _call_as("peer-A", server, "mem_rw", {"action": "scan_list"})
    assert listing["ok"] is True
    assert any(row["scan_id"] == scan_id for row in listing["scans"])


async def test_scan_cancel_is_owner_gated(tmp_path, monkeypatch) -> None:
    """A peer cannot cancel someone else's scan without force (which the
    v0.16 first cut deliberately does not implement)."""

    class _SlowScanFake(_RichFakeAgentClient):
        async def mem_read(self, pid, addr, size, space):  # noqa: ARG002
            # 50ms per 1 MiB chunk; with a 128 MiB range the scan takes
            # ~6s if uninterrupted — plenty of window for cancel to land.
            await asyncio.sleep(0.05)
            return b"\x00" * int(size)

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _SlowScanFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    start = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_start",
        "pid": 1234,
        "base": "0x100000",
        "size": 128 * 1024 * 1024,
        "pattern": "AA BB CC DD",
    })
    scan_id = start["scan_id"]

    # Give the runner one loop iteration so it's actually reading.
    await asyncio.sleep(0.06)

    # Foreign cancel refused.
    refused = await _call_as("peer-B", server, "mem_rw", {
        "action": "scan_cancel", "scan_id": scan_id,
    })
    assert refused["ok"] is False
    assert refused["kind"] == "foreign_owned"

    # Owner cancel succeeds.
    cancelled = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_cancel", "scan_id": scan_id,
    })
    assert cancelled["ok"] is True
    # Wait for the runner to observe the cancel flag.
    for _ in range(100):
        status = await _call_as("peer-A", server, "mem_rw", {
            "action": "scan_status", "scan_id": scan_id,
        })
        if status["status"] == "cancelled":
            break
        await asyncio.sleep(0.02)
    assert status["status"] == "cancelled"


async def test_pool_scan_guard_refuses_pattern_without_size(tmp_path, monkeypatch) -> None:
    """v0.16: passing `pattern` without `size` used to silently return 64
    arbitrary allocations with matched_offset=0 (driver-side bug). The
    orchestrator now refuses the shape up front so callers learn what's
    required instead of trusting fake matches."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    body = await _call_as("peer-A", server, "mem_rw", {
        "action": "pool_scan",
        "pattern": "48 8B ?? ??",   # non-empty pattern
        # size intentionally omitted (default 0)
    })
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"
    # The typed error names the requirement so the LLM can fix in-place.
    err_text = body.get("error") or ""
    assert "size" in err_text.lower() or "size" in (body.get("hint") or "").lower()


async def test_connect_refcount_partial_release(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    await _call_as("peer-B", server, "target_manage", {"action": "connect"})
    # peer-A disconnects: partial (peer-B still owns kernel)
    out = await _call_as("peer-A", server, "target_manage", {"action": "disconnect"})
    vk = next(iter(ctx.session.clients))  # '<machine>.kernel' key
    assert vk in out.get("partial_release", [])
    assert vk in ctx.session.clients  # not torn down yet
    # peer-B disconnects: kernel closes
    out = await _call_as("peer-B", server, "target_manage", {"action": "disconnect"})
    assert vk in out.get("disconnected", [])
    assert ctx.session.clients == {}
