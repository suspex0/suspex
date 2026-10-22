"""v0.17 B-1a — `mem_rw read` `decode=` + `conversions.decode_buffer`.

Pure-compute unit tests over ``conversions.decode_buffer`` plus one
integration test that drives `mem_rw read` through the FastMCP server
with decode=[...] and asserts the values/layout/hex/ascii shape.
"""
from __future__ import annotations

import asyncio
import json as _json
import struct
from typing import Any

import pytest

from suspex.mcp.conversions import (
    ConversionError, decode_buffer, _expand_spec,
)

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
# decode_buffer — pure-compute
# --------------------------------------------------------------------------- #


def test_decode_buffer_u64_scalar() -> None:
    """One u64 unpacks little-endian, values length 1, no remainder."""
    raw = struct.pack("<Q", 0xDEADBEEFCAFEBABE)
    result = decode_buffer(raw, "u64")
    assert result["values"] == [0xDEADBEEFCAFEBABE]
    assert result["layout"] == [{"offset": 0, "type": "u64", "size": 8}]
    assert result["consumed_bytes"] == 8
    assert result["remainder_hex"] == ""
    assert result["truncated"] is False


def test_decode_buffer_u32_array_shorthand() -> None:
    """`u32[3]` unpacks three u32s in a row."""
    raw = struct.pack("<3I", 0x11111111, 0x22222222, 0x33333333)
    result = decode_buffer(raw, "u32[3]")
    assert result["values"] == [0x11111111, 0x22222222, 0x33333333]
    assert [row["offset"] for row in result["layout"]] == [0, 4, 8]


def test_decode_buffer_fill_shorthand_matches_buffer() -> None:
    """`u64[]` fills as many u64s as fit and leaves no remainder."""
    raw = struct.pack("<3Q", 0xA, 0xB, 0xC)
    result = decode_buffer(raw, "u64[]")
    assert result["values"] == [0xA, 0xB, 0xC]
    assert result["remainder_hex"] == ""


def test_decode_buffer_mixed_list_form() -> None:
    """List form runs u32 + u32 + cstr through the same call."""
    raw = struct.pack("<II", 0x1234, 0x5678) + b"hello\x00\x99\x88"
    result = decode_buffer(raw, ["u32", "u32", "cstr"])
    assert result["values"] == [0x1234, 0x5678, "hello"]
    # cstr consumes the terminator too; two trailing bytes remain.
    assert result["remainder_hex"].lower() == "9988"


def test_decode_buffer_cstr_missing_terminator_marks_truncated() -> None:
    """A cstr with no NUL takes the whole tail; truncated=True."""
    raw = b"noterm"
    result = decode_buffer(raw, "cstr")
    assert result["values"] == ["noterm"]
    assert result["truncated"] is True
    assert result["layout"][0]["terminated"] is False


def test_decode_buffer_wstr_utf16le() -> None:
    """wstr reads UTF-16-LE up to the double-NUL terminator."""
    raw = "abc".encode("utf-16-le") + b"\x00\x00" + b"\xFF\xFF"
    result = decode_buffer(raw, "wstr")
    assert result["values"] == ["abc"]
    # Two remainder bytes past the terminator.
    assert result["remainder_hex"].lower() == "ffff"


def test_decode_buffer_short_buffer_truncates() -> None:
    """Spec asking for more than the buffer holds sets truncated=True and
    returns the values that did parse."""
    raw = struct.pack("<I", 0xABCD)  # 4 bytes
    result = decode_buffer(raw, "u64[2]")  # wants 16
    assert result["values"] == []
    assert result["truncated"] is True
    # No layout rows are added when nothing parses.
    assert result["layout"] == []


def test_decode_buffer_unknown_token_raises() -> None:
    with pytest.raises(ConversionError) as exc:
        decode_buffer(b"\x00" * 8, "u42")
    assert exc.value.kind == "unknown_type"


def test_decode_buffer_utf8_consumes_remainder() -> None:
    raw = b"\x01\x02" + b"tail-string"
    result = decode_buffer(raw, ["u8", "u8", "utf8"])
    assert result["values"] == [1, 2, "tail-string"]


def test_expand_spec_array_fill() -> None:
    """`_expand_spec` fills `u64[]` based on buffer length."""
    assert _expand_spec("u64[]", 24) == ["u64", "u64", "u64"]
    assert _expand_spec("u32[]", 12) == ["u32", "u32", "u32"]


# --------------------------------------------------------------------------- #
# Integration — mem_rw read with decode=
# --------------------------------------------------------------------------- #


class _DecodeFake:
    """AgentClient stub that returns a canned buffer on mem_read."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self._payloads: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        # Serve from `_payloads` when the caller pre-seeded it; else a
        # canonical 24-byte buffer of three u64s.
        if addr in self._payloads:
            return self._payloads[addr][:size]
        return struct.pack("<3Q", 0xAAAA, 0xBBBB, 0xCCCC)[:size]


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _DecodeFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _DecodeFake)

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


async def test_b_1a_read_decode_u64_array(tmp_path, monkeypatch) -> None:
    """`mem_rw read` with decode='u64[3]' returns typed values + layout."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "size": 24, "decode": "u64[3]",
    })
    assert body["ok"] is not False
    assert body["values"] == [0xAAAA, 0xBBBB, 0xCCCC]
    # layout has 3 rows; offsets 0/8/16 -> 8 bytes each.
    assert [row["offset"] for row in body["layout"]] == [0, 8, 16]
    # decode set + include_ascii unset -> ascii omitted.
    assert "ascii" not in body


async def test_b_1a_read_without_decode_keeps_legacy_ascii(
        tmp_path, monkeypatch) -> None:
    """No decode -> the pre-B-1 hex+ascii shape is preserved verbatim."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "size": 24,
    })
    assert body["ok"] is not False
    assert "ascii" in body
    assert "values" not in body
