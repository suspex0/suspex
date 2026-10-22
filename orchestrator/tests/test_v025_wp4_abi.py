"""v0.25 WP4 — ABI v12 agent_client contract tests (fake-stub, no gRPC).

Covers the _shared frozen contract:

- mem_write returns {"written_bytes", "write_path"} with the numeric
  write_path mapped to its string name; strict_va -> flags bit0 and cr3
  reach MemoryWriteRequest
- mem_va_translate(..., cr3=) threads the explicit-CR3 field through
  VaTranslateRequest and returns pa/present/cr3/page_size_shift
- idt_list(all_cpus=) calls Memory.IdtList and returns rows with the raw
  decoded fields (per-row idt_base preserved for base-drift scoring)
- idt_list on a client whose stub lacks IdtList raises a labelled error
"""
from __future__ import annotations

from typing import Any

import pytest

from suspex.agent_client import AgentClient
from suspex.generated import suspex_pb2 as pb


def _client() -> AgentClient:
    return AgentClient("127.0.0.1", 1, "", timeout_ms=1000, max_inflight=2)


def _resp(**fields: Any):
    """Minimal stand-in for a pb2 response: status.ok + the named fields."""

    class _Status:
        ok = True
        error = ""

    class _Resp:
        status = _Status()

    r = _Resp()
    for k, v in fields.items():
        setattr(r, k, v)
    return r


# ---------------------------------------------------------------- mem_write --


async def test_wp4_mem_write_returns_write_path() -> None:
    """Frozen contract: dict return, numeric write_path -> string."""
    client = _client()
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return _resp(written_bytes=len(req.data), write_path=2)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"Write": object()})()

    res = await client.mem_write(0, 0x1000, b"aa", "kernel")
    assert res == {"written_bytes": 2, "write_path": "phys_remap"}
    assert captured["req"].space == pb.KERNEL
    assert captured["req"].flags == 0
    assert captured["req"].cr3 == 0


async def test_wp4_mem_write_strict_va_and_cr3_reach_request() -> None:
    """strict_va -> SUSPEX_MEM_WRF_STRICT_VA (bit0); cr3 passes through."""
    client = _client()
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return _resp(written_bytes=len(req.data), write_path=3)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"Write": object()})()

    res = await client.mem_write(0, 0x2000, b"bb", "kernel",
                                 strict_va=True, cr3=0x1AB000)
    assert captured["req"].flags == 1  # SUSPEX_MEM_WRF_STRICT_VA
    assert captured["req"].cr3 == 0x1AB000
    assert res["write_path"] == "foreign_cr3"


async def test_wp4_mem_write_unknown_path_labelled() -> None:
    """A pre-v12 agent leaves write_path=0 -> 'unknown', not a crash."""
    client = _client()

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        return _resp(written_bytes=len(req.data), write_path=0)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"Write": object()})()

    res = await client.mem_write(0, 0x3000, b"cc", "kernel")
    assert res == {"written_bytes": 2, "write_path": "unknown"}


async def test_wp4_mem_write_status_error_raises() -> None:
    client = _client()

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        class _S:
            ok = False
            error = "driver: MEM_WRITE NTSTATUS 0xC0000141"
        return _resp(status=_S(), written_bytes=0, write_path=0)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"Write": object()})()

    with pytest.raises(RuntimeError, match="0xC0000141"):
        await client.mem_write(0, 0x4000, b"dd", "kernel", strict_va=True)


# --------------------------------------------------------- mem_va_translate --


async def test_wp4_va_translate_cr3_threads_through() -> None:
    """cr3= reaches VaTranslateRequest; response keeps the used CR3."""
    client = _client()
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return _resp(pa=0x12345000, present=True,
                     cr3=req.cr3, page_size_shift=12)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"VaTranslate": object()})()

    res = await client.mem_va_translate(0xFFFF800012340000, space="kernel",
                                        cr3=0xAAA000)
    assert captured["req"].cr3 == 0xAAA000
    assert captured["req"].space == pb.KERNEL
    assert res == {"pa": 0x12345000, "present": True,
                   "cr3": 0xAAA000, "page_size_shift": 12}


async def test_wp4_va_translate_user_needs_pid() -> None:
    """space='user' passes pid through; cr3 defaults to 0."""
    client = _client()
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return _resp(pa=0x777000, present=True, cr3=0xBEEF,
                     page_size_shift=21)

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"VaTranslate": object()})()

    res = await client.mem_va_translate(0x7FF600000000, space="user", pid=4242)
    assert captured["req"].space == pb.USER
    assert captured["req"].pid == 4242
    assert captured["req"].cr3 == 0
    assert res["page_size_shift"] == 21
    assert res["cr3"] == 0xBEEF


# ----------------------------------------------------------------- idt_list --


async def test_wp4_idt_list_rows_and_bases() -> None:
    """Entries decode to raw rows; per-row idt_base survives for the
    WP2 base-drift scorer."""
    client = _client()
    captured: dict = {}

    rows = [
        {"cpu": 0, "vector": 0x2E, "handler_va": 0xFFFFF80000001234,
         "selector": 0x10, "ist": 0, "dpl": 3, "idt_base": 0xFFFFF80020000000},
        {"cpu": 1, "vector": 0x2E, "handler_va": 0xFFFFF80000001234,
         "selector": 0x10, "ist": 0, "dpl": 3, "idt_base": 0xFFFFF80021000000},
    ]

    class _Row:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return _resp(idt_base=0xFFFFF80020000000, idt_limit=0xFFF,
                     entries=[_Row(**r) for r in rows])

    client._call = fake_call  # type: ignore[method-assign]
    client.memory = type("_M", (), {"IdtList": object()})()

    res = await client.idt_list(all_cpus=True)
    assert captured["req"].all_cpus is True
    assert res["ok"] is True
    assert res["idt_base"] == 0xFFFFF80020000000
    assert res["idt_limit"] == 0xFFF
    assert len(res["entries"]) == 2
    e0, e1 = res["entries"]
    assert e0["handler_va"] == 0xFFFFF80000001234
    assert e0["selector"] == 0x10 and e0["ist"] == 0 and e0["dpl"] == 3
    # Per-CPU bases differ — the raw per-row value must survive for the
    # tool's drift check.
    assert e0["idt_base"] != e1["idt_base"]


async def test_wp4_idt_list_missing_rpc_raises() -> None:
    """Feature gate: a stub without IdtList raises a labelled error that
    the WP2 tool maps to kind='agent_old'."""
    client = _client()
    client.memory = type("_M", (), {})()

    with pytest.raises(RuntimeError, match="IdtList"):
        await client.idt_list()
