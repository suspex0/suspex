"""bin_manage end-to-end tests — tool surface over fixture PEs.

Uses the in-memory FastMCP harness from test_file_artifacts.py: seeds a
synthesized PE under artifacts/, calls bin_manage actions through the
server, asserts envelope shape and content. Engine actions skip when
capstone isn't installed.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct

import pytest

import _pefixture as fx
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


async def _ctx(tmp_path) -> tuple[Context, object]:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    art_dir = tmp_path / "artifacts"
    (art_dir / "spill").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(art_dir / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), art_dir)
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(
            clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-test")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        import json as _json
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
    if isinstance(body.get("summary"), dict):
        merged.setdefault("summary", body["summary"])
    return merged


def _seed(ctx, tmp_path) -> tuple[str, bytes]:
    """Drop a fixture PE under artifacts/, return (path, data)."""
    data = fx.build_pe(
        code=(b"\xE8" + struct.pack("<i", 0x10 - 5) + b"\xC3"
              + b"\xCC" * (0x10 - 6) + b"\xC3"),
        imports={"KERNEL32.dll": ["CreateFileW", "VirtualAlloc"]},
        exports={"DrvMain": fx.TEXT_RVA},
        strings=[(0x20, b"http://c2.bad.example/beacon\x00"),
                 (0x60, "\\Device\\Fixt\x00".encode("utf-16le") + b"\x00\x00")],
    )
    p = tmp_path / "artifacts" / "fix.sys"
    p.write_bytes(data)
    return "fix.sys", data


async def test_info(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(ctx, tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "info", "path": "fix.sys"})
    assert body["ok"] is True
    assert body["arch"] == "x64"
    assert body["image_base"] in (fx.IMAGE_BASE, hex(fx.IMAGE_BASE))
    assert body["imports_dlls"] == 1


async def test_imports_and_imphash(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(ctx, tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "imports", "path": "fix.sys"})
    assert body["ok"] is True
    names = [r["name"] for r in body["items"]]
    assert "CreateFileW" in names and "VirtualAlloc" in names
    body = await _call(server, "bin_manage",
                       {"action": "imphash", "path": "fix.sys"})
    assert body["ok"] is True
    assert len(body["imphash"]) == 32


async def test_strings_and_iocs(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(ctx, tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "strings", "path": "fix.sys",
                        "min_len": 6})
    assert body["ok"] is True
    vals = [r["value"] for r in body["items"]]
    assert any("c2.bad.example" in v for v in vals)
    body = await _call(server, "bin_manage",
                       {"action": "iocs", "path": "fix.sys"})
    assert body["ok"] is True
    assert any(r["kind"] == "url" for r in body["items"])


async def test_entropy_sections_sec(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(ctx, tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "entropy", "path": "fix.sys"})
    assert body["ok"] is True
    assert "map" in body and "entropy" in body
    body = await _call(server, "bin_manage",
                       {"action": "sections", "path": "fix.sys"})
    names = {r["name"] for r in body["items"]}
    assert {".text", ".rdata", ".idata"} <= names
    body = await _call(server, "bin_manage",
                       {"action": "sec", "path": "fix.sys"})
    assert body["ok"] is True


async def test_sha256_source(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _, data = _seed(ctx, tmp_path)
    sha = hashlib.sha256(data).hexdigest()
    (ctx.cfg.spill_dir() / f"{sha}.bin").write_bytes(data)
    body = await _call(server, "bin_manage",
                       {"action": "info", "sha256": sha})
    assert body["ok"] is True
    assert body["arch"] == "x64"


async def test_path_escape_refused(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "info", "path": "..\\..\\evil.sys"})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"


async def test_unknown_action(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    body = await _call(server, "bin_manage", {"action": "wat"})
    assert body["ok"] is False
    assert body["kind"] == "unknown"


async def test_engine_funcs(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    _seed(ctx, tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "funcs", "path": "fix.sys"})
    assert body["ok"] is True
    starts = {r["va"] for r in body["items"]}
    base = fx.IMAGE_BASE + fx.TEXT_RVA
    assert base in starts or f"0x{base:x}" in starts


async def test_driver_surface_and_ioctl_harvest(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    # DriverEntry: mov rbx,rcx ; lea rax,handler ; mov [rbx+0xE0],rax ; ret
    # handler: cmp dword [rdx+0x18], 0x222003 ; je ; xor eax,eax ; ret
    prefix = (b"\x48\x8B\xD9"
              b"\x48\x8D\x05" + struct.pack("<i", 0x40 - 10)
              + b"\x48\x89\x83" + struct.pack("<i", 0xE0)
              + b"\xC3")
    handler = (b"\x81\xBA\x18\x00\x00\x00" + struct.pack("<I", 0x222003)
               + b"\x74\x03" + b"\x31\xC0\xC3"
               + b"\xB8\x01\x00\x00\x00\xC3")
    code = prefix + b"\xCC" * (0x40 - len(prefix)) + handler
    data = fx.build_pe(code=code, subsystem=1,
                       strings=[(0x30, "\\Device\\Fixt\x00"
                                 .encode("utf-16le"))])
    (tmp_path / "artifacts" / "drv.sys").write_bytes(data)

    body = await _call(server, "bin_manage",
                       {"action": "irp_surface", "path": "drv.sys"})
    assert body["ok"] is True
    assert body["is_driver"] is True
    disp = {d["name"]: d for d in body["irp_dispatch"]}
    assert "IRP_MJ_DEVICE_CONTROL" in disp
    assert disp["IRP_MJ_DEVICE_CONTROL"]["resolved"] is True
    assert any("\\Device\\Fixt" in d["value"] for d in body["devices"])

    body = await _call(server, "bin_manage",
                       {"action": "ioctl_surface", "path": "drv.sys"})
    assert body["ok"] is True
    codes = {r["code"]: r for r in body["ioctl_codes"]}
    assert 0x222003 in codes
    assert codes[0x222003]["method_name"] == "METHOD_NEITHER"
    assert codes[0x222003]["method_neither"] is True


async def test_pseudo_and_audit_smoke(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    data = fx.build_pe(code=b"\x48\x31\xC0\xC3",
                       exports={"Entry": fx.TEXT_RVA})
    (tmp_path / "artifacts" / "p.sys").write_bytes(data)
    body = await _call(server, "bin_manage",
                       {"action": "pseudo", "path": "p.sys",
                        "func": "Entry"})
    assert body["ok"] is True
    assert body["version"] == "v1-lite"
    assert any("return" in l for l in body["lines"])
    body = await _call(server, "bin_manage",
                       {"action": "audit", "path": "p.sys"})
    assert body["ok"] is True
    assert body["count"] == 0


async def test_non_pe_still_extracts(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    (tmp_path / "artifacts" / "blob.bin").write_bytes(
        b"\x00" * 64 + b"http://dropped.example/x\x00" + b"\xCC" * 32)
    body = await _call(server, "bin_manage",
                       {"action": "iocs", "path": "blob.bin"})
    assert body["ok"] is True
    assert any(r["kind"] == "url" for r in body["items"])
    # but PE actions refuse cleanly
    body = await _call(server, "bin_manage",
                       {"action": "imports", "path": "blob.bin"})
    assert body["ok"] is False
    assert body["kind"] == "bad_magic"


# ---------------------------------------------------------------- gadgets --

GADGET_CODE = (
    b"\x58\xC3"                       # 0x00 pop rax; ret
    b"\x5F\x5E\xC3"                   # 0x02 pop rdi; pop rsi; ret
    b"\x48\x89\xC4\xC3"               # 0x05 mov rsp, rax; ret
    b"\xC9\xC3"                       # 0x09 leave; ret
    b"\x48\x83\xC4\x20\xC3"           # 0x0B add rsp, 0x20; ret
    b"\xC2\x18\x00"                   # 0x10 ret 0x18
    b"\xFF\xE0"                       # 0x13 jmp rax
    b"\x0F\x05"                       # 0x15 syscall
    + b"\x90" * (0x200 - 0x17)
)
GADGET_BASE = fx.IMAGE_BASE + fx.TEXT_RVA


def _seed_gadgets(tmp_path, name: str = "g.sys") -> str:
    data = fx.build_pe(code=GADGET_CODE)
    (tmp_path / "artifacts" / name).write_bytes(data)
    return name


def _va(row: dict) -> int:
    v = row.get("va_int", row.get("va"))
    return int(v, 0) if isinstance(v, str) else int(v)


async def test_gadgets_scan(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    name = _seed_gadgets(tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name})
    assert body["ok"] is True
    rows = {_va(r): r for r in body["items"]}
    assert rows[GADGET_BASE + 0x00]["text"] == "pop rax; ret"
    assert rows[GADGET_BASE + 0x05]["text"] == "mov rsp, rax; ret"
    assert body["base_va"] in (fx.IMAGE_BASE, hex(fx.IMAGE_BASE))
    assert body["cached"] is False
    assert body["gadgets_indexed"] > 0
    assert body["truncated"] is False
    # Second call hits the index cache.
    body2 = await _call(server, "bin_manage",
                        {"action": "gadgets", "path": name})
    assert body2["cached"] is True
    # refresh=true forces a rebuild.
    body3 = await _call(server, "bin_manage",
                        {"action": "gadgets", "path": name,
                         "refresh": True})
    assert body3["cached"] is False


async def test_gadgets_filters(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    name = _seed_gadgets(tmp_path)

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "category": "stack_pivot"})
    vas = {_va(r) for r in body["items"]}
    assert GADGET_BASE + 0x05 in vas and GADGET_BASE + 0x09 in vas
    assert GADGET_BASE + 0x00 not in vas

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "ending": "jmp"})
    endings = {r["ending"] for r in body["items"]}
    assert endings == {"jmp_reg"}
    assert GADGET_BASE + 0x13 in {_va(r) for r in body["items"]}

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "ending": "ret", "reg": "rdi"})
    assert {_va(r) for r in body["items"]} == {GADGET_BASE + 0x02}

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "filter": "pop rdi"})
    assert all("pop rdi" in r["text"] for r in body["items"])
    assert body["items"]

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "ending": "ret", "max_len": 1})
    assert all(r["n_insns"] == 1 for r in body["items"])

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "ending": "bogus"})
    assert body["ok"] is False and body["kind"] == "bad_arg"

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "bad_bytes": "zz"})
    assert body["ok"] is False and body["kind"] == "bad_arg"


async def test_gadgets_on_raw_blob(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    (tmp_path / "artifacts" / "shell.bin").write_bytes(
        b"\x58\xC3\x5B\xC3" + b"\xCC" * 28)
    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": "shell.bin"})
    assert body["ok"] is True
    rows = {_va(r): r for r in body["items"]}
    # Blob VAs are buffer offsets (no PE parse → base 0).
    assert rows[0x00]["text"] == "pop rax; ret"
    assert rows[0x02]["text"] == "pop rbx; ret"


async def test_gadgets_paging_and_summary(tmp_path) -> None:
    pytest.importorskip("capstone")
    ctx, server = await _ctx(tmp_path)
    name = _seed_gadgets(tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name, "limit": 1})
    assert body["ok"] is True
    assert len(body["items"]) == 1
    assert body["summary"]["item_total"] > 1
    assert body["summary"]["next_cursor"]

    body = await _call(server, "bin_manage",
                       {"action": "gadgets", "path": name,
                        "summary": True})
    assert body["ok"] is True
    assert not body["items"]
    assert body["summary"]["item_total"] > 0
