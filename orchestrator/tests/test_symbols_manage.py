"""v0.22 · symbols_manage — PDB identity/cache/dbghelp surface.

Covers the two layout sources:
  * ``pdb_layout_cache`` (IDA dump_layout JSON) — struct_info /
    resolve_member / enum_info / layouts, all pure compute.
  * ``suspex.symbols`` (dbghelp) — info / ensure / resolve / lookup /
    layout. Real dbghelp calls are stubbed: the tests monkeypatch the
    module-level wrappers so no MSDL download or Sym* call happens.
"""
from __future__ import annotations

import asyncio
import json
import json as _json
import struct
from pathlib import Path
from typing import Any

import pytest

from suspex import pdb_layout_cache as _plc
from suspex import symbols as _sym
from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


# --- harness (same shape as test_handles_chunked) -------------------------

class _FakeAgentClient:
    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_modules(self, pid: int, kernel: bool):
        return [{"name": "fake.sys", "base": 0xFFFFF8000000,
                 "size": 0x100000,
                 "path": "\\SystemRoot\\fake.sys"}]

    async def mem_read(self, pid: int, address: int, size: int,
                       space: str, **kw):
        # _EPROCESS-shaped fake: Pcb udt (8B opaque), UniqueProcessId ptr,
        # Flags u32.
        return struct.pack("<8sQI", b"PCB00000", 0xDEADBEEF, 0x4141)


async def _server(tmp_path, monkeypatch, client_cls=_FakeAgentClient):
    monkeypatch.setattr("suspex.session.AgentClient", client_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", client_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    cfg.artifacts.pdb_cache = str(tmp_path / "artifacts" / "symbols")
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
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


# --- fixtures -------------------------------------------------------------

def _write_minipe(path: Path, guid: bytes, age: int, pdb_name: bytes) -> None:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    buf[0x44:0x46] = (0x8664).to_bytes(2, "little")
    buf[0x46:0x48] = (1).to_bytes(2, "little")
    buf[0x54:0x56] = (0xF0).to_bytes(2, "little")
    opt = 0x58
    buf[opt:opt + 2] = (0x20B).to_bytes(2, "little")
    dd = opt + 112
    buf[dd + 48:dd + 52] = (0x1000).to_bytes(4, "little")
    buf[dd + 52:dd + 56] = (28).to_bytes(4, "little")
    sec = opt + 0xF0
    buf[sec + 12:sec + 16] = (0x1000).to_bytes(4, "little")
    buf[sec + 16:sec + 20] = (0x1000).to_bytes(4, "little")
    buf[sec + 20:sec + 24] = (0x200).to_bytes(4, "little")
    entry = bytearray(28)
    entry[12:16] = (2).to_bytes(4, "little")
    entry[16:20] = (0x40).to_bytes(4, "little")
    entry[24:28] = (0x240).to_bytes(4, "little")
    rsds = b"RSDS" + guid + age.to_bytes(4, "little") + pdb_name + b"\0"
    buf[0x200:0x200 + 28] = entry
    buf[0x240:0x240 + len(rsds)] = rsds
    path.write_bytes(bytes(buf))


_GUID = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
_STORE_REL = "ci.pdb/0403020106050807090A0B0C0D0E0F103/ci.pdb"


def _eprocess_layout(build_id: str = "F1E2A3B4") -> dict:
    return {
        "module": "ntoskrnl.exe", "build_id": build_id,
        "types": {
            "_KPROCESS": {"size": 0x2E0, "members": [
                {"name": "DirectoryTableBase", "offset": 0x28,
                 "size": 0x8, "type": "unsigned __int64"}]},
            "_EPROCESS": {"size": 0x8E0, "members": [
                {"name": "Pcb", "offset": 0x0, "size": 0x2E0,
                 "type": "_KPROCESS"},
                {"name": "UniqueProcessId", "offset": 0x440,
                 "size": 0x8, "type": "void *"}]},
        },
        "enums": {"NL_NEIGHBOR_STATE": {"size": 4, "members": [
            {"name": "NlnsUnreachable", "value": 0},
            {"name": "NlnsReachable", "value": 5}]}},
    }


# --- discovery + arg validation -------------------------------------------

async def test_symbols_actions_and_unknown(tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "symbols_manage", {"action": "actions"})
    assert body["ok"] is True
    for verb in ("info", "ensure", "resolve", "lookup", "layout",
                 "struct_info", "resolve_member", "enum_info", "layouts"):
        assert verb in body["actions"], verb
    body = await _call(server, "symbols_manage", {"action": "bogus"})
    assert body["ok"] is False
    assert body["kind"] == "unknown"


async def test_symbols_missing_image_named_error(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "symbols_manage",
                       {"action": "info", "module": "neverdumped.sys"})
    assert body["ok"] is False
    assert body["kind"] == "module_not_found"
    assert "dump_module" in body.get("error", "")


# --- info / ensure on a synthetic PE --------------------------------------

async def test_symbols_info_minipe(tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "ci.dll"
    _write_minipe(pe, _GUID, 3, b"ci.pdb")
    body = await _call(server, "symbols_manage",
                       {"action": "info", "path": str(pe)})
    assert body["ok"] is True
    assert body["pdb_name"] == "ci.pdb"
    assert body["age"] == 3
    assert body["guid"] == "0403020106050807090A0B0C0D0E0F10"


async def test_symbols_info_via_artifacts_dump_dir(
        tmp_path, monkeypatch) -> None:
    """module= resolves under artifacts/dumps — the file_manage
    dump_module landing zone."""
    ctx, server = await _server(tmp_path, monkeypatch)
    dumps = tmp_path / "artifacts" / "dumps"
    dumps.mkdir(parents=True)
    pe = dumps / "ci.dll"
    _write_minipe(pe, _GUID, 3, b"ci.pdb")
    body = await _call(server, "symbols_manage",
                       {"action": "info", "module": "ci.dll"})
    assert body["ok"] is True
    assert body["image"] == "ci.dll"


async def test_symbols_ensure_cache_hit_and_miss(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "ci.dll"
    _write_minipe(pe, _GUID, 3, b"ci.pdb")
    # Pre-seed the cache the way ensure_pdb expects.
    cached = tmp_path / "artifacts" / "symbols" / _STORE_REL
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"fake pdb")
    body = await _call(server, "symbols_manage",
                       {"action": "ensure", "path": str(pe),
                        "download": False})
    assert body["ok"] is True
    assert body["cached"] is True
    # A non-cached PDB with download disabled -> pdb_missing.
    cached.unlink()
    body = await _call(server, "symbols_manage",
                       {"action": "ensure", "path": str(pe),
                        "download": False})
    assert body["ok"] is False
    assert body["kind"] == "pdb_missing"


# --- dbghelp verbs, stubbed ------------------------------------------------

async def test_symbols_resolve_and_lookup_stubbed(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "fake.sys"
    _write_minipe(pe, _GUID, 1, b"fake.pdb")

    monkeypatch.setattr(_sym, "ensure_pdb", lambda *a, **k: tmp_path / "x.pdb")
    monkeypatch.setattr(_sym, "resolve_rvas",
                        lambda *a, **k: {"FakeFunc": 0x1234})
    monkeypatch.setattr(_sym, "lookup_rva",
                        lambda *a, **k: {"found": True, "name": "FakeFunc",
                                         "rva": 0x1200,
                                         "displacement": 0x34})

    body = await _call(server, "symbols_manage",
                       {"action": "resolve", "path": str(pe),
                        "names": ["FakeFunc", "Missing"],
                        "base": "0xFFFFF8000000"})
    assert body["ok"] is True
    syms = body["symbols"]
    assert syms["FakeFunc"]["rva"] in (0x1234, "0x1234")
    assert "va" in syms["FakeFunc"]
    assert body["unresolved"] == ["Missing"]

    # symbol='mod!name' convenience form.
    body = await _call(server, "symbols_manage",
                       {"action": "resolve", "path": str(pe),
                        "symbol": "fake.sys!FakeFunc"})
    assert body["ok"] is True
    assert "FakeFunc" in body["symbols"]

    body = await _call(server, "symbols_manage",
                       {"action": "lookup", "path": str(pe),
                        "rva": "0x1234"})
    assert body["ok"] is True
    assert body["symbol"] == "FakeFunc"
    assert body["displacement"] in (0x34, "0x34")
    assert body["confidence"] == "high"


async def test_symbols_lookup_flags_low_confidence(
        tmp_path, monkeypatch) -> None:
    """v0.28: a huge nearest-match displacement means 'no real PDB
    coverage' — the response must say confidence:'low' instead of
    emitting confident-looking junk (MmSetBankedSection+0x8E27)."""
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "fake.sys"
    _write_minipe(pe, _GUID, 1, b"fake.pdb")
    monkeypatch.setattr(_sym, "ensure_pdb", lambda *a, **k: tmp_path / "x.pdb")
    monkeypatch.setattr(_sym, "lookup_rva",
                        lambda *a, **k: {"found": True,
                                         "name": "MmSetBankedSection",
                                         "rva": 0x1000,
                                         "displacement": 0x8E27})
    body = await _call(server, "symbols_manage",
                       {"action": "lookup", "path": str(pe),
                        "rva": "0x9e27"})
    assert body["ok"] is True
    assert body["symbol"] == "MmSetBankedSection"
    assert body["confidence"] == "low"
    assert "guess" in body.get("warning", "")
    # the caller can raise the threshold to accept big displacements
    body = await _call(server, "symbols_manage",
                       {"action": "lookup", "path": str(pe),
                        "rva": "0x9e27", "max_disp": "0x10000"})
    assert body["confidence"] == "high"


async def test_symbols_layout_stubbed(tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "fake.sys"
    _write_minipe(pe, _GUID, 1, b"fake.pdb")
    monkeypatch.setattr(_sym, "ensure_pdb", lambda *a, **k: tmp_path / "x.pdb")
    monkeypatch.setattr(_sym, "type_layout", lambda *a, **k: {
        "ok": True, "name": "_EPROCESS", "tag": "udt", "size": 0x8E0,
        "members": [{"name": "Pcb", "offset": 0, "size": 0x2E0,
                     "type": "_KPROCESS"}]})
    body = await _call(server, "symbols_manage",
                       {"action": "layout", "path": str(pe),
                        "type_name": "_EPROCESS"})
    assert body["ok"] is True
    assert body["size"] in (0x8E0, "0x8e0", "0x8E0")
    assert body["members"][0]["name"] == "Pcb"

    # type_not_found envelope passes through untouched.
    monkeypatch.setattr(_sym, "type_layout", lambda *a, **k: {
        "ok": False, "kind": "type_not_found",
        "error": "type '_NOPE' not in PDB"})
    body = await _call(server, "symbols_manage",
                       {"action": "layout", "path": str(pe),
                        "type_name": "_NOPE"})
    assert body["ok"] is False
    assert body["kind"] == "type_not_found"


# --- v0.24 · VA-layout dump_module outputs + pdb identity override ---------

def _write_minipe_va(path: Path, guid: bytes, age: int, pdb_name: bytes,
                     blob_rva: int = 0x240) -> None:
    """dump_module-shaped image: the agent zeroes PointerToRawData on the
    CodeView entry and keeps AddressOfRawData authoritative (VA layout,
    file offset == RVA). read_pdb_info must find the blob via the RVA."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    buf[0x44:0x46] = (0x8664).to_bytes(2, "little")
    buf[0x46:0x48] = (1).to_bytes(2, "little")
    buf[0x54:0x56] = (0xF0).to_bytes(2, "little")
    opt = 0x58
    buf[opt:opt + 2] = (0x20B).to_bytes(2, "little")
    dd = opt + 112
    buf[dd + 48:dd + 52] = (0x1000).to_bytes(4, "little")
    buf[dd + 52:dd + 56] = (28).to_bytes(4, "little")
    sec = opt + 0xF0
    buf[sec + 12:sec + 16] = (0x1000).to_bytes(4, "little")
    buf[sec + 16:sec + 20] = (0x1000).to_bytes(4, "little")
    buf[sec + 20:sec + 24] = (0x200).to_bytes(4, "little")
    entry = bytearray(28)
    entry[12:16] = (2).to_bytes(4, "little")
    entry[16:20] = (0x40).to_bytes(4, "little")
    entry[20:24] = blob_rva.to_bytes(4, "little")   # AddressOfRawData
    entry[24:28] = (0).to_bytes(4, "little")        # PointerToRawData zeroed
    rsds = b"RSDS" + guid + age.to_bytes(4, "little") + pdb_name + b"\0"
    buf[0x200:0x200 + 28] = entry
    buf[blob_rva:blob_rva + len(rsds)] = rsds
    path.write_bytes(bytes(buf))


async def test_symbols_info_va_layout_dump(tmp_path, monkeypatch) -> None:
    """The exact 'no RSDS CodeView entry' regression: dump_module output
    with PointerToRawData=0 must parse via AddressOfRawData."""
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "ntoskrnl.exe"
    _write_minipe_va(pe, _GUID, 3, b"ntkrnlmp.pdb")
    body = await _call(server, "symbols_manage",
                       {"action": "info", "path": str(pe)})
    assert body["ok"] is True
    assert body["pdb_name"] == "ntkrnlmp.pdb"
    assert body["age"] == 3
    assert body["guid"] == "0403020106050807090A0B0C0D0E0F10"


async def test_symbols_ensure_pdb_identity_override(
        tmp_path, monkeypatch) -> None:
    """ensure with pdb_guid=+pdb_age= skips the image's own debug dir."""
    ctx, server = await _server(tmp_path, monkeypatch)
    pe = tmp_path / "broken.sys"
    pe.write_bytes(b"MZ this image has no debug directory at all")
    seen: dict[str, Any] = {}

    def _fake_ensure(binary, cache_dir, allow_dl, servers, info):
        seen["info"] = info
        out = Path(cache_dir) / info.store_rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"fake pdb")
        return out

    monkeypatch.setattr(_sym, "ensure_pdb", _fake_ensure)
    body = await _call(server, "symbols_manage",
                       {"action": "ensure", "path": str(pe),
                        "pdb_guid": "AABBCCDDEEFF00112233445566778899",
                        "pdb_age": 2, "pdb_name": "weird.pdb",
                        "download": True})
    assert body["ok"] is True
    assert body["pdb_name"] == "weird.pdb"
    assert body["guid"] == "AABBCCDDEEFF00112233445566778899"
    assert body["age"] == 2
    assert "weird.pdb/AABBCCDDEEFF001122334455667788992/weird.pdb" \
        in str(seen["info"].store_rel)


# --- layout-cache family ----------------------------------------------------

async def test_symbols_layout_cache_family(tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    cache_dir = tmp_path / "layouts"
    cache_dir.mkdir()
    p = _plc.cache_path("ntoskrnl.exe", "F1E2A3B4", cache_dir=cache_dir)
    p.write_text(json.dumps(_eprocess_layout()), encoding="utf-8")

    body = await _call(server, "symbols_manage",
                       {"action": "layouts", "cache_dir": str(cache_dir)})
    assert body["ok"] is True
    assert body["count"] == 1
    assert body["layouts"][0]["module"] == "ntoskrnl.exe"

    body = await _call(server, "symbols_manage",
                       {"action": "struct_info", "module": "ntoskrnl.exe",
                        "build_id": "F1E2A3B4", "type_name": "_EPROCESS",
                        "cache_dir": str(cache_dir)})
    assert body["ok"] is True
    assert body["member_count"] == 2

    body = await _call(server, "symbols_manage",
                       {"action": "resolve_member",
                        "module": "ntoskrnl.exe", "build_id": "F1E2A3B4",
                        "type_name": "_EPROCESS", "offset": "0x28",
                        "cache_dir": str(cache_dir)})
    assert body["ok"] is True
    assert body["path"] == "_EPROCESS.Pcb.DirectoryTableBase"

    body = await _call(server, "symbols_manage",
                       {"action": "enum_info", "module": "ntoskrnl.exe",
                        "build_id": "F1E2A3B4",
                        "enum_name": "NL_NEIGHBOR_STATE",
                        "cache_dir": str(cache_dir)})
    assert body["ok"] is True
    assert body["kind"] == "enum"

    # Missing build -> pdb_layout_missing with the installed-builds hint.
    body = await _call(server, "symbols_manage",
                       {"action": "struct_info", "module": "ntoskrnl.exe",
                        "build_id": "NOPE", "type_name": "_EPROCESS",
                        "cache_dir": str(cache_dir)})
    assert body["ok"] is False
    assert body["kind"] == "pdb_layout_missing"


# --- mem_rw integration: resolve module!symbol + read decode={type:..} ----

async def test_mem_resolve_module_bang_symbol(tmp_path, monkeypatch) -> None:
    """value='fake.sys!FakeFunc' -> live module base + PDB RVA."""
    ctx, server = await _server(tmp_path, monkeypatch)
    monkeypatch.setattr(_sym, "resolve_rvas",
                        lambda *a, **k: {"FakeFunc": 0x1234})
    import suspex.mcp.tools.symbols as _ts
    monkeypatch.setattr(_ts, "_resolve_image",
                        lambda ctx, module, path: ("D:/fake.sys", "fake.sys"))
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw",
                       {"action": "resolve",
                        "value": "fake.sys!FakeFunc", "space": "kernel"})
    assert body["ok"] is True, body
    assert body["resolved_from"] == "module!symbol"
    va = body["va"]
    va_i = int(va, 16) if isinstance(va, str) else int(va)
    assert va_i == 0xFFFFF8000000 + 0x1234


async def test_mem_resolve_bang_missing_module(tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw",
                       {"action": "resolve",
                        "value": "notloaded.sys!X", "space": "kernel"})
    assert body["ok"] is False
    assert body["kind"] == "module_not_found"


async def test_mem_read_decode_named_type(tmp_path, monkeypatch) -> None:
    """decode={'type':...,'module':...,'build_id':...} decodes the fake
    _EPROCESS buffer via the cached layout."""
    ctx, server = await _server(tmp_path, monkeypatch)
    cache_dir = tmp_path / "layouts"
    cache_dir.mkdir()
    p = _plc.cache_path("fake.sys", "B1D", cache_dir=cache_dir)
    p.write_text(json.dumps({
        "module": "fake.sys", "build_id": "B1D",
        "types": {"_EPROCESS": {"size": 0x14, "members": [
            {"name": "Pcb", "offset": 0, "size": 8, "type": "_KPROCESS"},
            {"name": "UniqueProcessId", "offset": 8, "size": 8,
             "type": "void *"},
            {"name": "Flags", "offset": 16, "size": 4,
             "type": "unsigned long"}]}},
        "enums": {}}), encoding="utf-8")

    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw",
                       {"action": "read", "pid": 1234,
                        "address": "0x1000", "size": 0x14,
                        "space": "kernel",
                        "decode": {"type": "_EPROCESS",
                                   "module": "fake.sys",
                                   "build_id": "B1D",
                                   "cache_dir": str(cache_dir)}})
    assert body["ok"] is True, body
    assert body["type"] == "_EPROCESS"
    assert body["layout_source"] == "pdb_layout_cache"
    vals = body["values"]
    assert vals["UniqueProcessId"] in (0xDEADBEEF, "0xdeadbeef",
                                     3735928559)
    assert vals["Flags"] in (0x4141, "0x4141", 16705)
    # The _KPROCESS UDT isn't in `types` -> opaque hex blob.
    assert isinstance(vals["Pcb"], str)


async def test_mem_read_decode_named_type_missing_layout(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw",
                       {"action": "read", "pid": 1234,
                        "address": "0x1000", "size": 0x14,
                        "space": "kernel",
                        "decode": {"type": "_EPROCESS",
                                   "module": "fake.sys",
                                   "build_id": "NOPE",
                                   "cache_dir": str(tmp_path / "none")}})
    assert body["ok"] is False
    assert body["kind"] == "pdb_layout_missing"
