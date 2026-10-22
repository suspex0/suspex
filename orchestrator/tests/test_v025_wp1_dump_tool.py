"""v0.25 WP1 — dump_manage tool surface.

`latest` against a fake client with a canned C:\\Windows\\Minidump
ListDir + Download; `parse` over a local path / artifact sha256 /
remote_path; `actions` discovery. The fake's download honors the ranged
(offset/length) probe the tool performs before the full pull.
"""
from __future__ import annotations

import asyncio
import hashlib
import json as _json
import struct
from pathlib import Path
from typing import Any

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


def _filetime(y: int, m: int, d: int) -> int:
    import datetime as _dt
    dt = _dt.datetime(y, m, d, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return int((dt.timestamp() + 11644473600) * 10_000_000)


def _kernel_dump_bytes() -> bytes:
    """Same layout as test_v025_wp1_minidump's fixture — duplicated so
    this file stays self-contained."""
    hdr = bytearray(0x2000)
    hdr[0x00:0x04] = b"PAGE"
    hdr[0x04:0x08] = b"DU64"
    struct.pack_into("<I", hdr, 0x08, 15)
    struct.pack_into("<I", hdr, 0x0C, 22621)
    struct.pack_into("<Q", hdr, 0x10, 0x1AA000)
    struct.pack_into("<I", hdr, 0x30, 0x8664)
    struct.pack_into("<I", hdr, 0x34, 16)
    struct.pack_into("<I", hdr, 0x38, 0x133)          # DPC_WATCHDOG
    struct.pack_into("<4Q", hdr, 0x40, 0, 100, 200,
                     0xFFFFF80000001234)
    struct.pack_into("<Q", hdr, 0x80, 0xFFFFF8000ABC0000)
    struct.pack_into("<I", hdr, 0x88, 0)             # no phys runs
    # context @0x348 — flags + rsp/rip only
    struct.pack_into("<I", hdr, 0x348 + 0x30, 0x0010001F)
    struct.pack_into("<Q", hdr, 0x348 + 0x78 + 4 * 8, 0xFFFFF80011119000)
    struct.pack_into("<Q", hdr, 0x348 + 0xF8, 0xFFFFF80000001234)
    # exception @0xF00
    struct.pack_into("<I", hdr, 0xF00, 0x133)
    struct.pack_into("<Q", hdr, 0xF10, 0xFFFFF80000001234)
    struct.pack_into("<I", hdr, 0xF98, 4)            # TRIAGE
    struct.pack_into("<Q", hdr, 0xFA8, _filetime(2026, 10, 18))
    # triage subheader @0x2000 — no callstack saved
    tri = bytearray(0x80)
    struct.pack_into("<Q", tri, 0x48, 0xFFFFF80011119000)
    return bytes(hdr) + bytes(tri)


DUMP_BYTES = _kernel_dump_bytes()
DUMP_DIR = r"C:\Windows\Minidump"
DUMP_NAME = "Mini101826-02.dmp"
DUMP_REMOTE = DUMP_DIR + "\\" + DUMP_NAME


class _FakeClient:
    """Canned agent: one dump in the minidump dir, ranged download, a
    module map ntoskrnl spans."""

    def __init__(self, boot_epoch_ms: int = 0) -> None:
        self._boot = boot_epoch_ms
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "boot_epoch_ms": self._boot,
                "agent_instance_id": "inst-1",
                "driver_state": "DRIVER_SERVICE"}

    async def file_list_dir(self, path: str,
                            recursive: bool = False) -> list[dict]:
        assert path.rstrip("\\/") == DUMP_DIR
        return [
            {"name": "Mini101826-01.dmp", "dir": False,
             "mtime_unix": 100, "size": len(DUMP_BYTES)},
            {"name": DUMP_NAME, "dir": False,
             "mtime_unix": 200, "size": len(DUMP_BYTES)},
            {"name": "not-a-dump.txt", "dir": False,
             "mtime_unix": 300, "size": 12},
        ]

    async def file_download(self, remote: str, local: str,
                            offset: int = 0, length: int = 0) -> dict:
        data = DUMP_BYTES
        chunk = data[offset:offset + length] if length else data[offset:]
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(chunk)
        return {"ok": True, "bytes": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest()}

    async def mem_modules(self, pid: int, kernel: bool) -> list[dict]:
        return [
            {"name": "ntoskrnl.exe", "base": 0xFFFFF80000000000,
             "size": 0x1000000, "path": r"\SystemRoot\system32\ntoskrnl.exe"},
            {"name": "suspex_driver.sys", "base": 0xFFFFF80002000000,
             "size": 0x50000, "path": r"\??\C:\lab\suspex_driver.sys"},
        ]

    def recent_ops(self, n: int) -> list[dict]:
        return []


async def _build_ctx(tmp_path, monkeypatch):
    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None
    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-wp1")
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


# ----------------------------------------------------------------------- #
# actions / parse / latest
# ----------------------------------------------------------------------- #

async def test_actions_lists_verbs(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    body = await _call(server, "dump_manage", {"action": "actions"})
    assert body["ok"] is True
    assert set(body["actions"]) >= {"parse", "latest", "actions"}


async def test_latest_pulls_newest_and_parses(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _FakeClient()
    body = await _call(server, "dump_manage", {"action": "latest"})
    assert body["ok"] is True, body
    assert body["bugcheck"]["code"] == 0x133
    assert body["bugcheck"]["name"] == "DPC_WATCHDOG_VIOLATION"
    assert body["params"] == [0, 100, 200, 0xFFFFF80000001234]
    # newest by mtime — the -02 file, not -01 and never the .txt.
    assert body["source"]["name"] == DUMP_NAME
    assert body["source"]["remote_path"] == DUMP_REMOTE
    # the artifact landed under artifacts/dumps/
    assert "dumps" in body["source"]["local_path"].replace("\\", "/")
    # params_resolved — p4 lands in ntoskrnl, the rest aren't module VAs.
    resolved = body["params_resolved"]
    assert resolved[3] is not None
    assert resolved[3]["module"] == "ntoskrnl.exe"
    assert resolved[3]["offset"] == 0x1234
    assert resolved[0] is None
    # faulting_va: 0x133's map picks param[3] → resolves to ntoskrnl.
    assert body["faulting"]["module"] == "ntoskrnl.exe"
    assert body["faulting"]["text"].startswith("ntoskrnl.exe+0x1234")
    assert body["faulting_module"] == "ntoskrnl.exe"


async def test_latest_reports_missing_dir_entries(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)

    class _Empty(_FakeClient):
        async def file_list_dir(self, path, recursive=False):
            return [{"name": "readme.txt", "dir": False,
                     "mtime_unix": 1, "size": 4}]

    ctx.session.clients["kernel"] = _Empty()
    body = await _call(server, "dump_manage", {"action": "latest"})
    assert body["ok"] is False
    assert body["kind"] == "not_found"


async def test_parse_local_path(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "local.dmp"
    dmp.write_bytes(DUMP_BYTES)
    body = await _call(server, "dump_manage",
                       {"action": "parse", "path": str(dmp)})
    assert body["ok"] is True, body
    assert body["bugcheck"]["code"] == 0x133
    assert body["source"]["via"] == "path"
    # no client attached — resolution honestly reports it can't happen.
    assert body["resolution"] == "no_target"


async def test_parse_by_sha256_prefix(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    art = Path(ctx.cfg.artifacts_dir()) / "dumps"
    art.mkdir(parents=True, exist_ok=True)
    target = art / "stashed.dmp"
    target.write_bytes(DUMP_BYTES)
    digest = hashlib.sha256(DUMP_BYTES).hexdigest()
    body = await _call(server, "dump_manage",
                       {"action": "parse", "sha256": digest[:16]})
    assert body["ok"] is True, body
    assert body["source"]["via"] == "artifact"
    assert body["source"]["sha256"] == digest
    assert body["bugcheck"]["code"] == 0x133


async def test_parse_remote_path_pulls_first(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _FakeClient()
    body = await _call(server, "dump_manage",
                       {"action": "parse", "remote_path": DUMP_REMOTE})
    assert body["ok"] is True, body
    assert body["source"]["via"] == "remote"
    assert body["source"]["remote_path"] == DUMP_REMOTE
    assert body["bugcheck"]["code"] == 0x133
    # same-boot freshness (fake boot_epoch_ms=0 → unknown_boot) → the
    # 0x133 faulting param resolved against the live module map.
    assert body["resolution"] == "unknown_boot"
    assert body["faulting_module"] == "ntoskrnl.exe"


async def test_parse_stale_boot_skips_resolution(tmp_path, monkeypatch):
    """A dump that predates the live boot must come back raw —
    resolution='stale_boot' — not resolved against the wrong map."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _FakeClient(boot_epoch_ms=9999999999999)
    body = await _call(server, "dump_manage",
                       {"action": "parse", "remote_path": DUMP_REMOTE})
    assert body["ok"] is True, body
    assert body["resolution"] == "stale_boot"
    assert "params_resolved" not in body
    # but with assume_fresh the caller can force it anyway
    body2 = await _call(server, "dump_manage",
                        {"action": "parse", "remote_path": DUMP_REMOTE,
                         "assume_fresh": True})
    assert body2["ok"] is True
    assert body2["resolution"] == "assumed_fresh"
    assert body2["faulting_module"] == "ntoskrnl.exe"


async def test_parse_requires_a_source(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    body = await _call(server, "dump_manage", {"action": "parse"})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"


async def test_parse_corrupt_surfaces_bad_dump(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "junk.dmp"
    dmp.write_bytes(b"MZ" + b"\x00" * 4000)
    body = await _call(server, "dump_manage",
                       {"action": "parse", "path": str(dmp)})
    assert body["ok"] is False
    assert body["kind"] == "bad_dump"


async def test_parse_carries_hex_mirrors(tmp_path, monkeypatch):
    """v0.28: params/context/faulting come back with `*_hex` siblings —
    no value_manage round-trip needed to eyeball an address."""
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "local.dmp"
    dmp.write_bytes(DUMP_BYTES)
    body = await _call(server, "dump_manage",
                       {"action": "parse", "path": str(dmp)})
    assert body["ok"] is True, body
    assert body["params_hex"][-1] == "0xfffff80000001234"
    assert body["faulting_va_hex"] == "0xfffff80000001234"
    assert body["context_hex"]["rip"] == "0xfffff80000001234"
    assert body["context_hex"]["rsp"] == "0xfffff80011119000"
    # decimal originals stay untouched
    assert body["params"][-1] == 0xFFFFF80000001234


async def test_stack_action_reports_empty_region_honestly(tmp_path,
                                                          monkeypatch):
    """The fixture dump saves no callstack bytes — stack answers ok with
    zero frames and the honest note instead of an error."""
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "local.dmp"
    dmp.write_bytes(DUMP_BYTES)
    body = await _call(server, "dump_manage",
                       {"action": "stack", "path": str(dmp)})
    assert body["ok"] is True, body
    assert body["frames_total"] == 0
    assert any("no callstack" in n for n in body["notes"])
    assert body["source"]["via"] == "path"


async def test_unknown_action_lists_one_liners(tmp_path, monkeypatch):
    """v0.28: a mistyped action embeds the per-verb one_liners so
    discovery costs one round trip, and an empty action IS the help."""
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    body = await _call(server, "dump_manage", {"action": "walk"})
    assert body["ok"] is False
    assert isinstance(body.get("actions"), dict)
    assert "parse" in body["actions"]
    assert body["actions"]["parse"]
    body = await _call(server, "dump_manage", {"action": ""})
    assert body["ok"] is True
    assert "stack" in body["actions"]
