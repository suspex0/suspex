"""v0.25 WP3 — `file_manage read` + `download recursive=true`.

Cases exercised:

- read rides the Download stream's offset/length (fake verifies the
  requested range) and returns inline hex + ascii + size
- read decode='u32[2]' decodes the returned range like mem_rw read
- read side='orchestrator' answers an artifacts/-local file with
  sha256/path semantics and no live target required
- download recursive mirrors a remote tree under artifacts/downloads/,
  collects a per-file failure into `skipped` instead of aborting
- the 512-file cap reports capped/remaining
"""
from __future__ import annotations

import asyncio
import hashlib
import json as _json
from pathlib import Path
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


class _FileFake:
    """Fake AgentClient — file_download honours the Download range."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.blob = bytes(range(256)) * 4  # 1024 bytes of content
        self.tree: list[dict[str, Any]] = []
        self.download_calls: list[tuple[str, int, int]] = []
        self.fail_names: set[str] = set()

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "DRIVER_SERVICE", "boot_epoch_ms": 1}

    async def file_hash(self, remote_path: str) -> dict[str, Any]:
        return {"sha256": hashlib.sha256(self.blob).hexdigest(),
                "size": len(self.blob)}

    async def file_download(self, remote_path: str, local_path: str,
                            offset: int = 0, length: int = 0) -> dict[str, Any]:
        self.download_calls.append((remote_path, offset, length))
        if remote_path in self.fail_names:
            raise RuntimeError("simulated remote read failure")
        match = next((e for e in self.tree if e["name"] == remote_path), None)
        src = match["data"] if match is not None else self.blob
        data = src[offset:offset + length] if length else src[offset:]
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_bytes(data)
        return {"path": local_path, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    async def file_list_dir(self, path: str, recursive: bool = False,
                            max_entries: int = 2000) -> list[dict[str, Any]]:
        return list(self.tree)


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls=_FileFake):
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
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
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


# --------------------------------------------------------------------------- #
# read
# --------------------------------------------------------------------------- #


async def test_v025_wp3_read_ranged(tmp_path, monkeypatch) -> None:
    """read offset=8,length=4 pulls exactly that range off the stream."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "file_manage", {
        "action": "read", "remote_path": r"C:\Temp\x.bin",
        "offset": 8, "length": 4})
    assert body["ok"] is True, body
    assert fake.download_calls[-1] == (r"C:\Temp\x.bin", 8, 4)
    assert body["size"] == 4
    assert body["hex"] == fake.blob[8:12].hex()
    assert "ascii" in body
    assert body["offset"] == 8


async def test_v025_wp3_read_decode(tmp_path, monkeypatch) -> None:
    """decode='u32[2]' yields values+layout like mem_rw read decode=."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    import struct
    expected = list(struct.unpack("<II", fake.blob[0:8]))

    body = await _call(server, "file_manage", {
        "action": "read", "remote_path": r"C:\Temp\x.bin",
        "offset": 0, "length": 8, "decode": "u32[2]"})
    assert body["ok"] is True, body
    assert body["values"] == expected
    assert body["size"] == 8


async def test_v025_wp3_read_to_eof_capped(tmp_path, monkeypatch) -> None:
    """length=0 means to-EOF; the probe sizes it and truncation reports."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "file_manage", {
        "action": "read", "remote_path": r"C:\Temp\x.bin"})
    assert body["ok"] is True, body
    # 1024-byte blob fits under the cap — whole file back, no truncation.
    assert body["size"] == len(fake.blob)
    assert body.get("total_size") == len(fake.blob)
    assert "next_offset" not in body
    # Download was issued with length>0 derived from the hash probe.
    assert fake.download_calls[-1][1] == 0
    assert fake.download_calls[-1][2] == len(fake.blob)


async def test_v025_wp3_read_orchestrator_side(tmp_path, monkeypatch) -> None:
    """side='orchestrator' reads an artifacts/-local file — no target needed."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # Deliberately NOT connecting — orchestrator-side reads work unconnected.
    local = tmp_path / "artifacts" / "note.bin"
    local.write_bytes(b"hello-suspex" * 4)

    body = await _call(server, "file_manage", {
        "action": "read", "remote_path": str(local),
        "side": "orchestrator"})
    assert body["ok"] is True, body
    assert body["size"] == len(b"hello-suspex" * 4)
    assert body["sha256"] == hashlib.sha256(b"hello-suspex" * 4).hexdigest()
    assert body["hex"] == (b"hello-suspex" * 4).hex()

    # Containment: a path outside artifacts/ is refused.
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"nope")
    body = await _call(server, "file_manage", {
        "action": "read", "remote_path": str(outside),
        "side": "orchestrator"})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"


# --------------------------------------------------------------------------- #
# download recursive
# --------------------------------------------------------------------------- #


def _mk_tree(root: str) -> list[dict[str, Any]]:
    return [
        {"name": root, "dir": True, "size": 0},
        {"name": root + r"\a.bin", "dir": False, "size": 4,
         "data": b"AAAA"},
        {"name": root + r"\sub", "dir": True, "size": 0},
        {"name": root + r"\sub\b.bin", "dir": False, "size": 4,
         "data": b"BBBB"},
        {"name": root + r"\locked.bin", "dir": False, "size": 4,
         "data": b"FAIL"},
    ]


async def test_v025_wp3_download_recursive(tmp_path, monkeypatch) -> None:
    """Tree mirrors under artifacts/downloads/<root>/; failures -> skipped."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    root = r"C:\Work\logs"
    fake.tree = _mk_tree(root)
    fake.fail_names.add(root + r"\locked.bin")

    body = await _call(server, "file_manage", {
        "action": "download", "remote_path": root, "recursive": True})
    assert body["ok"] is True, body
    assert body["counts"]["downloaded"] == 2
    assert body["counts"]["skipped"] == 1
    assert body["skipped"][0]["path"] == root + r"\locked.bin"

    dest = Path(body["dir"])
    assert (dest / "a.bin").read_bytes() == b"AAAA"
    assert (dest / "sub" / "b.bin").read_bytes() == b"BBBB"
    rels = sorted(d["path"] for d in body["downloaded"])
    assert rels == ["a.bin", "sub/b.bin"]


async def test_v025_wp3_download_recursive_cap(tmp_path, monkeypatch) -> None:
    """More than 512 listed files -> capped flag + remaining count."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    root = r"C:\Work\big"
    fake.tree = [
        {"name": f"{root}\\f{i:04d}.bin", "dir": False, "size": 1,
         "data": b"x"}
        for i in range(520)
    ]

    body = await _call(server, "file_manage", {
        "action": "download", "remote_path": root, "recursive": True})
    assert body["ok"] is True, body
    assert body["capped"] is True
    assert body["remaining"] == 8
    assert body["counts"]["downloaded"] == 512
