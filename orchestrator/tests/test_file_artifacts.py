"""v0.16: grep_artifact bare-sha resolution and list_artifacts enumeration.

Exercises the file_manage surface via the same in-memory FastMCP client
pattern used by test_multi_agent.py. Seeds the orchestrator's spill_dir
with a handful of fake spilled artifacts (no live target needed) and
asserts:

    - list_artifacts returns them, sorted newest-first.
    - grep_artifact with a bare 64-hex sha256 resolves to the spilled
      artifact and matches lines inside.
    - grep_artifact with a filesystem path still works.
    - unknown sha yields kind='artifact_missing'.
"""

from __future__ import annotations

import asyncio
import hashlib
import json as _json
import os
import time
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


def _seed_artifact(spill_dir, ext: str, content: bytes) -> str:
    sha = hashlib.sha256(content).hexdigest()
    (spill_dir / f"{sha}{ext}").write_bytes(content)
    return sha


async def _build_ctx_and_server(tmp_path) -> tuple[Context, Any]:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    (art_dir / "spill").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(art_dir / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), art_dir)
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
    return ctx, build_server(ctx)


async def _call_as(client_id: str, server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set(client_id)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    # v0.17 A-1: envelope now rides in ``structured_content`` (no text
    # copy in ``content`` unless SUSPX_MCP_LEGACY_DUAL_CONTENT=1). Fall
    # back to the text path for the legacy dual-emit shape.
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
    if isinstance(body.get("summary"), dict):
        merged.setdefault("summary", body["summary"])
    return merged


async def test_list_artifacts_enumerates_spilled_files(tmp_path) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path)
    spill = ctx.cfg.spill_dir()
    _seed_artifact(spill, ".txt", b"alpha content\nline two\n")
    # Force a monotonic mtime gap so the sort is deterministic on Windows.
    os.utime(spill / next(iter(os.listdir(spill))), (time.time() - 60, time.time() - 60))
    sha_b = _seed_artifact(spill, ".jsonl", b'{"hit": 1}\n{"hit": 2}\n')

    body = await _call_as("peer-A", server, "file_manage", {"action": "list_artifacts"})
    assert body["ok"] is True
    items = body.get("items") or []
    shas = [r["sha256"] for r in items]
    # The freshly-written .jsonl should be first (newest); the aged .txt
    # is still enumerated.
    assert items[0]["sha256"] == sha_b
    assert any(r["kind"] == "jsonl" for r in items)
    assert any(r["kind"] == "txt" for r in items)
    assert len(shas) == 2


async def test_grep_artifact_bare_sha_resolves(tmp_path) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path)
    spill = ctx.cfg.spill_dir()
    payload = b"needle line one\nnothing here\nneedle line three\n"
    sha = _seed_artifact(spill, ".txt", payload)

    body = await _call_as("peer-A", server, "file_manage", {
        "action": "grep_artifact",
        "sha256": sha,
        "pattern": r"needle",
    })
    assert body["ok"] is True
    items = body.get("items") or []
    assert len(items) == 2
    assert all("needle" in row["match"] for row in items)


async def test_grep_artifact_unknown_sha_returns_typed_error(tmp_path) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path)
    # 64 hex chars but not in spill_dir
    fake_sha = "f" * 64
    body = await _call_as("peer-A", server, "file_manage", {
        "action": "grep_artifact",
        "sha256": fake_sha,
        "pattern": "anything",
    })
    assert body["ok"] is False
    assert body["kind"] == "artifact_missing"


async def test_grep_artifact_bare_path_still_works(tmp_path) -> None:
    """The v0.16 sha resolver must not regress the plain-path path."""
    ctx, server = await _build_ctx_and_server(tmp_path)
    art_dir = ctx.cfg.artifacts_dir()
    plain = art_dir / "plain.txt"
    plain.write_text("hello world\nthe brown fox\n")

    body = await _call_as("peer-A", server, "file_manage", {
        "action": "grep_artifact",
        "path": str(plain),
        "pattern": r"brown",
    })
    assert body["ok"] is True
    items = body.get("items") or []
    assert len(items) == 1
    assert "brown fox" in items[0]["match"]
