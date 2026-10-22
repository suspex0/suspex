"""detail= semantics on heavy producers (Part 3, Task 3.4).

Integration through the real dump_manage parse/stack path (works
unconnected) plus unit coverage of stamp_result's summary/complete
behavior and coverage preservation.
"""
from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.evidence import store as ev_store
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


def _filetime(y: int, m: int, d: int) -> int:
    import datetime as _dt
    dt = _dt.datetime(y, m, d, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return int((dt.timestamp() + 11644473600) * 10_000_000)


def _dump_bytes() -> bytes:
    """Minimal DUMP_HEADER64 + triage stack (same layout as
    test_v025_wp1_dump_tool's fixture — duplicated so this file stays
    self-contained)."""
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
    struct.pack_into("<I", hdr, 0x348 + 0x30, 0x0010001F)
    struct.pack_into("<Q", hdr, 0x348 + 0x78 + 4 * 8, 0xFFFFF80011119000)
    struct.pack_into("<Q", hdr, 0x3F8, 0xFFFFF80000001234)
    tri = bytearray(0x80)
    struct.pack_into("<I", tri, 0x00, 4)             # TRIAGE signature
    struct.pack_into("<Q", tri, 0x48, 0xFFFFF80011119000)
    struct.pack_into("<Q", tri, 0x58, 0xFFFFF80000001234)
    return bytes(hdr) + bytes(tri)


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
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger,
                  bridge=IdaBridge(IdaConfigLite.from_config(cfg.ida),
                                   tmp_path / "artifacts"),
                  clients=clients_reg,
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-detail")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body


def _parse_args(dmp: Path, **extra: Any) -> dict:
    return {"action": "parse", "path": str(dmp), **extra}


async def test_detail_complete_delivers_inline_and_retains(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_dump_bytes())

    body = await _call(server, "dump_manage", _parse_args(dmp))
    assert body["ok"] is True, body
    # Full payload delivered inline.
    assert body["data"]["bugcheck"]["code"] == 0x133
    # Evidence block present, complete detail, fully delivered inline ->
    # no continuation handle.
    ev = body["evidence"]
    assert ev["evidence_id"].startswith("ev_")
    assert ev["detail"] == "complete"
    assert "continuation" not in ev
    # Record retained verbatim under artifacts/evidence/.
    rec = ev_store.load(ev["evidence_id"],
                        artifacts_root=Path(ctx.cfg.artifacts_dir()))
    assert rec["data"]["bugcheck"]["code"] == 0x133
    assert rec["request"]["action"] == "parse"
    # Ledger row written, unattached.
    row = ctx.ledger.evidence_record(ev["evidence_id"])
    assert row is not None
    assert row["tool"] == "dump_manage"
    assert row["kind"] == "tool_result"


async def test_detail_summary_returns_counts_not_payload(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_dump_bytes())

    body = await _call(server, "dump_manage",
                       _parse_args(dmp, detail="summary"))
    assert body["ok"] is True, body
    data = body["data"]
    # Bounded view: counts + request, no payload rows/bytes.
    assert set(data) <= {"counts", "request", "coverage", "provenance",
                         "ok", "evidence"}
    assert "bugcheck" not in data
    assert data["counts"], "summary must show per-field sizes"
    ev = body["evidence"]
    assert ev["detail"] == "summary"
    assert ev["continuation"]["tool"] == "knowledge_manage"
    assert ev["continuation"]["action"] == "evidence_get"
    assert ev["continuation"]["args"]["evidence_id"] == ev["evidence_id"]
    # The complete record is intact behind the summary.
    rec = ev_store.load(ev["evidence_id"],
                        artifacts_root=Path(ctx.cfg.artifacts_dir()))
    assert rec["data"]["bugcheck"]["code"] == 0x133


async def test_summary_continuation_replays_record(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_dump_bytes())

    body = await _call(server, "dump_manage",
                       _parse_args(dmp, detail="summary"))
    ev = body["evidence"]
    rec = ev_store.load(ev["evidence_id"],
                        artifacts_root=Path(ctx.cfg.artifacts_dir()))

    # Replay the continuation args EXACTLY as advertised.
    args = dict(ev["continuation"]["args"])
    got = await _call(server, "knowledge_manage",
                      {"action": "evidence_get", **args})
    assert got["ok"] is True, got
    page = got["data"]["content"]
    field = got["data"]["field"]
    fv = rec["data"][field]
    if isinstance(fv, str):
        expected = fv[:args["limit"]]
    elif isinstance(fv, list):
        expected = fv[:args["limit"]]
    else:  # dict blob pages as a single row
        expected = [fv]
    assert page == expected
    # Page 2 continues the payload exactly.
    consumed = len(page) if isinstance(page, (str, list)) else 1
    args2 = dict(args, offset=args["offset"] + consumed)
    got2 = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", **args2})
    fv2 = fv[args2["offset"]:args2["offset"] + args["limit"]] \
        if isinstance(fv, (str, list)) else [fv]
    assert got2["data"]["content"] == fv2


async def test_detail_complete_deterministic_and_deduped(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_dump_bytes())

    b1 = await _call(server, "dump_manage", _parse_args(dmp))
    b2 = await _call(server, "dump_manage", _parse_args(dmp))
    assert b1["evidence"]["evidence_id"] == b2["evidence"]["evidence_id"]
    rows = ctx.ledger.evidence_records()
    assert len(rows) == 1


async def test_default_detail_is_complete_backcompat(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_dump_bytes())
    body = await _call(server, "dump_manage", _parse_args(dmp))
    assert body["data"]["bugcheck"]["code"] == 0x133
    assert body["evidence"]["detail"] == "complete"


# ------------------------------------------------------------ stamp_result units ----

def _unit_ctx(tmp_path: Path):
    cfg = SuspexConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    return SimpleNamespace(cfg=cfg, ledger=ledger)


def test_stamp_result_summary_preserves_coverage_unknown(tmp_path: Path):
    ctx = _unit_ctx(tmp_path)
    legacy = {"ok": True, "addr": "0x1000", "hex": "aa" * 200,
              "coverage": {"scope": "mem-read", "status": "unknown",
                           "limits": []}}
    out = ev_store.stamp_result(ctx, "mem_rw", "read", {"action": "read",
                                                        "pid": 5},
                                json.dumps(legacy), "summary")
    parsed = json.loads(out)
    # Summary must NOT launder unknown into complete — copied verbatim.
    assert parsed["coverage"]["status"] == "unknown"
    assert parsed["counts"]["hex"] == 400  # "aa" * 200
    assert parsed["evidence"]["detail"] == "summary"


def test_stamp_result_complete_passes_payload_through(tmp_path: Path):
    ctx = _unit_ctx(tmp_path)
    legacy = {"ok": True, "bugcheck": {"code": 0x133}}
    out = ev_store.stamp_result(ctx, "dump_manage", "parse",
                                {"action": "parse"}, json.dumps(legacy),
                                "complete")
    parsed = json.loads(out)
    assert parsed["bugcheck"]["code"] == 0x133
    assert parsed["evidence"]["detail"] == "complete"
    assert "continuation" not in parsed["evidence"]


def test_stamp_result_passes_through_non_results(tmp_path: Path):
    ctx = _unit_ctx(tmp_path)
    err = json.dumps({"ok": False, "kind": "not_found",
                      "error": "nope"})
    assert ev_store.stamp_result(ctx, "mem_rw", "read", {}, err,
                                 "summary") == err
    raw = "<html>shim text</html>"
    assert ev_store.stamp_result(ctx, "ida_manage", "weird", {}, raw,
                                 "summary") == raw
    assert ev_store.stamp_result(ctx, "mem_rw", "write", {}, "{\"ok\": true}",
                                 "nonsense") == "{\"ok\": true}"


def test_stamp_result_handles_envelope_dict_results(tmp_path: Path):
    # mem.py returns ready dicts for list actions (hexify_dict output):
    # already-envelope shape + envelope-level coverage block.
    ctx = _unit_ctx(tmp_path)

    def _base() -> dict:
        return {"ok": True, "kind": "modules", "tool": "mem_rw",
                "action": "modules",
                "data": {"items": [{"name": f"m{i:02d}",
                                    "base": hex(0x1000 * i)}
                                   for i in range(40)]},
                "summary": {"item_count": 40, "item_total": 40},
                "coverage": {"scope": "enumeration",
                             "status": "complete"}}

    req = {"action": "modules", "pid": 4}
    env = _base()
    out = ev_store.stamp_result(ctx, "mem_rw", "modules", req, env,
                                "complete")
    assert out is env
    assert out["evidence"]["detail"] == "complete"
    rec = ev_store.load(out["evidence"]["evidence_id"],
                        artifacts_root=Path(ctx.cfg.artifacts_dir()))
    assert rec["data"]["items"][0]["name"] == "m00"
    # Envelope-level coverage captured into the record.
    assert rec["coverage"]["status"] == "complete"

    # Idempotency: a second stamp on an already-stamped result is a no-op.
    again = ev_store.stamp_result(ctx, "mem_rw", "modules", req, env,
                                  "summary")
    assert again is env
    assert again["evidence"]["detail"] == "complete"

    out2 = ev_store.stamp_result(ctx, "mem_rw", "modules", req, _base(),
                                 "summary")
    assert isinstance(out2, dict)
    assert out2.get("data") is None or "items" not in out2["data"]
    assert out2["coverage"]["status"] == "complete"  # never laundered
    assert out2["evidence"]["detail"] == "summary"


def test_stamp_result_retention_failure_keeps_payload(tmp_path: Path,
                                                      monkeypatch):
    ctx = _unit_ctx(tmp_path)

    def _boom(*a: object, **k: object) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(ev_store, "save", _boom)
    legacy = {"ok": True, "hex": "ab" * 300}
    res = json.dumps(legacy)
    # A summary that cannot be retained falls back to the complete
    # payload — never a counts-only response without a record.
    out = ev_store.stamp_result(ctx, "mem_rw", "read", {"action": "read"},
                                res, "summary")
    assert json.loads(out) == legacy
