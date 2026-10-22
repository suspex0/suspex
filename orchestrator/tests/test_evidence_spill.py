"""maybe_spill evidence wiring (Part 3, Task 3.3).

Bare calls behave exactly as before; wiring artifacts_root + ledger +
request retains the complete pre-spill payload as an evidence record and
sets env["evidence"] with a continuation. Producer-stamped blocks only
gain the continuation.
"""
from __future__ import annotations

import json
from pathlib import Path

from suspex.findings import FindingsLedger
from suspex.mcp._spill import maybe_spill
from suspex.mcp._envelope import envelope_ok
from suspex.mcp.evidence import store as ev_store
from suspex.mcp.evidence import views as ev_views


def _wired(tmp_path: Path):
    return {
        "artifacts_root": tmp_path / "artifacts",
        "ledger": FindingsLedger(tmp_path / "artifacts" / "findings.db"),
        "request": {"action": "read", "pid": 4, "address": "0x1000"},
    }


def _big_hex_env() -> dict:
    raw = bytes(range(256)) * 512  # 128 KiB
    return envelope_ok(
        {"addr": "0x1000", "size": len(raw), "hex": raw.hex()},
        kind="read", tool="mem_rw", action="read",
    ), raw


def test_bare_spill_behavior_unchanged(tmp_path: Path):
    env, _raw = _big_hex_env()
    spill = tmp_path / "spill"
    spill.mkdir()
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128)
    assert "artifact" in env
    assert "evidence" not in env  # bare call — no retention


def test_partial_wiring_no_retention(tmp_path: Path):
    env, _raw = _big_hex_env()
    spill = tmp_path / "spill"
    spill.mkdir()
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128,
                artifacts_root=tmp_path / "artifacts", ledger=None,
                request={"action": "read"})
    assert "artifact" in env
    assert "evidence" not in env


def test_spill_with_wiring_retains_full_record(tmp_path: Path):
    env, raw = _big_hex_env()
    spill = tmp_path / "spill"
    spill.mkdir()
    w = _wired(tmp_path)
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128,
                **w)
    # Legacy spill surface untouched.
    assert "artifact" in env
    assert env["data"]["hex"]["spilled"] is True
    assert "preview" in env["data"]["hex"]
    # Evidence block added with continuation.
    ev = env["evidence"]
    assert ev["evidence_id"].startswith("ev_")
    assert ev["detail"] == "complete"
    cont = ev["continuation"]
    assert cont["tool"] == "knowledge_manage"
    assert cont["action"] == "evidence_get"
    assert cont["args"]["evidence_id"] == ev["evidence_id"]
    assert cont["args"]["offset"] == 0
    # The retained record carries the FULL pre-spill payload.
    rec = ev_store.load(ev["evidence_id"],
                        artifacts_root=w["artifacts_root"])
    assert rec["data"]["hex"] == raw.hex()
    assert rec["request"]["address"] == "0x1000"
    # Ledger row (tool/action lifted from the envelope).
    row = w["ledger"].evidence_record(ev["evidence_id"])
    assert row is not None
    assert row["tool"] == "mem_rw"
    assert row["action"] == "read"
    w["ledger"].close()


def test_list_payload_spill_retains_rows(tmp_path: Path):
    rows = [{"i": i, "blob": "x" * 64} for i in range(500)]
    env = envelope_ok({"items": rows}, kind="meta",
                      tool="file_manage", action="list")
    spill = tmp_path / "spill"
    spill.mkdir()
    w = _wired(tmp_path)
    maybe_spill(env, budget_bytes=2048, spill_dir=spill, preview_bytes=128,
                **w)
    assert "artifact" in env
    ev = env["evidence"]
    rec = ev_store.load(ev["evidence_id"],
                        artifacts_root=w["artifacts_root"])
    assert rec["data"]["items"] == rows
    w["ledger"].close()


def test_producer_stamped_block_gains_only_continuation(tmp_path: Path):
    env, raw = _big_hex_env()
    # Simulate a heavy tool that already retained the complete record.
    w = _wired(tmp_path)
    _, block = ev_store.retain_record(
        request=w["request"], data=env["data"],
        artifacts_root=w["artifacts_root"], ledger=w["ledger"],
        tool="mem_rw", action="read", detail="complete")
    stamped = dict(block)
    env["evidence"] = stamped
    spill = tmp_path / "spill"
    spill.mkdir()
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128,
                **w)
    # Same evidence_id — no second record, continuation added.
    assert env["evidence"]["evidence_id"] == block["evidence_id"]
    assert "continuation" in env["evidence"]
    assert w["ledger"].evidence_record(block["evidence_id"]) is not None
    assert len(w["ledger"].evidence_records()) == 1
    w["ledger"].close()


def test_spill_evidence_continuation_pages_exact_bytes(tmp_path: Path):
    env, raw = _big_hex_env()
    spill = tmp_path / "spill"
    spill.mkdir()
    w = _wired(tmp_path)
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128,
                **w)
    rec = ev_store.load(env["evidence"]["evidence_id"],
                        artifacts_root=w["artifacts_root"])
    args = env["evidence"]["continuation"]["args"]
    off, lim = args["offset"], args["limit"]
    page, total, truncated = ev_views.page_view(rec, offset=off, limit=lim)
    assert total == len(raw.hex())
    assert page == raw.hex()[off:off + lim]
    assert truncated is True
    w["ledger"].close()
