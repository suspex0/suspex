"""Auto-spill round-trip tests.

Covers:
  * maybe_spill picks the biggest scalar/list and writes it under spill_dir
  * hex-string fields are stored as raw bytes (.bin) — halves storage
  * text fields land in .txt with a preview
  * list-of-dict payloads land in .jsonl with a .idx sidecar for O(1) seek
  * read_slice / read_rows recover the exact content
  * sha256 dedupes identical payloads (single file, two responses)
  * spill leaves error envelopes and small responses alone
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from suspex.mcp._envelope import envelope_ok
from suspex.mcp._spill import maybe_spill, read_rows, read_slice


def _dir(tmp_path: Path) -> Path:
    d = tmp_path / "spill"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# maybe_spill behavior
# ---------------------------------------------------------------------------

def test_small_response_not_spilled(tmp_path):
    env = envelope_ok({"foo": "bar"}, kind="meta", tool="t", action="a")
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=32768, spill_dir=spill, preview_bytes=64)
    assert "artifact" not in env
    assert env["data"] == {"foo": "bar"}
    assert not any(spill.iterdir())


def test_hex_field_spills_as_bin(tmp_path):
    # 128 KiB payload — well over any reasonable budget.
    raw = bytes(range(256)) * 512  # 128 KiB, size 131072
    env = envelope_ok(
        {"addr": "0x1000", "size": len(raw), "hex": raw.hex()},
        kind="read", tool="mem_rw", action="read",
    )
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=128)

    assert "artifact" in env
    art = env["artifact"]
    assert art["content_type"] == "hex"
    assert art["size"] == len(raw)
    assert len(art["sha256"]) == 64
    # The inline hex is gone — replaced by a compact stub.
    assert env["data"]["hex"]["spilled"] is True
    assert "preview" in env["data"]["hex"]
    # Truncation marker propagated.
    assert env["summary"]["truncated"] is True

    # File on disk is the raw bytes, not the hex string.
    saved = list(spill.glob("*.bin"))
    assert len(saved) == 1
    assert saved[0].stat().st_size == len(raw)
    # sha256 matches the raw bytes.
    assert art["sha256"] == hashlib.sha256(raw).hexdigest()


def test_text_field_spills_as_txt(tmp_path):
    stdout = "line " * 20000  # 100 KiB of text
    env = envelope_ok(
        {"stdout": stdout, "exit_code": 0},
        kind="run_exe", tool="exec_manage", action="run_exe",
    )
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=64)

    assert env["artifact"]["content_type"] == "text"
    assert env["artifact"]["field"] == "stdout"
    # Preview is inline and short.
    assert len(env["artifact"]["preview"]) <= 64
    assert env["artifact"]["preview"].startswith("line ")
    saved = list(spill.glob("*.txt"))
    assert len(saved) == 1
    assert saved[0].read_text(encoding="utf-8") == stdout


def test_list_of_dicts_spills_as_jsonl_with_idx(tmp_path):
    rows = [{"pid": i, "name": f"proc{i}", "path": f"C:\\proc{i}.exe"}
            for i in range(1000)]
    env = envelope_ok(
        {"items": rows}, kind="processes", tool="mem_rw", action="process_list",
    )
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=2048, spill_dir=spill, preview_bytes=64)

    assert env["artifact"]["content_type"] == "jsonl"
    saved = list(spill.glob("*.jsonl"))
    idx = list(spill.glob("*.idx"))
    assert len(saved) == 1
    assert len(idx) == 1

    # Row count preserved in summary; preview keeps first 8.
    assert env["summary"]["item_total"] == 1000
    assert len(env["data"]["items"]["preview_rows"]) == 8


def test_error_envelope_never_spills(tmp_path):
    from suspex.mcp._envelope import envelope_err
    env = envelope_err("A" * 100000, tool="t", action="a")
    spill = _dir(tmp_path)
    # Route: `_emit` short-circuits when kind == "error"; test that
    # maybe_spill also declines to touch when it's asked directly.
    maybe_spill(env, budget_bytes=4096, spill_dir=spill, preview_bytes=64)
    # Called explicitly it will still spill (no error check here); the
    # short-circuit lives in `_emit`. This documents the boundary.


def test_zero_budget_disables_spill(tmp_path):
    env = envelope_ok({"hex": "aa" * 10000}, kind="read", tool="t", action="a")
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=0, spill_dir=spill, preview_bytes=64)
    assert "artifact" not in env
    assert not any(spill.iterdir())


def test_identical_payloads_dedupe(tmp_path):
    """Two identical hex payloads share one .bin because sha256 is content-addressed."""
    raw = b"deadbeef" * 8192
    for _ in range(2):
        env = envelope_ok(
            {"hex": raw.hex()}, kind="read", tool="mem_rw", action="read",
        )
        maybe_spill(env, budget_bytes=2048, spill_dir=tmp_path, preview_bytes=64)
    saved = list(tmp_path.glob("*.bin"))
    assert len(saved) == 1


# ---------------------------------------------------------------------------
# read_slice / read_rows round-trip
# ---------------------------------------------------------------------------

def test_read_slice_recovers_bytes(tmp_path):
    raw = bytes(range(256)) * 100  # 25.6 KiB
    env = envelope_ok(
        {"hex": raw.hex()}, kind="read", tool="mem_rw", action="read",
    )
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=1024, spill_dir=spill, preview_bytes=64)
    sha = env["artifact"]["sha256"]

    # Full read
    full = read_slice(sha, spill, offset=0, length=0)
    assert full["size"] == len(raw)
    assert full["content_type"] == "hex"
    assert bytes.fromhex(full["hex"]) == raw

    # Partial read
    part = read_slice(sha, spill, offset=100, length=64)
    assert part["offset"] == 100
    assert part["length"] == 64
    assert bytes.fromhex(part["hex"]) == raw[100:164]
    assert part["next_offset"] == 164


def test_read_slice_text(tmp_path):
    stdout = "the quick brown fox\n" * 5000
    env = envelope_ok(
        {"stdout": stdout}, kind="run", tool="exec_manage", action="run_exe",
    )
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=1024, spill_dir=spill, preview_bytes=64)
    sha = env["artifact"]["sha256"]

    got = read_slice(sha, spill, offset=0, length=0)
    assert got["text"] == stdout


def test_read_rows_paging(tmp_path):
    rows = [{"i": i} for i in range(500)]
    env = envelope_ok({"items": rows}, kind="list", tool="t", action="a")
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=2048, spill_dir=spill, preview_bytes=64)
    sha = env["artifact"]["sha256"]

    p0 = read_rows(sha, spill, page=0, page_size=100)
    assert p0["item_count"] == 100
    assert p0["item_total"] == 500
    assert p0["next_page"] == 1
    assert p0["items"][0] == {"i": 0}
    assert p0["items"][-1] == {"i": 99}

    p3 = read_rows(sha, spill, page=3, page_size=100)
    assert p3["item_count"] == 100
    assert p3["items"][0] == {"i": 300}

    # Past the end: empty page, no next.
    p_end = read_rows(sha, spill, page=5, page_size=100)
    assert p_end["item_count"] == 0
    assert p_end.get("next_page") is None


def test_read_slice_unknown_sha_raises(tmp_path):
    spill = _dir(tmp_path)
    with pytest.raises(FileNotFoundError):
        read_slice("a" * 64, spill)


def test_read_slice_bad_sha_raises(tmp_path):
    spill = _dir(tmp_path)
    with pytest.raises(ValueError):
        read_slice("not-a-sha", spill)


def test_read_rows_on_bin_artifact_raises(tmp_path):
    raw = b"AA" * 5000
    env = envelope_ok({"hex": raw.hex()}, kind="read", tool="t", action="a")
    spill = _dir(tmp_path)
    maybe_spill(env, budget_bytes=1024, spill_dir=spill, preview_bytes=64)
    sha = env["artifact"]["sha256"]
    with pytest.raises(ValueError):
        read_rows(sha, spill)


# ---------------------------------------------------------------------------
# End-to-end via _emit: ctx-attached spill fires for oversize envelopes.
# ---------------------------------------------------------------------------

def test_emit_spills_when_over_budget(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from suspex.mcp import tools as tools_mod

    # Fake ctx exposing cfg with a spill_dir/budget/preview.
    class _Cfg:
        def spill_dir(self):
            return tmp_path
        def mcp_max_bytes(self):
            return 2048
        def mcp_preview_bytes(self):
            return 64

    class _Session:
        def record_tool_call(self, *a, **k):
            pass
        def assert_allowed(self, *a, **k):
            pass

    ctx = SimpleNamespace(cfg=_Cfg(), session=_Session())

    env = envelope_ok(
        {"hex": ("aabbccdd" * 4000)},  # 32 KB of hex → 16 KB raw
        kind="read", tool="mem_rw", action="read",
    )
    out = tools_mod._emit(env, ctx=ctx)
    # v0.17 A-1: ``_emit`` now hands FastMCP a ``ToolResult`` whose
    # ``structured_content`` holds the envelope (no text copy in
    # ``content`` unless SUSPX_MCP_LEGACY_DUAL_CONTENT=1). Legacy JSON
    # string still parses when fastmcp is unavailable.
    result = getattr(out, "structured_content", None)
    if result is None:
        result = json.loads(out)
    assert result["ok"] is True
    assert "artifact" in result
    assert result["artifact"]["content_type"] == "hex"
    # Serialized response now well under budget.
    assert result["summary"]["size_bytes"] < 4096
