"""Unit tests for the idalib_stdio_shim JOBS pipeline.

The shim depends on ida-pro-mcp packages at runtime, but the JOBS
helpers themselves only touch stdlib (asyncio, json, uuid, time).
We import the module by file path with the anyio/mcp dependencies
stubbed so the tests run in the plain orchestrator venv.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

SHIM_PATH = Path(__file__).parent.parent / "idalib_stdio_shim.py"


def _install_stubs() -> None:
    """Provide minimal stand-ins for the runtime deps the shim imports.
    We only touch the JOBS pipeline, which doesn't call into any of
    these — but the module-level imports must resolve."""
    for name in ("anyio", "mcp", "mcp.types", "mcp.client",
                 "mcp.client.sse", "mcp.server", "mcp.server.lowlevel",
                 "mcp.server.stdio"):
        sys.modules.setdefault(name, types.ModuleType(name))
    # mcp.types.TextContent / Tool: dataclass-ish stubs
    tt = sys.modules["mcp.types"]
    class TextContent:
        def __init__(self, type: str = "text", text: str = "") -> None:
            self.type = type
            self.text = text
    class Tool:
        def __init__(self, name: str = "", description: str = "",
                     inputSchema: dict | None = None) -> None:
            self.name = name
            self.description = description
            self.inputSchema = inputSchema or {}
    tt.TextContent = TextContent
    tt.Tool = Tool
    # mcp.ClientSession — unused by JOBS tests
    sys.modules["mcp"].ClientSession = object
    sys.modules["mcp.client.sse"].sse_client = lambda url: None
    class _Server:
        def __init__(self, *a, **kw) -> None:
            pass
        def list_tools(self):
            def _dec(fn): return fn
            return _dec
        def call_tool(self):
            def _dec(fn): return fn
            return _dec
        def create_initialization_options(self):
            return {}
        async def run(self, *a, **kw):
            pass
    sys.modules["mcp.server.lowlevel"].Server = _Server
    sys.modules["mcp.server.stdio"].stdio_server = None
    sys.modules["anyio"].run = None


_install_stubs()
_spec = importlib.util.spec_from_file_location("suspex_shim_under_test", SHIM_PATH)
shim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shim)  # type: ignore[union-attr]


async def test_stash_result_and_page_roundtrip() -> None:
    """A completed job's result_text is chunked correctly across pages
    of the requested size, including the tail page."""
    shim.JOBS.clear()
    text = "".join(chr(0x30 + (i % 10)) for i in range(50_000))  # 50k
    job_id = await shim._stash_result("decompile_function", {}, "sid_x", text)
    assert job_id.startswith("j_")

    # Status shows done + total_bytes.
    st = json.loads(await shim._ida_job_status(job_id=job_id))
    assert st["status"] == "done"
    assert st["total_bytes"] == 50_000

    # Page 0 with a 10k page: pull 5 chunks and reassemble.
    collected: list[str] = []
    total_pages = None
    page = 0
    while True:
        r = json.loads(await shim._ida_result(job_id=job_id, page=page,
                                               page_size=10_000))
        assert r["status"] == "done"
        collected.append(r["data"])
        total_pages = r["total_pages"]
        if r["is_last"]:
            break
        page += 1
    assert total_pages == 5
    assert "".join(collected) == text


async def test_spawn_job_completes_and_serves_result() -> None:
    """A background job started via _spawn_job settles to done and its
    result_text becomes fetchable via _ida_result."""
    shim.JOBS.clear()

    async def _work():
        await asyncio.sleep(0.05)
        # Return a TextContent list, matching the shape _spawn_job expects.
        return [shim.types.TextContent(type="text", text="hello world")]

    job_id = await shim._spawn_job("decompile_function", {}, "sid_x", _work)
    # First observed: pending.
    st = json.loads(await shim._ida_job_status(job_id=job_id))
    assert st["status"] in ("pending", "done")

    # Wait for completion.
    for _ in range(30):
        st = json.loads(await shim._ida_job_status(job_id=job_id))
        if st["status"] == "done":
            break
        await asyncio.sleep(0.02)
    assert st["status"] == "done"
    assert st["total_bytes"] == len("hello world")

    r = json.loads(await shim._ida_result(job_id=job_id, page=0))
    assert r["data"] == "hello world"
    assert r["is_last"] is True


async def test_unknown_job_id_is_actionable() -> None:
    shim.JOBS.clear()
    with pytest.raises(RuntimeError, match="unknown job"):
        await shim._ida_job_status(job_id="j_nope")
    with pytest.raises(RuntimeError, match="unknown job"):
        await shim._ida_result(job_id="j_nope")


async def test_page_out_of_range() -> None:
    shim.JOBS.clear()
    jid = await shim._stash_result("t", {}, "s", "abcdef")
    with pytest.raises(RuntimeError, match="out of range"):
        await shim._ida_result(job_id=jid, page=99, page_size=2)


async def test_chunked_envelope_shape(tmp_path, monkeypatch) -> None:
    """v0.14 L6 hard cutover — the chunked envelope now speaks the shared
    {ok, kind:"artifact", tool, action, data, summary, artifact} shape and
    spills full-listing bytes to <spill_dir>/<sha256>.listing so
    file_manage(read_artifact) can serve them by content hash."""
    monkeypatch.setenv("SUSPX_MCP_SPILL_DIR", str(tmp_path))
    text = "X" * 60_000
    jid = await shim._stash_result("disassemble_function", {}, "sid_x", text)
    env = json.loads(shim._chunked_envelope(jid, "disassemble_function", text,
                                             action="disassemble_function"))
    assert env["ok"] is True
    assert env["kind"] == "artifact"
    assert env["tool"] == "ida_manage"
    assert env["action"] == "disassemble_function"
    assert env["data"]["job_id"] == jid
    assert env["data"]["preview"].startswith("X")
    assert env["summary"]["size_bytes"] == 60_000
    assert env["summary"]["truncated"] is True
    assert env["summary"]["item_total"] >= 2  # total chunks
    art = env["artifact"]
    assert len(art["sha256"]) == 64
    assert art["content_type"] == "listing"
    assert art["field"] == "listing"
    assert art["size"] == 60_000
    assert "read_artifact" in art["replay_hint"]
    # The listing bytes actually land on disk under the spill dir.
    listing = tmp_path / f"{art['sha256']}.listing"
    assert listing.exists()
    assert listing.stat().st_size == 60_000


async def test_pending_envelope_shape() -> None:
    """v0.14 L6 — pending envelope now speaks the shared v0.14 shape."""
    env = json.loads(shim._pending_envelope("j_abc", "exec_idapython",
                                             action="exec_idapython",
                                             elapsed_ms=25_000))
    assert env["ok"] is True
    assert env["kind"] == "pending"
    assert env["tool"] == "ida_manage"
    assert env["action"] == "exec_idapython"
    assert env["data"]["job_id"] == "j_abc"
    assert env["data"]["state"] == "running"
    assert env["summary"]["elapsed_ms"] == 25_000
    warns = env.get("warnings", [])
    assert any("poll" in w.lower() for w in warns)


async def test_chunked_envelope_sha256_round_trip(tmp_path, monkeypatch) -> None:
    """The sha256 in the chunked envelope's artifact slot should match the
    sha256 of the bytes actually written to disk — proving _ida_result can
    later find the spill by content hash even after the JOBS entry expires."""
    import hashlib
    monkeypatch.setenv("SUSPX_MCP_SPILL_DIR", str(tmp_path))
    text = "line\n" * 6_000  # 30 KB, above CHUNK_BYTES
    jid = await shim._stash_result("decompile_function", {}, "sid_y", text)
    env = json.loads(shim._chunked_envelope(jid, "decompile_function", text,
                                             action="decompile_function"))
    expected_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert env["artifact"]["sha256"] == expected_sha
    # And _ida_result can serve pages by that sha256 alone.
    r = json.loads(await shim._ida_result(sha256=expected_sha, page=0,
                                           page_size=8_192))
    assert r["status"] == "done"
    assert r["sha256"] == expected_sha
    assert r["page"] == 0
    assert r["total_pages"] >= 3
    assert r["data"].startswith("line\n")
