"""Unit tests for the ghidra_shim JOBS pipeline — mirrors
test_shim_jobs.py. The ghidra supervisor lives in the `ghidra_shim`
package; the job helpers only touch stdlib, but `dispatch`/`sessions`
import mcp, so the same stub pattern applies."""
from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


_STUBBED: list[str] = []


def _install_stubs() -> None:
    """Minimal stand-ins for the mcp imports in ghidra_shim.sessions /
    dispatch — the JOBS pipeline never calls into them.

    Stubs are REMOVED from sys.modules after the shim modules import
    (see below): a leftover bare ModuleType for ``mcp`` breaks the real
    import machinery in later-collected test files
    (``importlib.util.find_spec('mcp')`` -> ``mcp.__spec__ is None``).
    """
    for name in ("mcp", "mcp.types", "mcp.client", "mcp.client.sse",
                 "mcp.server", "mcp.server.lowlevel", "mcp.server.stdio"):
        if name in sys.modules:
            continue
        sys.modules[name] = types.ModuleType(name)
        _STUBBED.append(name)
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
    tt.Content = TextContent  # dispatch annotates with types.Content
    tt.Tool = Tool
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


_install_stubs()

from ghidra_shim.dispatch import (  # noqa: E402
    _ghidra_job_status,
    _ghidra_result,
    _inject_binary_name,
)
from ghidra_shim.envelopes import (  # noqa: E402
    _chunked_envelope,
    _pending_envelope,
)
from ghidra_shim.jobs import (  # noqa: E402
    JOBS,
    _spawn_job,
    _stash_result,
)

# Stubs served their purpose (ghidra_shim.* modules hold bound
# references); drop them so real `mcp` resolves normally for every other
# test module in this run.
for _name in _STUBBED:
    sys.modules.pop(_name, None)


async def test_stash_result_and_page_roundtrip() -> None:
    """A completed job's result_text chunks correctly across pages,
    including the tail page."""
    JOBS.clear()
    text = "".join(chr(0x30 + (i % 10)) for i in range(50_000))
    job_id = await _stash_result("decompile_function", {}, "sid_x", text)
    assert job_id.startswith("j_")

    st = json.loads(await _ghidra_job_status(job_id=job_id))
    assert st["status"] == "done"
    assert st["total_bytes"] == 50_000

    collected: list[str] = []
    total_pages = None
    page = 0
    while True:
        r = json.loads(await _ghidra_result(job_id=job_id, page=page,
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
    """A background job settles to done and its result_text becomes
    fetchable via _ghidra_result."""
    JOBS.clear()
    # TextContent must be the same class the shim's `types` module bound
    # (the stub — isinstance() checks inside the shim rely on it).
    from ghidra_shim import listing as _listing
    _TextContent = _listing.types.TextContent

    async def _work():
        await asyncio.sleep(0.05)
        return [_TextContent(type="text", text="hello world")]

    job_id = await _spawn_job("decompile_function", {}, "sid_x", _work)
    st = json.loads(await _ghidra_job_status(job_id=job_id))
    assert st["status"] in ("pending", "done")

    for _ in range(30):
        st = json.loads(await _ghidra_job_status(job_id=job_id))
        if st["status"] == "done":
            break
        await asyncio.sleep(0.02)
    assert st["status"] == "done"
    assert st["total_bytes"] == len("hello world")

    r = json.loads(await _ghidra_result(job_id=job_id, page=0))
    assert r["data"] == "hello world"
    assert r["is_last"] is True


async def test_unknown_job_id_is_actionable() -> None:
    JOBS.clear()
    with pytest.raises(RuntimeError, match="unknown job"):
        await _ghidra_job_status(job_id="j_nope")
    with pytest.raises(RuntimeError, match="unknown job"):
        await _ghidra_result(job_id="j_nope")


async def test_page_out_of_range() -> None:
    JOBS.clear()
    jid = await _stash_result("t", {}, "s", "abcdef")
    with pytest.raises(RuntimeError, match="out of range"):
        await _ghidra_result(job_id=jid, page=99, page_size=2)


async def test_chunked_envelope_shape(tmp_path, monkeypatch) -> None:
    """The chunked envelope speaks the shared {ok, kind:"artifact", ...}
    shape with tool=ghidra_manage and spills the full listing bytes."""
    monkeypatch.setenv("SUSPX_MCP_SPILL_DIR", str(tmp_path))
    text = "X" * 60_000
    jid = await _stash_result("disassemble_function", {}, "sid_x", text)
    env = json.loads(_chunked_envelope(jid, "disassemble_function", text,
                                       action="disassemble_function"))
    assert env["ok"] is True
    assert env["kind"] == "artifact"
    assert env["tool"] == "ghidra_manage"
    assert env["action"] == "disassemble_function"
    assert env["data"]["job_id"] == jid
    assert env["data"]["preview"].startswith("X")
    assert env["summary"]["size_bytes"] == 60_000
    assert env["summary"]["truncated"] is True
    art = env["artifact"]
    assert len(art["sha256"]) == 64
    assert art["content_type"] == "listing"
    listing = tmp_path / f"{art['sha256']}.listing"
    assert listing.exists()
    assert listing.stat().st_size == 60_000


async def test_pending_envelope_shape() -> None:
    env = json.loads(_pending_envelope("j_abc", "exec_ghidra_script",
                                       action="exec_ghidra_script",
                                       elapsed_ms=25_000))
    assert env["ok"] is True
    assert env["kind"] == "pending"
    assert env["tool"] == "ghidra_manage"
    assert env["action"] == "exec_ghidra_script"
    assert env["data"]["job_id"] == "j_abc"
    assert env["data"]["state"] == "running"
    assert env["summary"]["elapsed_ms"] == 25_000
    warns = env.get("warnings", [])
    assert any("poll" in w.lower() for w in warns)


def test_inject_binary_name_routes_program() -> None:
    """_inject_binary_name stamps the session's program name as
    binary_name — the session-name -> program mapping every backend
    tool needs."""
    st = {"program": "tcpip.sys", "path": "/x/tcpip.sys"}
    args = {"address": "0x14000"}
    _inject_binary_name("decompile_function", args, st)
    assert args["binary_name"] == "tcpip.sys"
    # An explicit binary_name from the caller wins (never clobber).
    args2 = {"binary_name": "other.sys"}
    _inject_binary_name("decompile_function", args2, st)
    assert args2["binary_name"] == "other.sys"


def test_inject_binary_name_skips_project_tools() -> None:
    """Once the backend schema cache knows a tool doesn't take
    binary_name (project-level verbs), injection leaves it alone."""
    from ghidra_shim import dispatch as _dispatch
    st = {"program": "tcpip.sys", "path": "/x/tcpip.sys"}
    _dispatch.BACKEND_TOOL_META.update({
        "import_binary": {"inputSchema": {"properties": {"binary_path": {}}}},
        "list_project_binaries": {"inputSchema": {"properties": {}}},
        "project_info": {"inputSchema": {"properties": {}}},
    })
    try:
        for tool in ("import_binary", "list_project_binaries",
                     "project_info"):
            args: dict = {}
            _inject_binary_name(tool, args, st)
            assert "binary_name" not in args, tool
    finally:
        for tool in ("import_binary", "list_project_binaries",
                     "project_info"):
            _dispatch.BACKEND_TOOL_META.pop(tool, None)
