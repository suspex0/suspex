"""GhidraBridge unit tests against a fake MCP stdio server (no Ghidra/JVM
required) — mirrors test_ida_bridge.py; the fake speaks the same
line-delimited JSON-RPC but answers the ghidra_* shim tool names."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from suspex.ghidra_bridge import (  # noqa: E402
    GhidraBridge,
    GhidraBridgeError,
    GhidraConfigLite,
)

FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    rid = msg["id"]
    method = msg.get("method", "")
    params = msg.get("params", {}) or {}
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {},
                  "serverInfo": {"name": "fake-ghidra-shim"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "ghidra_open", "description": "open"},
            {"name": "ghidra_list", "description": "list"},
            {"name": "ghidra_close", "description": "close"},
            {"name": "decompile_function", "description": "decompile"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "ghidra_open":
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "decompile_function":
            text = "decompiled database=" + str(args.get("database"))
        elif name == "ghidra_list":
            text = json.dumps([{"session_id": "sid_victim", "preferred_session_id": "victim"}])
        elif name == "ghidra_close":
            text = "closed " + str(args.get("database"))
        else:
            text = "called " + str(name)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "error": {"code": -32601, "message": "unknown method"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()
"""

# Same wire protocol as FAKE_SERVER, but the ghidra_open call sleeps for
# two seconds before responding -- exercises the open_soft_deadline_s
# fallback (JVM+analysis is the slow path this deadline exists for).
FAKE_SERVER_SLOW = r"""
import json, sys, time
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    rid = msg["id"]
    method = msg.get("method", "")
    params = msg.get("params", {}) or {}
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {},
                  "serverInfo": {"name": "fake-ghidra-shim-slow"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "ghidra_open", "description": "open"},
            {"name": "ghidra_list", "description": "list"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "ghidra_open":
            time.sleep(2.0)
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "ghidra_list":
            text = json.dumps([])
        else:
            text = "called " + str(name)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "error": {"code": -32601, "message": "unknown method"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()
"""


@pytest.fixture()
def bridge(tmp_path: Path) -> GhidraBridge:
    fake = tmp_path / "fake_ghidra_shim.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = GhidraConfigLite(command=[sys.executable, str(fake)])
    return GhidraBridge(cfg, tmp_path / "artifacts")


async def test_precheck_rejects_missing_exe(tmp_path: Path) -> None:
    cfg = GhidraConfigLite(command=["definitely-not-a-real-tool-xyz", "run"])
    b = GhidraBridge(cfg, tmp_path)
    with pytest.raises(GhidraBridgeError, match="not found"):
        b.precheck()


async def test_open_database_extracts_session(bridge: GhidraBridge, tmp_path: Path) -> None:
    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    envelope = await bridge.open_database(binary, "victim")
    assert envelope["status"] == "ready"
    assert envelope["session_id"] == "sid_victim"
    assert envelope["name"] == "victim"
    assert bridge.sessions["victim"] == "sid_victim"
    await bridge.stop()


async def test_decompile_forwards_resolved_database(bridge: GhidraBridge, tmp_path: Path) -> None:
    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    await bridge.open_database(binary, "victim")
    out = await bridge.ghidra_manage("decompile", "victim", {"address": "0x1400"})
    assert "decompiled database=sid_victim" in out
    await bridge.stop()


async def test_unknown_action_rejected(bridge: GhidraBridge) -> None:
    with pytest.raises(GhidraBridgeError, match="unknown ghidra_manage action"):
        await bridge.ghidra_manage("disassemble_everything")
    await bridge.stop()


async def test_tool_not_offered_is_actionable(bridge: GhidraBridge) -> None:
    await bridge.ensure_started()
    # `pcode` is a mapped verb (→ get_pcode) but the fake server doesn't
    # offer it — _require_tool must raise the actionable error.
    with pytest.raises(GhidraBridgeError, match="not offered"):
        await bridge.ghidra_manage("pcode", "victim")
    await bridge.stop()


async def test_store_binary_artifact_layout(bridge: GhidraBridge) -> None:
    import hashlib

    data = b"MZ" + b"A" * 64
    path = await bridge.store_binary(data, "victim.sys")
    assert path.parent.name == hashlib.sha256(data).hexdigest()
    assert path.read_bytes() == data


async def test_open_auto_forwards_on_slow_backend(tmp_path: Path) -> None:
    """Slow-backend guard: when ghidra_open outruns open_soft_deadline_s
    (JVM start + import + auto-analysis is the norm, not the exception),
    the sync open_database returns the same pending envelope
    open_database_async would, and the in-flight tools/call keeps running
    so open_status(name) reports 'ready' once the shim finishes."""
    fake = tmp_path / "fake_ghidra_shim_slow.py"
    fake.write_text(FAKE_SERVER_SLOW, encoding="utf-8")
    cfg = GhidraConfigLite(command=[sys.executable, str(fake)],
                           open_soft_deadline_s=0.5)
    b = GhidraBridge(cfg, tmp_path / "artifacts")

    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        envelope = await b.open_database(binary, "victim")
        assert isinstance(envelope, dict), envelope
        assert envelope.get("status") == "pending", envelope
        assert envelope.get("name") == "victim", envelope

        await asyncio.sleep(2.5)
        status = await b.open_status("victim")
        assert status.get("status") == "ready", status
        assert status.get("session_id") == "sid_victim", status
    finally:
        await b.stop()


# Fake server that returns a HUGE decompile_function payload — bigger than
# the default 64 KiB asyncio StreamReader line limit. Same regression
# coverage as the IDA huge-line test: the bridge bumps the subprocess
# limit to 32 MiB.
FAKE_SERVER_HUGE = r"""
import json, sys
BIG = "A" * (150 * 1024)  # 150 KiB — well past the 64 KiB default limit
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    rid = msg["id"]
    method = msg.get("method", "")
    params = msg.get("params", {}) or {}
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {},
                  "serverInfo": {"name": "fake-ghidra-shim-huge"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "ghidra_open", "description": "open"},
            {"name": "ghidra_list", "description": "list"},
            {"name": "decompile_function", "description": "decompile"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "ghidra_open":
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "decompile_function":
            text = BIG
        elif name == "ghidra_list":
            text = json.dumps([])
        else:
            text = "called " + str(name)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "error": {"code": -32601, "message": "unknown method"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()
"""


async def test_bridge_survives_huge_line_response(tmp_path: Path) -> None:
    """Regression parity with the IDA bridge test: a single decompile
    response past the 64 KiB StreamReader default must round-trip."""
    fake = tmp_path / "fake_ghidra_shim_huge.py"
    fake.write_text(FAKE_SERVER_HUGE, encoding="utf-8")
    cfg = GhidraConfigLite(command=[sys.executable, str(fake)])
    b = GhidraBridge(cfg, tmp_path / "artifacts")

    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await b.open_database(binary, "victim")
        out = await b.ghidra_manage("decompile", "victim", {"address": "0x1400"})
        assert len(out) >= 150 * 1024, f"got only {len(out)} bytes back"
        assert out.startswith("A"), out[:32]
    finally:
        await b.stop()
