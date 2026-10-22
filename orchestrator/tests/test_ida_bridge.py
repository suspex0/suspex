"""IdaBridge unit tests against a fake MCP stdio server (no IDA required)."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from suspex.ida_bridge import IdaBridge, IdaBridgeError, IdaConfigLite

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
                  "serverInfo": {"name": "fake-idalib-mcp"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "idb_open", "description": "open"},
            {"name": "idb_list", "description": "list"},
            {"name": "decompile_function", "description": "decompile"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "idb_open":
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "decompile_function":
            text = "decompiled database=" + str(args.get("database"))
        elif name == "idb_list":
            text = json.dumps([{"session_id": "sid_victim", "preferred_session_id": "victim"}])
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

# Same wire protocol as FAKE_SERVER, but the idb_open tool call sleeps for two
# seconds before responding -- exercises the open_soft_deadline_s fallback.
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
                  "serverInfo": {"name": "fake-idalib-mcp-slow"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "idb_open", "description": "open"},
            {"name": "idb_list", "description": "list"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "idb_open":
            time.sleep(2.0)
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "idb_list":
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
def bridge(tmp_path: Path) -> IdaBridge:
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    return IdaBridge(cfg, tmp_path / "artifacts")


async def test_precheck_rejects_missing_exe(tmp_path: Path) -> None:
    cfg = IdaConfigLite(command=["definitely-not-a-real-tool-xyz", "run"])
    b = IdaBridge(cfg, tmp_path)
    with pytest.raises(IdaBridgeError, match="not found"):
        b.precheck()


async def test_open_database_extracts_session(bridge: IdaBridge, tmp_path: Path) -> None:
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    envelope = await bridge.open_database(binary, "victim")
    assert envelope["status"] == "ready"
    assert envelope["session_id"] == "sid_victim"
    assert envelope["name"] == "victim"
    assert bridge.sessions["victim"] == "sid_victim"
    await bridge.stop()


async def test_decompile_forwards_resolved_database(bridge: IdaBridge, tmp_path: Path) -> None:
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    await bridge.open_database(binary, "victim")
    out = await bridge.ida_manage("decompile", "victim", {"address": "0x1400"})
    assert "decompiled database=sid_victim" in out
    await bridge.stop()


async def test_unknown_action_rejected(bridge: IdaBridge) -> None:
    with pytest.raises(IdaBridgeError, match="unknown ida_manage action"):
        await bridge.ida_manage("disassemble_everything")
    await bridge.stop()


async def test_tool_not_offered_is_actionable(bridge: IdaBridge) -> None:
    await bridge.ensure_started()
    # fake server offers idb_open/decompile/idb_list but not "patch"
    with pytest.raises(IdaBridgeError, match="not offered by idalib-mcp"):
        await bridge.ida_manage("patch", "victim")
    await bridge.stop()


async def test_store_binary_artifact_layout(bridge: IdaBridge) -> None:
    import hashlib

    data = b"MZ" + b"A" * 64
    path = await bridge.store_binary(data, "victim.exe")
    assert path.parent.name == hashlib.sha256(data).hexdigest()
    assert path.read_bytes() == data


async def test_open_auto_forwards_on_slow_backend(tmp_path: Path) -> None:
    """Slow-backend guard: when idb_open outruns open_soft_deadline_s, the
    sync open_database returns the same pending envelope open_database_async
    would, and the in-flight tools/call keeps running so open_status(name)
    reports 'ready' once the shim finishes."""
    fake = tmp_path / "fake_idalib_mcp_slow.py"
    fake.write_text(FAKE_SERVER_SLOW, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)], open_soft_deadline_s=0.5)
    b = IdaBridge(cfg, tmp_path / "artifacts")

    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        envelope = await b.open_database(binary, "victim")
        assert isinstance(envelope, dict), envelope
        assert envelope.get("status") == "pending", envelope
        assert envelope.get("name") == "victim", envelope

        # The shim sleeps 2s; give the shielded task room to finish, then
        # confirm the poll surface sees a completed session.
        # v0.17 C1-2: open_status is async now (best-effort live probe).
        await asyncio.sleep(2.5)
        status = await b.open_status("victim")
        assert status.get("status") == "ready", status
        assert status.get("session_id") == "sid_victim", status
    finally:
        await b.stop()


# Fake server that returns a HUGE decompile_function payload — bigger than
# the default 64 KiB asyncio StreamReader line limit, which used to crash
# the bridge's readline() with 'Separator is found, but chunk is longer
# than limit'. The v0.8 bridge bumps the subprocess limit to 32 MiB, so
# this response should round-trip cleanly.
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
                  "serverInfo": {"name": "fake-idalib-mcp-huge"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "idb_open", "description": "open"},
            {"name": "idb_list", "description": "list"},
            {"name": "decompile_function", "description": "decompile"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "idb_open":
            text = "opened session sid_" + str(args.get("preferred_session_id", "x"))
        elif name == "decompile_function":
            text = BIG
        elif name == "idb_list":
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
    """Regression: pre-v0.8 the bridge spawned the subprocess with the
    asyncio StreamReader default 64 KiB line cap; a single decompile
    response of a real 100 KB function crashed readline. v0.8 bumps to
    32 MiB. A 150 KiB payload must now round-trip."""
    fake = tmp_path / "fake_idalib_mcp_huge.py"
    fake.write_text(FAKE_SERVER_HUGE, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    b = IdaBridge(cfg, tmp_path / "artifacts")

    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await b.open_database(binary, "victim")
        out = await b.ida_manage("decompile", "victim", {"address": "0x1400"})
        # Bridge returns the raw text from the shim; huge payload survives.
        assert len(out) >= 150 * 1024, f"got only {len(out)} bytes back"
        assert out.startswith("A"), out[:32]
    finally:
        await b.stop()
