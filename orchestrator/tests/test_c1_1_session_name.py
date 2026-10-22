"""v0.17 C1-1: caller-supplied IDA session `name` is honored verbatim.

Before this change, ``ida_manage(action='open', path='tcpip.sys',
name='tcpip26200')`` would silently collapse to the session name
``tcpip`` because the top-level ``name`` kwarg was dropped in favour
of ``Path(path).stem``. Also verifies:
- charset validation refuses ``../evil`` and similar traversal names
- collision (same name, different path) fails with a ``session_exists``
  message instead of the historical silent ``<name>#<hex>`` rename
- collision (same name, same path) still shares cleanly under
  ``share=True`` — same session id returned, ``shared=true`` on the
  second caller's envelope.
"""

from __future__ import annotations

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
            {"name": "idb_close", "description": "close"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "idb_open":
            pref = args.get("preferred_session_id", "x")
            text = "opened session sid_" + str(pref)
        elif name == "idb_list":
            text = json.dumps([])
        elif name == "idb_close":
            text = "closed"
        else:
            text = "called " + str(name)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "error": {"code": -32601, "message": "?"}}) + "\n")
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


async def test_c1_1_name_honored_verbatim(bridge: IdaBridge, tmp_path: Path):
    """Top-level `name` kwarg wins over Path(path).stem."""
    binary = tmp_path / "tcpip.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        out = await bridge.ida_manage(
            "open", "tcpip26200",
            {"path": str(binary)},
        )
        env = json.loads(out)
        assert env["status"] == "ready", env
        assert env["name"] == "tcpip26200", env
        # session id derives from the preferred_session_id we handed to
        # the shim, so the fake echo confirms the value was propagated.
        assert env["session_id"] == "sid_tcpip26200", env
        assert bridge.sessions["tcpip26200"] == "sid_tcpip26200"
    finally:
        await bridge.stop()


async def test_c1_1_name_honored_verbatim_open_async(
    bridge: IdaBridge, tmp_path: Path,
):
    """Same precedence rule on open_async."""
    binary = tmp_path / "nt.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        out = await bridge.ida_manage(
            "open_async", "nt.10.0.26100",
            {"path": str(binary), "return_after_s": 5.0},
        )
        env = json.loads(out)
        # completed instantly against the fake; both status paths
        # (ready and pending) must carry the caller's requested name.
        assert env["name"] == "nt.10.0.26100", env
    finally:
        await bridge.stop()


async def test_c1_1_preferred_session_id_still_works_when_no_name(
    bridge: IdaBridge, tmp_path: Path,
):
    """A caller who only passes preferred_session_id (legacy shape) still wins."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        out = await bridge.ida_manage(
            "open", None,
            {"path": str(binary), "preferred_session_id": "legacy_name"},
        )
        env = json.loads(out)
        assert env["name"] == "legacy_name", env
    finally:
        await bridge.stop()


async def test_c1_1_falls_back_to_path_stem(bridge: IdaBridge, tmp_path: Path):
    """No name, no preferred_session_id -> Path(path).stem still works."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        out = await bridge.ida_manage("open", None, {"path": str(binary)})
        env = json.loads(out)
        assert env["name"] == "victim", env
    finally:
        await bridge.stop()


async def test_c1_1_name_collision_different_path_errors(
    bridge: IdaBridge, tmp_path: Path,
):
    """Opening name='foo' on two DIFFERENT paths -> session_exists error."""
    a = tmp_path / "a.sys"
    a.write_bytes(b"MZa")
    b = tmp_path / "b.sys"
    b.write_bytes(b"MZb")
    try:
        # First open lands.
        out1 = await bridge.ida_manage(
            "open", "foo", {"path": str(a)})
        assert json.loads(out1)["name"] == "foo"
        # Second open, same name but different path, refuses.
        with pytest.raises(IdaBridgeError, match=r"session_exists"):
            await bridge.ida_manage("open", "foo", {"path": str(b)})
    finally:
        await bridge.stop()


async def test_c1_1_name_collision_same_path_shares(
    bridge: IdaBridge, tmp_path: Path,
):
    """Same name AND same path -> reuses the existing session; with
    share=True the second caller becomes a co-owner."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        out1 = await bridge.ida_manage(
            "open", "foo", {"path": str(binary)}, owner="alice")
        env1 = json.loads(out1)
        sid = env1["session_id"]
        # Second caller opens the SAME (name, path) with share=True; the
        # bridge treats this as a co-owner join, not a peer collision.
        out2 = await bridge.ida_manage(
            "open", "foo",
            {"path": str(binary), "share": True},
            owner="bob",
        )
        env2 = json.loads(out2)
        assert env2["name"] == "foo"
        assert env2["session_id"] == sid
        assert env2["shared"] is True, env2
    finally:
        await bridge.stop()


async def test_c1_1_invalid_name_charset(bridge: IdaBridge, tmp_path: Path):
    """A name containing filesystem-escape metachars refuses the open."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        with pytest.raises(IdaBridgeError, match=r"invalid session name"):
            await bridge.ida_manage(
                "open", "../evil", {"path": str(binary)})
    finally:
        await bridge.stop()


async def test_c1_1_invalid_name_charset_spaces(
    bridge: IdaBridge, tmp_path: Path,
):
    """Whitespace and separators are rejected up front."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        with pytest.raises(IdaBridgeError, match=r"invalid session name"):
            await bridge.ida_manage(
                "open", "name with spaces", {"path": str(binary)})
    finally:
        await bridge.stop()


async def test_c1_1_invalid_name_too_long(bridge: IdaBridge, tmp_path: Path):
    """Names longer than 64 chars refuse up front (idb budget limit)."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        with pytest.raises(IdaBridgeError, match=r"invalid session name"):
            await bridge.ida_manage(
                "open", "a" * 65, {"path": str(binary)})
    finally:
        await bridge.stop()


async def test_c1_1_artifacts_dir_uses_requested_name(
    bridge: IdaBridge, tmp_path: Path,
):
    """The per-session artifacts subdir must be named for the caller's
    requested name, not Path(path).stem — otherwise two sessions on
    the same input collide on-disk."""
    binary = tmp_path / "tcpip.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await bridge.ida_manage(
            "open", "tcpip26200", {"path": str(binary)})
        expected = bridge.artifacts_dir / "tcpip26200"
        assert expected.is_dir(), (
            f"artifacts subdir {expected} was not created; the requested "
            "name lost precedence to Path(path).stem again"
        )
    finally:
        await bridge.stop()
