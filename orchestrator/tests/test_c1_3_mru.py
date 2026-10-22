"""v0.17 C1-3: MRU IDA session — session-scoped ``ida_manage`` actions
without an explicit ``name=`` fall back to the most-recently-opened
session, and the response envelope carries a warning so the caller
sees which session actually served the request.

Before this change every session-scoped call required ``name=``; a
caller with exactly one open database still had to plumb its
public name through every follow-up. Also verifies:

- ``open`` bumps MRU; a fresh open switches it.
- ``close`` rotates MRU onto any remaining session; drops to None
  when the last session goes.
- ``autofill_session_name`` respects the non-session action list
  (open/open_async/open_status/list/schemas never autofill).
- ``open_status`` still needs its explicit ``name=`` — it reports
  on a specific session, not "whatever's current".
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from suspex.ida_bridge import (  # noqa: E402
    IdaBridge,
    IdaConfigLite,
    _NON_SESSION_ACTIONS,
)


def _stub_bridge(tmp_path: Path) -> IdaBridge:
    """Build a bridge WITHOUT starting the shim — we only exercise the
    pure MRU bookkeeping here. The shim spins up in the integration
    tests below."""
    cfg = IdaConfigLite(command=[sys.executable, "-c", "pass"])
    return IdaBridge(cfg, tmp_path / "artifacts")


# ---------- Pure MRU bookkeeping --------------------------------------------

def test_c1_3_mru_starts_none(tmp_path: Path):
    b = _stub_bridge(tmp_path)
    assert b.mru_session is None


def test_c1_3_touch_mru_updates(tmp_path: Path):
    b = _stub_bridge(tmp_path)
    b._touch_mru("first")
    assert b.mru_session == "first"
    b._touch_mru("second")
    assert b.mru_session == "second"


def test_c1_3_rotate_after_close_falls_to_remaining(tmp_path: Path):
    """When the MRU session is closed and any other session remains,
    the MRU rotates onto that fallback rather than dangling."""
    b = _stub_bridge(tmp_path)
    b._sessions["alpha"] = "sid_alpha"
    b._sessions["beta"] = "sid_beta"
    b._touch_mru("beta")
    b._rotate_mru_after_close("beta")
    assert b.mru_session == "alpha", (
        "MRU should rotate to `alpha` once `beta` is gone"
    )


def test_c1_3_rotate_after_close_clears_when_empty(tmp_path: Path):
    """Closing the last session clears MRU so autofill surfaces the
    right "open a session first" error instead of a stale name."""
    b = _stub_bridge(tmp_path)
    b._sessions["only"] = "sid_only"
    b._touch_mru("only")
    b._sessions.pop("only")
    b._rotate_mru_after_close("only")
    assert b.mru_session is None


def test_c1_3_rotate_after_close_preserves_non_mru(tmp_path: Path):
    """Closing a non-MRU session must NOT change the MRU."""
    b = _stub_bridge(tmp_path)
    b._sessions["alpha"] = "sid_alpha"
    b._sessions["beta"] = "sid_beta"
    b._touch_mru("beta")
    b._rotate_mru_after_close("alpha")
    assert b.mru_session == "beta"


# ---------- autofill_session_name --------------------------------------------

def test_c1_3_autofill_non_session_actions_pass_through(tmp_path: Path):
    """open/open_async/open_status/list/schemas never autofill."""
    b = _stub_bridge(tmp_path)
    b._touch_mru("mru_name")
    for action in _NON_SESSION_ACTIONS:
        name, autofilled = b.autofill_session_name(action, None)
        assert name is None, f"{action} should not autofill"
        assert autofilled is False


def test_c1_3_autofill_explicit_name_wins(tmp_path: Path):
    b = _stub_bridge(tmp_path)
    b._touch_mru("mru_name")
    name, autofilled = b.autofill_session_name("decompile", "explicit")
    assert name == "explicit"
    assert autofilled is False


def test_c1_3_autofill_uses_mru_on_session_action(tmp_path: Path):
    b = _stub_bridge(tmp_path)
    b._touch_mru("victim")
    name, autofilled = b.autofill_session_name("decompile", None)
    assert name == "victim"
    assert autofilled is True


def test_c1_3_autofill_signals_no_mru(tmp_path: Path):
    """Session-scoped action with no MRU: signal True + None so the
    caller raises an actionable "open first" error."""
    b = _stub_bridge(tmp_path)
    name, autofilled = b.autofill_session_name("decompile", None)
    assert name is None
    assert autofilled is True


# ---------- End-to-end: open bumps MRU, close rotates it --------------------

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
def live_bridge(tmp_path: Path) -> IdaBridge:
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    return IdaBridge(cfg, tmp_path / "artifacts")


async def test_c1_3_open_bumps_mru(
    live_bridge: IdaBridge, tmp_path: Path,
):
    """A successful open makes the requested name the MRU."""
    binary = tmp_path / "a.sys"
    binary.write_bytes(b"MZa")
    try:
        assert live_bridge.mru_session is None
        await live_bridge.ida_manage(
            "open", "alpha", {"path": str(binary)})
        assert live_bridge.mru_session == "alpha"
    finally:
        await live_bridge.stop()


async def test_c1_3_two_opens_second_wins_mru(
    live_bridge: IdaBridge, tmp_path: Path,
):
    """The most-recent open is the MRU; the earlier one is still open."""
    a = tmp_path / "a.sys"
    a.write_bytes(b"MZa")
    b = tmp_path / "b.sys"
    b.write_bytes(b"MZb")
    try:
        await live_bridge.ida_manage("open", "alpha", {"path": str(a)})
        await live_bridge.ida_manage("open", "beta", {"path": str(b)})
        assert live_bridge.mru_session == "beta"
        assert set(live_bridge.sessions.keys()) == {"alpha", "beta"}
    finally:
        await live_bridge.stop()


async def test_c1_3_close_mru_rotates_to_remaining(
    live_bridge: IdaBridge, tmp_path: Path,
):
    """Closing the MRU session shifts MRU onto any remaining session."""
    a = tmp_path / "a.sys"
    a.write_bytes(b"MZa")
    b = tmp_path / "b.sys"
    b.write_bytes(b"MZb")
    try:
        await live_bridge.ida_manage("open", "alpha", {"path": str(a)})
        await live_bridge.ida_manage("open", "beta", {"path": str(b)})
        assert live_bridge.mru_session == "beta"
        await live_bridge.ida_manage("close", "beta", {})
        assert live_bridge.mru_session == "alpha"
    finally:
        await live_bridge.stop()


async def test_c1_3_close_last_session_clears_mru(
    live_bridge: IdaBridge, tmp_path: Path,
):
    """Closing the last session clears MRU."""
    binary = tmp_path / "only.sys"
    binary.write_bytes(b"MZ")
    try:
        await live_bridge.ida_manage(
            "open", "only", {"path": str(binary)})
        assert live_bridge.mru_session == "only"
        await live_bridge.ida_manage("close", "only", {})
        assert live_bridge.mru_session is None
    finally:
        await live_bridge.stop()
