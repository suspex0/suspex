"""v0.17 C1-2: ``open_status`` (and every ready-path envelope from
``open`` / ``open_async``) carries the ``symbols`` /
``named_functions`` / ``pdb`` triple.

Before this change callers had no way to distinguish "database
opened, symbols loaded" from "database opened, PDB fetch silently
failed, name searches will return nothing" — the only signal was a
follow-up ``list_functions`` that came back empty.

The classifier helpers are pure, so we exercise them directly to
pin the transition table, then drive the live probe through a fake
idalib-mcp that echoes an ``ida_status`` shape we control.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from suspex.ida_bridge import (  # noqa: E402
    IdaBridge,
    IdaConfigLite,
    _classify_pdb,
    _classify_symbols,
    _safe_int,
)


# ---- Pure classifier ------------------------------------------------------

def test_c1_2_classify_symbols_loaded():
    """functions_count > 0 -> loaded regardless of analysis_state."""
    assert _classify_symbols({"functions_count": 42, "analysis_state": "running"}) == "loaded"
    assert _classify_symbols({"functions_count": 1, "analysis_state": "idle"}) == "loaded"


def test_c1_2_classify_symbols_failed_when_idle_zero():
    """analysis_state=idle AND functions_count=0 -> failed (analysis quiesced
    but nothing was carved, matches "PDB fetch failed silently" in practice)."""
    assert _classify_symbols({"functions_count": 0, "analysis_state": "idle"}) == "failed"


def test_c1_2_classify_symbols_loading_when_running():
    """Zero functions but analysis still churning -> loading."""
    assert _classify_symbols({"functions_count": 0, "analysis_state": "running"}) == "loading"


def test_c1_2_classify_symbols_missing_fields_defaults_to_loading():
    """No functions_count key: default 0; no analysis_state key: not idle."""
    assert _classify_symbols({}) == "loading"


def test_c1_2_classify_pdb_matched_from_bool():
    """pdb_matched=True -> matched, False -> missing."""
    assert _classify_pdb({"pdb_matched": True}) == "matched"
    assert _classify_pdb({"pdb_matched": False}) == "missing"


def test_c1_2_classify_pdb_string_wins():
    """An explicit `pdb` string (matched|missing|failed) is preserved."""
    assert _classify_pdb({"pdb": "matched"}) == "matched"
    assert _classify_pdb({"pdb": "failed"}) == "failed"
    assert _classify_pdb({"pdb": "missing"}) == "missing"


def test_c1_2_classify_pdb_unknown_when_absent():
    """No signal from the extension -> unknown so callers get a stable slot."""
    assert _classify_pdb({}) == "unknown"


def test_c1_2_safe_int_defaults_zero():
    assert _safe_int(None) == 0
    assert _safe_int("junk") == 0
    assert _safe_int(3) == 3
    assert _safe_int("42") == 42


# ---- Live probe over a fake idalib-mcp ------------------------------------

# Fake shim that:
#  * registers `ida_status` alongside idb_open/list/close
#  * echoes a caller-controllable `functions_count` and `analysis_state`
#    (encoded via the `preferred_session_id` prefix so the test controls
#    what a probe sees per session).
FAKE_SERVER = r"""
import json, sys
STATUS_BY_SID = {}
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
            {"name": "ida_status", "description": "status"},
        ]}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "idb_open":
            pref = args.get("preferred_session_id", "x")
            # Preferred-session-id conventions we cooperate with:
            #   loaded_N  -> functions_count=N, analysis_state=idle
            #   loading_N -> functions_count=N, analysis_state=running
            #   failed    -> functions_count=0, analysis_state=idle
            #   pdb_ok    -> also pdb_matched=True (loaded=1)
            #   probe_err -> ida_status returns isError
            sid = "sid_" + str(pref)
            STATUS_BY_SID[sid] = pref
            text = "opened session " + sid
        elif name == "ida_status":
            sid = args.get("database", "")
            pref = STATUS_BY_SID.get(sid, "")
            if pref == "probe_err":
                out = {"content": [{"type": "text", "text": "probe boom"}],
                       "isError": True}
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                             "result": out}) + "\n")
                sys.stdout.flush()
                continue
            body = {"ok": True, "analysis_state": "idle",
                    "functions_count": 0, "input_path": "x",
                    "idb_target": "x.i64"}
            if pref.startswith("loaded_"):
                body["functions_count"] = int(pref.split("_", 1)[1])
                body["analysis_state"] = "idle"
            elif pref.startswith("loading_"):
                body["functions_count"] = int(pref.split("_", 1)[1])
                body["analysis_state"] = "running"
            elif pref == "failed":
                body["functions_count"] = 0
                body["analysis_state"] = "idle"
            elif pref == "pdb_ok":
                body["functions_count"] = 1
                body["analysis_state"] = "idle"
                body["pdb_matched"] = True
            text = json.dumps(body)
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


async def test_c1_2_open_status_ready_reports_named_functions(
    bridge: IdaBridge, tmp_path: Path,
):
    """A ready session with 42 functions surfaces ``named_functions=42``
    and ``symbols=loaded`` in the open_status envelope."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        env = json.loads(await bridge.ida_manage(
            "open", "loaded_42", {"path": str(binary)}))
        assert env["status"] == "ready"
        # The open envelope also carries the triple now.
        assert env["symbols"] == "loaded", env
        assert env["named_functions"] == 42, env
        assert env["pdb"] == "unknown", env

        st = json.loads(await bridge.ida_manage(
            "open_status", "loaded_42", {}))
        assert st["status"] == "ready", st
        assert st["symbols"] == "loaded", st
        assert st["named_functions"] == 42, st
    finally:
        await bridge.stop()


async def test_c1_2_open_status_pending_reports_loading(
    bridge: IdaBridge, tmp_path: Path,
):
    """A pending status (in-flight task) reports ``symbols=loading``
    and ``named_functions=0`` without a probe (session id not yet
    resolved)."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        # Simulate pending by injecting an unfinished future into
        # _pending_opens directly — the fake shim completes instantly
        # so the natural path is always 'ready'.
        loop = asyncio.get_event_loop()
        never = loop.create_future()
        task = asyncio.ensure_future(_await_future(never))
        bridge._pending_opens["waiter"] = (task, str(binary))
        try:
            st = json.loads(await bridge.ida_manage(
                "open_status", "waiter", {}))
            assert st["status"] == "pending", st
            assert st["symbols"] == "loading", st
            assert st["named_functions"] == 0, st
            assert st["pdb"] == "unknown", st
        finally:
            never.cancel()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
    finally:
        await bridge.stop()


async def _await_future(fut: asyncio.Future[str]) -> str:
    return await fut


async def test_c1_2_open_status_zero_funcs_idle_reports_failed(
    bridge: IdaBridge, tmp_path: Path,
):
    """analysis_state=idle AND functions_count=0 -> ``symbols=failed``,
    the "PDB fetch silently missed" bucket callers need to see."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await bridge.ida_manage("open", "failed", {"path": str(binary)})
        st = json.loads(await bridge.ida_manage(
            "open_status", "failed", {}))
        assert st["status"] == "ready", st
        assert st["symbols"] == "failed", st
        assert st["named_functions"] == 0, st
    finally:
        await bridge.stop()


async def test_c1_2_open_status_probe_error_reports_unknown(
    bridge: IdaBridge, tmp_path: Path,
):
    """A live-probe wire error must NOT flip a ready session to error;
    the enrichment fields fall through to unknown/0 instead."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await bridge.ida_manage("open", "probe_err", {"path": str(binary)})
        st = json.loads(await bridge.ida_manage(
            "open_status", "probe_err", {}))
        assert st["status"] == "ready", st
        # Probe returned isError -> classifiers see an empty dict.
        assert st["symbols"] == "loading", st
        assert st["named_functions"] == 0, st
        assert st["pdb"] == "unknown", st
    finally:
        await bridge.stop()


async def test_c1_2_open_envelope_carries_symbols_triple(
    bridge: IdaBridge, tmp_path: Path,
):
    """A blocking ``open`` (not open_async) also inherits the triple on
    the ready path — no follow-up poll needed to see whether the
    freshly opened DB actually has symbols."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        env = json.loads(await bridge.ida_manage(
            "open", "loading_0", {"path": str(binary)}))
        assert env["status"] == "ready"
        # functions_count=0, analysis_state=running -> loading bucket.
        assert env["symbols"] == "loading", env
        assert env["named_functions"] == 0, env
        assert env["pdb"] == "unknown", env
    finally:
        await bridge.stop()


async def test_c1_2_open_envelope_pdb_matched_bool(
    bridge: IdaBridge, tmp_path: Path,
):
    """When the extension exposes ``pdb_matched=True`` (C2-3 hookup)
    the envelope reports ``pdb=matched`` instead of unknown."""
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        env = json.loads(await bridge.ida_manage(
            "open", "pdb_ok", {"path": str(binary)}))
        assert env["status"] == "ready"
        assert env["pdb"] == "matched", env
        assert env["symbols"] == "loaded", env
        assert env["named_functions"] == 1, env
    finally:
        await bridge.stop()


async def test_c1_2_open_status_unknown_when_never_opened(
    bridge: IdaBridge, tmp_path: Path,
):
    """A poll for a name we've never opened still hits the ``unknown``
    fast-path — no probe, no error, an actionable hint."""
    try:
        st = json.loads(await bridge.ida_manage(
            "open_status", "ghost", {}))
        assert st["status"] == "unknown", st
        assert "hint" in st, st
    finally:
        await bridge.stop()
