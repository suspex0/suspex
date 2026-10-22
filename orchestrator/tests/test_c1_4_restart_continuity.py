"""v0.17 C1-4: IDA session continuity across orchestrator restart.

Before this change the only way to keep a session across an
orchestrator restart was to rely on the ida-pro-mcp persistent
workers still being alive — and once a worker died with its
supervisor the session id was lost. Now the bridge writes a small
manifest (``~/.suspex0/ida_sessions.json`` by default, or the path
in ``SUSPX_IDA_MANIFEST``) at every open / close; on startup it
loads the manifest and lazy-reopens on the first
session-scoped ``ida_manage`` call that references a name from
the pre-restart set.

Every test points ``SUSPX_IDA_MANIFEST`` at a ``tmp_path`` fixture
so nothing leaks into the user's real ``~/.suspex0``. That's the
test-isolation rule from ``_shared.md`` §0.9.
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
    IDA_MANIFEST_VERSION,
    IdaBridge,
    IdaConfigLite,
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
                  "serverInfo": {"name": "fake-idalib-mcp"}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "idb_open", "description": "open"},
            {"name": "idb_list", "description": "list"},
            {"name": "idb_close", "description": "close"},
            {"name": "decompile_function", "description": "decompile"},
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
        elif name == "decompile_function":
            text = "// decomp: " + str(args.get("database", "?"))
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


def _make_bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IdaBridge:
    """Build a bridge whose manifest lands under tmp_path (never
    touches the user's real ~/.suspex0)."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    return IdaBridge(cfg, tmp_path / "artifacts")


async def test_c1_4_manifest_written_on_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A successful open lands a manifest entry that names the input
    path so a later cold-start can lazy-reopen it."""
    bridge = _make_bridge(tmp_path, monkeypatch)
    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        await bridge.ida_manage(
            "open", "victim", {"path": str(binary)})
        manifest_path = Path(str(binary.parent / "ida_sessions.json"))
        # Manifest lives under tmp_path, whose exact location the
        # env var controls.
        content = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert content["version"] == IDA_MANIFEST_VERSION
        assert "victim" in content["sessions"], content
        entry = content["sessions"]["victim"]
        assert entry["input_path"] == str(binary), entry
        assert entry["idb_target"] == f"{binary}.i64", entry
    finally:
        await bridge.stop()


async def test_c1_4_manifest_dropped_on_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A caller-initiated close removes the manifest entry so a
    later cold-start doesn't re-open a session the user explicitly
    closed."""
    bridge = _make_bridge(tmp_path, monkeypatch)
    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ")
    manifest_path = tmp_path / "ida_sessions.json"
    try:
        await bridge.ida_manage(
            "open", "victim", {"path": str(binary)})
        assert "victim" in json.loads(
            manifest_path.read_text(encoding="utf-8"))["sessions"]
        await bridge.ida_manage("close", "victim", {})
        assert "victim" not in json.loads(
            manifest_path.read_text(encoding="utf-8"))["sessions"]
    finally:
        await bridge.stop()


def test_c1_4_restore_from_manifest_populates_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A fresh bridge reads the manifest into ``_manifest_sessions``
    without spawning the shim."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    binary = tmp_path / "target.sys"
    binary.write_bytes(b"MZ")
    manifest.write_text(json.dumps({
        "version": IDA_MANIFEST_VERSION,
        "sessions": {
            "target": {
                "input_path": str(binary),
                "idb_target": f"{binary}.i64",
                "last_opened_iso": "2026-09-16T00:00:00Z",
                "run_auto_analysis": True,
            },
        },
    }), encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, "-c", "pass"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    n = b.restore_from_manifest()
    assert n == 1
    assert "target" in b._manifest_sessions
    assert b._manifest_sessions["target"]["input_path"] == str(binary)


def test_c1_4_manifest_survives_json_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A corrupted manifest silently starts fresh instead of crashing
    bridge construction."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    manifest.write_text("{ not valid json", encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, "-c", "pass"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    n = b.restore_from_manifest()
    assert n == 0
    assert b._manifest_sessions == {}


def test_c1_4_manifest_rejects_bad_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A manifest with a mismatched version integer is ignored — we
    never silently consume a schema we don't know."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    manifest.write_text(json.dumps({
        "version": 42,
        "sessions": {"x": {"input_path": "/tmp/x"}},
    }), encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, "-c", "pass"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    assert b.restore_from_manifest() == 0


def test_c1_4_manifest_rejects_invalid_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Entries with names that fail the session-name charset check
    are dropped on load — nothing gets to lazy-open a bad name."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    manifest.write_text(json.dumps({
        "version": IDA_MANIFEST_VERSION,
        "sessions": {
            "../evil": {"input_path": "/tmp/x.sys"},
            "good_name": {"input_path": "/tmp/good.sys"},
        },
    }), encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, "-c", "pass"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    b.restore_from_manifest()
    assert "../evil" not in b._manifest_sessions
    assert "good_name" in b._manifest_sessions


async def test_c1_4_lazy_open_on_missing_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A session-scoped call referencing a manifest name that isn't
    yet in ``_sessions`` triggers a silent re-open so the call
    succeeds instead of erroring out with unknown-name."""
    # Seed a manifest as if a prior process had opened `victim`.
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    binary = tmp_path / "victim.sys"
    binary.write_bytes(b"MZ")
    manifest.write_text(json.dumps({
        "version": IDA_MANIFEST_VERSION,
        "sessions": {
            "victim": {
                "input_path": str(binary),
                "idb_target": f"{binary}.i64",
                "last_opened_iso": "2026-09-15T00:00:00Z",
                "run_auto_analysis": True,
            },
        },
    }), encoding="utf-8")
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    bridge = IdaBridge(cfg, tmp_path / "artifacts")
    try:
        # Fresh bridge -> no live sessions yet.
        assert bridge.sessions == {}
        # A session-scoped call with a name that only exists in the
        # manifest triggers the lazy re-open path.
        out = await bridge.ida_manage(
            "decompile", "victim", {"address": "0x1400"})
        # The fake echoes the database sid so we can assert the
        # session actually opened rather than the shim seeing an
        # empty database=.
        assert "sid_victim" in out
        assert "victim" in bridge.sessions
        # Manifest entry has been swept into the live-session set.
        assert "victim" not in bridge._manifest_sessions
    finally:
        await bridge.stop()


async def test_c1_4_stale_input_path_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """When the manifest entry points at a file that no longer
    exists, lazy-reopen bails out (returning False) and drops the
    stale entry so a crash-loop doesn't keep trying it."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    missing = tmp_path / "gone.sys"
    manifest.write_text(json.dumps({
        "version": IDA_MANIFEST_VERSION,
        "sessions": {
            "ghost": {
                "input_path": str(missing),
                "idb_target": f"{missing}.i64",
                "last_opened_iso": "2026-09-15T00:00:00Z",
                "run_auto_analysis": True,
            },
        },
    }), encoding="utf-8")
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    bridge = IdaBridge(cfg, tmp_path / "artifacts")
    try:
        # ensure_started reads the manifest.
        await bridge.ensure_started()
        assert "ghost" in bridge._manifest_sessions
        ok = await bridge._maybe_lazy_reopen("ghost")
        assert ok is False
        assert "ghost" not in bridge._manifest_sessions
        # Persistent drop: the tmp manifest no longer contains ghost.
        content = json.loads(manifest.read_text(encoding="utf-8"))
        assert "ghost" not in content["sessions"]
    finally:
        await bridge.stop()


async def test_c1_4_lazy_open_skipped_when_session_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A name that's already in ``_sessions`` shouldn't trigger a
    lazy re-open, no matter what the manifest says."""
    manifest = tmp_path / "ida_sessions.json"
    monkeypatch.setenv("SUSPX_IDA_MANIFEST", str(manifest))
    binary = tmp_path / "hot.sys"
    binary.write_bytes(b"MZ")
    fake = tmp_path / "fake_idalib_mcp.py"
    fake.write_text(FAKE_SERVER, encoding="utf-8")
    cfg = IdaConfigLite(command=[sys.executable, str(fake)])
    bridge = IdaBridge(cfg, tmp_path / "artifacts")
    try:
        # Open once — live session records.
        await bridge.ida_manage(
            "open", "hot", {"path": str(binary)})
        assert "hot" in bridge.sessions
        # `_manifest_sessions` doesn't retain names that are already
        # live: the manifest-drop-on-open logic keeps the two sets
        # disjoint.
        assert "hot" not in bridge._manifest_sessions
        # Session-scoped call still routes to the live session.
        out = await bridge.ida_manage(
            "decompile", "hot", {"address": "0x1400"})
        assert "sid_hot" in out
    finally:
        await bridge.stop()
