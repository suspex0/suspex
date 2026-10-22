"""v0.27: canonical artifact-root + shared path/sha resolution.

Regression tests for the two-store drift: a dump written under
``<repo>/artifacts`` was invisible to consumers resolving
``artifacts.dir`` against the process cwd (``orchestrator/artifacts``).
One anchored ``artifacts_dir`` now feeds every producer/consumer, and
all four input spellings — ``dumps/x.sys``, ``artifacts/dumps/x.sys``,
the ``abs_path`` list_artifacts emits, and ``sha256`` — resolve through
the same helpers.
"""
from __future__ import annotations

import asyncio
import hashlib

import pytest

import _pefixture as fx
from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig, _project_root
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp._artifacts import (artifact_roots, find_artifact_by_sha,
                                   resolve_artifact_path)
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


# --- config anchoring ----------------------------------------------------


def test_artifacts_dir_relative_anchors_at_repo_root():
    cfg = SuspexConfig()
    cfg.artifacts.dir = "artifacts"
    assert cfg.artifacts_dir() == _project_root() / "artifacts"
    # the rest of the configured dirs anchor the same way
    assert cfg.pdb_cache_dir() == _project_root() / "artifacts" / "symbols"
    assert cfg.reports_dir() == _project_root() / "reports"


def test_artifacts_dir_absolute_passthrough(tmp_path):
    cfg = SuspexConfig()
    cfg.artifacts.dir = str(tmp_path / "store")
    assert cfg.artifacts_dir() == tmp_path / "store"


def test_artifacts_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_ARTIFACTS_DIR", str(tmp_path / "envstore"))
    cfg = SuspexConfig()
    cfg.artifacts.dir = "artifacts"
    assert cfg.artifacts_dir() == tmp_path / "envstore"
    # spill still derives from the same root
    assert cfg.spill_dir() == tmp_path / "envstore" / "spill"


# --- resolve_artifact_path ------------------------------------------------


def _cfg(tmp_path) -> SuspexConfig:
    cfg = SuspexConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    return cfg


def test_resolve_relative_subdir(tmp_path):
    cfg = _cfg(tmp_path)
    p = resolve_artifact_path(cfg, "dumps/x.sys")
    assert p == (tmp_path / "artifacts" / "dumps" / "x.sys").resolve()


def test_resolve_store_prefixed(tmp_path):
    """'artifacts/dumps/x.sys' strips the leading store-name component
    instead of double-prefixing to artifacts/artifacts/..."""
    cfg = _cfg(tmp_path)
    p = resolve_artifact_path(cfg, "artifacts/dumps/x.sys")
    assert p == (tmp_path / "artifacts" / "dumps" / "x.sys").resolve()


def test_resolve_absolute_under_root(tmp_path):
    cfg = _cfg(tmp_path)
    abs_p = tmp_path / "artifacts" / "dumps" / "x.sys"
    p = resolve_artifact_path(cfg, str(abs_p))
    assert p == abs_p.resolve()


def test_resolve_absolute_outside_root_refused(tmp_path):
    cfg = _cfg(tmp_path)
    outside = tmp_path / "elsewhere" / "x.sys"
    assert resolve_artifact_path(cfg, str(outside)) is None


def test_resolve_escape_refused(tmp_path):
    cfg = _cfg(tmp_path)
    assert resolve_artifact_path(cfg, "..\\..\\evil.sys") is None
    assert resolve_artifact_path(cfg, "../../evil.sys") is None


def test_resolve_missing_but_contained_returns_path(tmp_path):
    """Contained-but-absent resolves — callers turn it into not_found,
    not bad_arg."""
    cfg = _cfg(tmp_path)
    p = resolve_artifact_path(cfg, "dumps/gone.sys")
    assert p == (tmp_path / "artifacts" / "dumps" / "gone.sys").resolve()


def test_resolve_external_spill_dir(tmp_path, monkeypatch):
    """SUSPX_MCP_SPILL_DIR can point outside artifacts/; spill paths must
    still resolve (bare relative + 'spill/'-prefixed + absolute)."""
    ext = tmp_path / "extspill"
    ext.mkdir()
    monkeypatch.setenv("SUSPX_MCP_SPILL_DIR", str(ext))
    cfg = _cfg(tmp_path)
    assert cfg.spill_dir() == ext
    assert artifact_roots(cfg) == [
        (tmp_path / "artifacts").resolve(), ext.resolve()]
    assert resolve_artifact_path(cfg, "abc.bin") \
        == (tmp_path / "artifacts" / "abc.bin").resolve()
    # 'spill/<sha>.bin' routes to the external spill root, not artifacts/
    assert resolve_artifact_path(cfg, "spill/deadbeef.bin") \
        == (ext / "deadbeef.bin").resolve()
    assert resolve_artifact_path(cfg, str(ext / "deadbeef.bin")) \
        == (ext / "deadbeef.bin").resolve()


# --- find_artifact_by_sha -------------------------------------------------


def test_find_by_sha_covers_dumps_ingested_spill(tmp_path):
    cfg = _cfg(tmp_path)
    art = tmp_path / "artifacts"
    dumps = art / "dumps"
    ing = art / "ingested"
    spill = cfg.spill_dir()
    for d in (dumps, ing, spill):
        d.mkdir(parents=True, exist_ok=True)
    a, b, c = b"dump-bytes-A", b"ingest-bytes-B", b"spill-bytes-C"
    (dumps / "mod.sys").write_bytes(a)
    (ing / "x.bin").write_bytes(b)
    sha_c = hashlib.sha256(c).hexdigest()
    (spill / f"{sha_c}.bin").write_bytes(c)

    hit_a = find_artifact_by_sha(cfg, hashlib.sha256(a).hexdigest())
    assert hit_a is not None and hit_a[0].endswith("mod.sys")
    hit_b = find_artifact_by_sha(cfg, hashlib.sha256(b).hexdigest())
    assert hit_b is not None and hit_b[0].endswith("x.bin")
    hit_c = find_artifact_by_sha(cfg, sha_c)
    assert hit_c is not None and hit_c[1] == sha_c
    # prefix lookup hits too
    assert find_artifact_by_sha(cfg, sha_c[:16])[1] == sha_c
    assert find_artifact_by_sha(cfg, "0" * 64) is None


# --- bin_manage end-to-end ------------------------------------------------


async def _ctx(tmp_path):
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    art_dir = tmp_path / "artifacts"
    (art_dir / "spill").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(art_dir / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), art_dir)
    clients_reg = ClientRegistry()
    ctx = Context(
        cfg=cfg, session=session, ledger=ledger, bridge=bridge,
        clients=clients_reg,
        leases=LeaseManager(publish_event=lambda ev: asyncio.create_task(
            clients_reg.publish(ev))),
        ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-test")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        import json as _json
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return {"raw": body}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    err = body.get("error")
    if isinstance(err, dict):
        merged.update(err)
    merged.setdefault("ok", body.get("ok"))
    if isinstance(body.get("summary"), dict):
        merged.setdefault("summary", body["summary"])
    return merged


def _seed_dump(tmp_path) -> tuple[str, bytes]:
    data = fx.build_pe(imports={"KERNEL32.dll": ["CreateFileW"]})
    p = tmp_path / "artifacts" / "dumps" / "mod.sys"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return str(p), data


async def test_bin_manage_all_path_spellings(tmp_path):
    """The core repro: dump lands under <root>/dumps/, and every spelling
    dump_module / list_artifacts can emit reaches the same file."""
    ctx, server = await _ctx(tmp_path)
    abs_p, _data = _seed_dump(tmp_path)
    for path in ("dumps/mod.sys",
                 "artifacts/dumps/mod.sys",
                 abs_p):
        body = await _call(server, "bin_manage",
                           {"action": "info", "path": path})
        assert body["ok"] is True, (path, body)
        assert body["arch"] == "x64"


async def test_bin_manage_sha256_finds_dumped_artifact(tmp_path):
    """sha256= used to search spill/ only — a dump_module payload was
    'no spilled artifact' even though list_artifacts prints its sha."""
    ctx, server = await _ctx(tmp_path)
    _abs_p, data = _seed_dump(tmp_path)
    sha = hashlib.sha256(data).hexdigest()
    body = await _call(server, "bin_manage",
                       {"action": "info", "sha256": sha})
    assert body["ok"] is True, body
    assert body["arch"] == "x64"


async def test_bin_manage_sha256_finds_ingested(tmp_path):
    ctx, server = await _ctx(tmp_path)
    data = fx.build_pe()
    ing = tmp_path / "artifacts" / "ingested" / "drv.bin"
    ing.parent.mkdir(parents=True, exist_ok=True)
    ing.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    body = await _call(server, "bin_manage",
                       {"action": "info", "sha256": sha})
    assert body["ok"] is True, body


async def test_bin_manage_sha256_miss_reports_artifact_missing(tmp_path):
    ctx, server = await _ctx(tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "info", "sha256": "ab" * 32})
    assert body["ok"] is False
    assert body["kind"] == "artifact_missing"


async def test_bin_manage_list_artifacts_path_round_trip(tmp_path):
    """The `path` field list_artifacts emits must feed bin_manage
    verbatim — that's the workflow the drift broke."""
    ctx, server = await _ctx(tmp_path)
    _seed_dump(tmp_path)
    listing = await _call(server, "file_manage",
                          {"action": "list_artifacts"})
    assert listing["ok"] is True, listing
    rows = [r for r in listing["items"] if r["path"].endswith("mod.sys")]
    assert rows, listing["items"]
    for field in ("path", "abs_path"):
        body = await _call(server, "bin_manage",
                           {"action": "info", "path": rows[0][field]})
        assert body["ok"] is True, (field, body)


async def test_read_orchestrator_sha_finds_dump(tmp_path):
    """file_manage(read, side='orchestrator', sha256=...) covers the
    whole store, not just spill/."""
    ctx, server = await _ctx(tmp_path)
    _abs_p, data = _seed_dump(tmp_path)
    sha = hashlib.sha256(data).hexdigest()
    body = await _call(server, "file_manage",
                       {"action": "read", "side": "orchestrator",
                        "sha256": sha, "length": 2})
    assert body["ok"] is True, body
    assert body["hex"] == data[:2].hex()


# --- ida bridge path resolution ------------------------------------------


def test_ida_resolve_binary_path_spellings(tmp_path):
    """ida_manage's resolver takes the same spellings: dumps/…,
    artifacts/dumps/… (no double-prefix), abs under root."""
    art = tmp_path / "artifacts"
    (art / "dumps").mkdir(parents=True)
    target = art / "dumps" / "x.sys"
    target.write_bytes(b"MZ")
    bridge = IdaBridge(IdaConfigLite(), art)
    for spelling in ("dumps/x.sys", "artifacts/dumps/x.sys",
                     str(target)):
        assert bridge._resolve_binary_path(spelling) == target, spelling


def test_ida_resolve_binary_path_missing_raises(tmp_path):
    from suspex.ida_bridge.errors import IdaBridgeError
    art = tmp_path / "artifacts"
    art.mkdir()
    bridge = IdaBridge(IdaConfigLite(), art)
    with pytest.raises(IdaBridgeError):
        bridge._resolve_binary_path("dumps/gone.sys")
