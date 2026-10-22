"""v0.21 dev-feedback regression tests.

Covers the bug batch reported from a live session:

* ``mem_rw scan_start`` refused ``address=0x0`` (truthiness check on a
  value that legitimately can be 0).
* ``mem_rw exports``/``imports`` ignored ``filter`` and bypassed the
  paging envelope entirely (3390-row spills on ntoskrnl).
* ``file_manage grep_artifact`` rejected a bare spill sha256 when
  ``SUSPX_MCP_SPILL_DIR`` points outside ``artifacts_dir``.
* ``bin_manage path='artifacts\\x.bin'`` double-prefixed the artifacts
  dir; absolute paths had no clean ingest path (file_manage ingest).
* ``bin_manage source='memory' action='exports'`` read the whole module
  image and tripped ``max_mem_read_mb`` — now headers+.edata only.
* ``value_manage eval`` left ``env_json`` string values as str — numeric
  strings now coerce.
* ``exec_manage run_script`` ran PowerShell bodies as .cmd when ``shell``
  was left default; ``script_b64`` corrupted long payloads via
  ``-EncodedCommand`` — now decoded server-side into run_script.
* ``ida_manage open_async`` died on ``uv run idalib-mcp`` when the
  repo-local .ida-mcp-venv shim was sitting right there.
* ``sections='.text'`` scopes pattern_scan/scan_start to named PE
  sections of a live module.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from pathlib import Path

import pytest

from _multi_fakes import _RichFakeAgentClient, _build_ctx_and_server, _call_as
from _pefixture import build_pe, IMAGE_BASE, TEXT_RVA, SEC_RAW

from suspex.mcp.value_eval import EvalError, evaluate
from suspex.mcp.tools.exec_ import _sniff_script_shell
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.ida_bridge.lifecycle import IdaLifecycleMixin


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_MOD_BASE = 0x140000000
_FILE_PE = build_pe(exports={"MmMapIoSpaceEx": TEXT_RVA,
                             "IoCreateDevice": TEXT_RVA + 8},
                    code=b"\x48\x8b\x05\xAA\xBB\xCC\xDD" + b"\x90" * 32)


def _image_layout(file_img: bytes) -> bytes:
    """Re-lay a file-layout fixture into memory image layout (rva==off),
    which is what a live module read returns."""
    img = bytearray(0x4000)  # fixture SizeOfImage
    img[:0x200] = file_img[:0x200]                     # headers
    for rva, raw in SEC_RAW.items():
        img[rva:rva + 0x200] = file_img[raw:raw + 0x200]
    return bytes(img)


_IMG = _image_layout(_FILE_PE)


class _PeMemFake(_RichFakeAgentClient):
    """Serves ``_IMG`` bytes out of a fake module mapped at _MOD_BASE."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.read_calls: list[tuple[int, int]] = []

    async def mem_modules(self, pid, kernel=False, *a, **kw):
        return [{"name": "fix.sys", "base": _MOD_BASE, "size": len(_IMG),
                 "path": "\\SystemRoot\\fix.sys"}]

    async def mem_read(self, pid, addr, size, space="user", **kw):
        self.read_calls.append((int(addr), int(size)))
        off = int(addr) - _MOD_BASE
        if off < 0 or off >= len(_IMG):
            raise RuntimeError("read out of range")
        return _IMG[off: off + int(size)]

    async def mem_read_stream(self, pid, address, size, space="user",
                              allow_fault=False, timeout=None):
        off = int(address) - _MOD_BASE
        if off < 0 or off >= len(_IMG):
            raise RuntimeError("read out of range")
        pos = 0
        while pos < int(size):
            chunk = _IMG[off + pos: off + pos + 0x400]
            if not chunk:
                break
            yield pos, chunk
            pos += len(chunk)

    async def mem_exports(self, pid, module, kernel=False, *a, **kw):
        return [
            {"name": "MmMapIoSpaceEx", "ordinal": 1, "rva": TEXT_RVA,
             "address": _MOD_BASE + TEXT_RVA, "forwarder": ""},
            {"name": "IoCreateDevice", "ordinal": 2, "rva": TEXT_RVA + 8,
             "address": _MOD_BASE + TEXT_RVA + 8, "forwarder": ""},
        ] * 500  # 1000 rows — enough to prove server-side filtering


# ---------------------------------------------------------------------------
# scan_start: address=0x0 must be accepted
# ---------------------------------------------------------------------------

async def test_scan_start_accepts_zero_base(tmp_path, monkeypatch):
    class _Zeros(_RichFakeAgentClient):
        async def mem_read(self, pid, addr, size, space="user", **kw):
            return b"\x00" * int(size)

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _Zeros)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_start", "pid": 1234, "base": "0x0",
        "size": 0x4000, "pattern": "48 8B",
    })
    assert out["ok"] is True, out
    scan_id = out["scan_id"]
    for _ in range(100):
        st = await _call_as("peer-A", server, "mem_rw", {
            "action": "scan_status", "scan_id": scan_id})
        if st["status"] != "running":
            break
        await asyncio.sleep(0.02)
    assert st["status"] == "done"


async def test_scan_start_zero_size_still_refused(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_start", "pid": 1234, "base": "0x1000",
        "size": 0, "pattern": "48 8B",
    })
    assert out["ok"] is False
    assert "size" in (out.get("error") or "").lower()


# ---------------------------------------------------------------------------
# mem_rw exports: filter + paging envelope
# ---------------------------------------------------------------------------

async def test_exports_filter_applies(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "exports", "module": "fix.sys",
        "filter": "MmMapIoSpaceEx",
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    # Default page is 64; every row must be the matching export — an
    # unfiltered page would interleave the two fake names.
    assert len(items) == 64
    assert all("MmMapIoSpaceEx" in str(i) for i in items)


async def test_exports_unfiltered_uses_items_envelope(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "exports", "module": "fix.sys", "limit": 10,
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    assert len(items) == 10


# ---------------------------------------------------------------------------
# section-scoped pattern_scan
# ---------------------------------------------------------------------------

async def test_pattern_scan_sections_scopes_range(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "pattern_scan", "pid": 1234,
        "module": "fix.sys", "sections": ".text",
        "pattern": "48 8B 05 ?? ?? ?? ??",
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    assert items, out  # the pattern sits at .text start in the fixture
    assert items[0] == hex(_MOD_BASE + TEXT_RVA)
    assert out.get("sections") == [".text"]
    spans = out.get("spans") or []
    assert spans and spans[0]["va"] == hex(_MOD_BASE + TEXT_RVA)


async def test_pattern_scan_sections_bad_name_errors(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "pattern_scan", "pid": 1234,
        "module": "fix.sys", "sections": ".nosuch",
        "pattern": "48 8B",
    })
    assert out["ok"] is False
    assert out["kind"] == "no_sections"


async def test_scan_start_sections(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_start", "pid": 1234,
        "module": "fix.sys", "sections": ".text",
        "pattern": "48 8B 05 ?? ?? ?? ??",
    })
    assert out["ok"] is True, out
    for _ in range(100):
        st = await _call_as("peer-A", server, "mem_rw", {
            "action": "scan_status", "scan_id": out["scan_id"]})
        if st["status"] != "running":
            break
        await asyncio.sleep(0.02)
    assert st["status"] == "done"
    res = await _call_as("peer-A", server, "mem_rw", {
        "action": "scan_result", "scan_id": out["scan_id"]})
    items = res.get("items") or []
    assert hex(_MOD_BASE + TEXT_RVA) in items


# ---------------------------------------------------------------------------
# grep_artifact: spill dir outside artifacts_dir
# ---------------------------------------------------------------------------

async def test_grep_artifact_spill_outside_artifacts(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # Spill dir deliberately OUTSIDE artifacts_dir — the original bug.
    spill = tmp_path / "spill_elsewhere"
    spill.mkdir()
    monkeypatch.setenv("SUSPX_MCP_SPILL_DIR", str(spill))
    payload = b"alpha\nbeta MmMapIoSpaceEx gamma\nomega\n"
    sha = hashlib.sha256(payload).hexdigest()
    (spill / f"{sha}.txt").write_bytes(payload)

    out = await _call_as("peer-A", server, "file_manage", {
        "action": "grep_artifact", "sha256": sha, "pattern": "MmMapIoSpaceEx",
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    assert items and "MmMapIoSpaceEx" in items[0]["match"]


# ---------------------------------------------------------------------------
# bin_manage: path normalization + ingest + sparse exports
# ---------------------------------------------------------------------------

async def test_bin_manage_path_artifacts_prefix(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    art = Path(ctx.cfg.artifacts_dir())
    (art / "dumps").mkdir(parents=True, exist_ok=True)
    (art / "dumps" / "fix.sys").write_bytes(_FILE_PE)

    # The reported bug: 'artifacts\\dumps\\fix.sys' resolved to
    # artifacts\\artifacts\\dumps\\fix.sys. Both spellings must work.
    for p in ("artifacts\\dumps\\fix.sys", "artifacts/dumps/fix.sys",
              "dumps\\fix.sys", "dumps/fix.sys"):
        out = await _call_as("peer-A", server, "bin_manage", {
            "action": "info", "path": p})
        assert out["ok"] is True, (p, out)


async def test_bin_manage_abs_path_outside_refused_with_ingest_hint(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(_FILE_PE)
    out = await _call_as("peer-A", server, "bin_manage", {
        "action": "info", "path": str(outside)})
    assert out["ok"] is False
    assert "ingest" in (out.get("hint") or "")


async def test_file_ingest_then_bin_manage(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    src = tmp_path / "elsewhere.sys"
    src.write_bytes(_FILE_PE)
    out = await _call_as("peer-A", server, "file_manage", {
        "action": "ingest", "local_path": str(src)})
    assert out["ok"] is True, out
    rel = out["path"]
    assert rel.replace("\\", "/").startswith("ingested/")
    assert out["sha256"] == hashlib.sha256(_FILE_PE).hexdigest()
    # …and the ingested path feeds bin_manage directly.
    info = await _call_as("peer-A", server, "bin_manage", {
        "action": "info", "path": rel})
    assert info["ok"] is True, info


async def test_bin_manage_memory_exports_sparse(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "bin_manage", {
        "action": "exports", "source": "memory", "module": "fix.sys",
        "kernel": True,
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    names = {i.get("name") for i in items}
    assert "MmMapIoSpaceEx" in names
    va = next(i["va"] for i in items if i["name"] == "MmMapIoSpaceEx")
    assert int(va, 16) == _MOD_BASE + TEXT_RVA
    # The sparse path must never have asked for the whole image.
    fake = next(iter(ctx.session.clients.values()))
    assert max(sz for _, sz in fake.read_calls) < len(_IMG)


async def test_bin_manage_memory_big_module_streams(tmp_path, monkeypatch):
    """A module bigger than max_mem_read_mb must not go through the unary
    read — it streams via mem_read_stream."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # Zero cap: every unary read would exceed it, forcing the streamer.
    ctx.cfg.security.max_mem_read_mb = 0
    monkeypatch.setattr("suspex.session.AgentClient", _PeMemFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "bin_manage", {
        "action": "sections", "source": "memory", "module": "fix.sys",
        "kernel": True,
    })
    assert out["ok"] is True, out
    items = out.get("items") or []
    assert {i["name"] for i in items} >= {".text", ".rdata", ".idata"}
    fake = next(iter(ctx.session.clients.values()))
    # Unary path must not have run — everything came via the streamer.
    assert not fake.read_calls


# ---------------------------------------------------------------------------
# value_manage eval: env string coercion
# ---------------------------------------------------------------------------

def test_eval_env_numeric_strings_coerced():
    r = evaluate("BASE + SIZE", env={"BASE": "0x1000", "SIZE": "0x40"})
    assert r["result"] == 0x1040


def test_eval_env_negative_hex_string():
    # signed=True interprets 0xFFFF800000000000 as -0x800000000000, so
    # A + B == -(0x800000000000 + 0x80000000).
    r = evaluate("A + B", env={"A": "0xFFFF800000000000",
                               "B": "-0x80000000"}, signed=True)
    assert r["result"] == -(0x800000000000 + 0x80000000)


def test_eval_env_nonnumeric_string_arith_is_bad_expr():
    with pytest.raises(EvalError) as exc:
        evaluate("X + 1", env={"X": "notanumber"})
    assert exc.value.kind == "bad_expr"


def test_eval_env_dict_value_rejected():
    with pytest.raises(EvalError) as exc:
        evaluate("X", env={"X": {"nested": 1}})
    assert exc.value.kind == "bad_expr"


# ---------------------------------------------------------------------------
# exec_manage: shell sniff + script_b64 decode path
# ---------------------------------------------------------------------------

def test_sniff_powershell_inline():
    assert _sniff_script_shell(
        "$x = Get-Process | Where-Object { $_.Id -eq 4 }\nWrite-Host $x",
        "") == "powershell"


def test_sniff_cmd_inline():
    assert _sniff_script_shell("@echo off\nsetlocal\nset X=1\ngoto end\n:end",
                               "") == "cmd"


def test_sniff_python_inline():
    assert _sniff_script_shell("import os\nprint(os.getcwd())\n",
                               "") == "python"


def test_sniff_by_extension():
    assert _sniff_script_shell("", "C:\\x\\run.ps1") == "powershell"
    assert _sniff_script_shell("", "C:\\x\\run.bat") == "cmd"
    assert _sniff_script_shell("", "C:\\x\\run.py") == "python"


def test_sniff_unknown_defaults_empty():
    # opaque text -> "" so the caller falls back to cmd
    assert _sniff_script_shell("echo hello\n", "") == ""


async def test_run_script_autodetects_powershell(tmp_path, monkeypatch):
    """PowerShell body + no shell= must spawn powershell.exe -File .ps1,
    not cmd.exe /c .cmd (the reported bug)."""
    calls: list[tuple] = []

    class _ExecFake(_RichFakeAgentClient):
        async def file_upload(self, local, remote):
            calls.append(("upload", remote))
            return {"ok": True}

        async def run_exe(self, exe, args_list, workdir, timeout_ms):
            calls.append(("run_exe", exe, tuple(args_list)))
            return {"ok": True, "exit_code": 0, "stdout": "hi"}

        async def file_delete(self, path, no_trash=False):
            calls.append(("delete", path))
            return {"ok": True}

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _ExecFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    out = await _call_as("peer-A", server, "exec_manage", {
        "action": "run_script",
        "script": "$p = Get-Process -Name svchost\nWrite-Host $p.Count",
    })
    assert out["ok"] is True, out
    assert out["shell"] == "powershell"
    exe_call = next(c for c in calls if c[0] == "run_exe")
    assert exe_call[1] == "powershell.exe"
    remote = next(c[1] for c in calls if c[0] == "upload")
    assert remote.endswith(".ps1")


async def test_script_b64_routes_through_run_script(tmp_path, monkeypatch):
    """script_b64 is decoded server-side and run via -File, not
    -EncodedCommand (which corrupted long payloads)."""
    calls: list[tuple] = []
    uploaded: dict[str, str] = {}

    class _ExecFake(_RichFakeAgentClient):
        async def file_upload(self, local, remote):
            uploaded["remote"] = remote
            uploaded["text"] = Path(local).read_text(encoding="utf-8")
            return {"ok": True}

        async def run_exe(self, exe, args_list, workdir, timeout_ms):
            calls.append((exe, tuple(args_list)))
            return {"ok": True, "exit_code": 0}

        async def file_delete(self, path, no_trash=False):
            return {"ok": True}

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", _ExecFake)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})

    ps = "Write-Host 'hello from b64'\n$y = 1 + 2\n"
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    out = await _call_as("peer-A", server, "exec_manage", {
        "action": "run_powershell", "script_b64": b64,
    })
    assert out["ok"] is True, out
    exe, args = calls[0]
    assert exe == "powershell.exe"
    assert "-EncodedCommand" not in args
    assert "-File" in args
    assert uploaded["text"] == ps


async def test_script_b64_garbage_is_named_error(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    out = await _call_as("peer-A", server, "exec_manage", {
        "action": "run_powershell",
        "script_b64": "!!!not-base64!!!",
    })
    assert out["ok"] is False
    assert out["kind"] == "bad_script_b64"


# ---------------------------------------------------------------------------
# ida_bridge: uv -> repo shim substitution
# ---------------------------------------------------------------------------

def _fake_venv(tmp_path: Path) -> Path:
    import sys as _sys
    venv = tmp_path / "fake-venv"
    scripts = venv / ("Scripts" if _sys.platform == "win32" else "bin")
    scripts.mkdir(parents=True)
    (scripts / ("python.exe" if _sys.platform == "win32" else "python")) \
        .write_bytes(b"fake")
    return venv


def test_precheck_substitutes_repo_shim_for_uv(tmp_path, monkeypatch):
    """`uv run idalib-mcp` on a bare checkout swaps to the repo's
    .ida-mcp-venv python + idalib_stdio_shim.py when present."""
    venv = _fake_venv(tmp_path)
    monkeypatch.setenv("SUSPX_IDA_VENV", str(venv))
    # Deterministic: pretend `uv` resolves on PATH.
    monkeypatch.setattr(IdaLifecycleMixin, "_resolve_exe",
                        staticmethod(lambda exe: exe))

    cfg = IdaConfigLite(command=["uv", "run", "idalib-mcp", "--stdio"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    b.precheck()
    assert Path(cfg.command[0]).name.lower() in ("python.exe", "python")
    assert cfg.command[1].endswith("idalib_stdio_shim.py")


def test_precheck_keeps_uv_when_project_flags_present(tmp_path, monkeypatch):
    """`uv run --project X idalib-mcp` is a deliberate config — leave it."""
    venv = _fake_venv(tmp_path)
    monkeypatch.setenv("SUSPX_IDA_VENV", str(venv))
    monkeypatch.setattr(IdaLifecycleMixin, "_resolve_exe",
                        staticmethod(lambda exe: exe))

    cfg = IdaConfigLite(command=["uv", "run", "--project", "C:/ida-pro-mcp",
                                 "idalib-mcp", "--stdio"])
    b = IdaBridge(cfg, tmp_path / "artifacts")
    b.precheck()
    assert "uv" in Path(cfg.command[0]).name.lower()
