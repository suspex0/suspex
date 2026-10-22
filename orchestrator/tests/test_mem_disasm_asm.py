"""Unit tests for the Phase 1 codegen surface: capstone / keystone wrappers
+ the `mem_rw disasm/assemble` dispatch helpers.

Pure-compute; no live target, no gRPC. When the codegen extra is not
installed the whole module skips.
"""
from __future__ import annotations

import json

import pytest

from suspex import codegen as cg
from suspex.mcp import tools as mtools


pytestmark = pytest.mark.skipif(
    not (cg.capstone_available() and cg.keystone_available()),
    reason="codegen extra not installed (pip install suspex0[codegen])",
)


# ---------------------------------------------------------------------------
# codegen module — direct
# ---------------------------------------------------------------------------


class TestDisasmDirect:
    def test_ret_only(self) -> None:
        rows = cg.disasm(b"\xc3", "x64")
        assert len(rows) == 1
        assert rows[0]["mnemonic"] == "ret"
        assert rows[0]["size"] == 1

    def test_mov_rbp_rsp_ret(self) -> None:
        rows = cg.disasm(bytes.fromhex("4889e5c3"), "x64", address=0x1000)
        assert [r["mnemonic"] for r in rows] == ["mov", "ret"]
        assert rows[0]["addr"] == 0x1000
        assert rows[0]["op_str"] == "rbp, rsp"
        assert rows[1]["addr"] == 0x1003

    def test_x86_mode(self) -> None:
        # push ebp; mov ebp, esp; ret
        rows = cg.disasm(bytes.fromhex("5589e5c3"), "x86")
        assert [r["mnemonic"] for r in rows] == ["push", "mov", "ret"]

    def test_count_cap(self) -> None:
        # 8x nop
        rows = cg.disasm(b"\x90" * 8, "x64", count=3)
        assert len(rows) == 3

    def test_bad_arch_raises(self) -> None:
        with pytest.raises(Exception) as exc:
            cg.disasm(b"\x90", "arm64")
        assert getattr(exc.value, "kind", None) == "bad_arg"

    def test_att_syntax(self) -> None:
        # mov rbp, rsp — Intel: "mov rbp, rsp", AT&T: "movq %rsp, %rbp"
        rows_intel = cg.disasm(b"\x48\x89\xe5", "x64", syntax="intel")
        rows_att = cg.disasm(b"\x48\x89\xe5", "x64", syntax="att")
        assert "rbp" in rows_intel[0]["op_str"]
        assert "%" in rows_att[0]["op_str"]

    def test_detail_populates_regs(self) -> None:
        # mov rax, rbx — reads rbx, writes rax
        rows = cg.disasm(bytes.fromhex("4889d8"), "x64", detail=True)
        r = rows[0]
        assert "regs_read" in r
        assert "regs_write" in r


class TestAssembleDirect:
    def test_ret(self) -> None:
        encoded, count, labels = cg.assemble("ret", "x64")
        assert encoded == b"\xc3"
        assert count == 1
        assert labels == {}

    def test_mov_syscall_x64(self) -> None:
        encoded, count, _ = cg.assemble("mov rax, 1; syscall", "x64")
        # mov rax, 1 -> 48 c7 c0 01 00 00 00  (7 bytes)
        # syscall    -> 0f 05                  (2 bytes)
        assert encoded == bytes.fromhex("48c7c0010000000f05")
        assert count == 2

    def test_x86_ret(self) -> None:
        encoded, count, _ = cg.assemble("ret", "x86")
        assert encoded == b"\xc3"

    def test_label_map_no_forward_ref(self) -> None:
        src = "start:\nmov rax, 1\nend:\nret"
        encoded, count, labels = cg.assemble(src, "x64", address=0x1000)
        assert labels["start"] == 0x1000
        # `mov rax, 1` -> 7 bytes
        assert labels["end"] == 0x1000 + 7
        # keystone counts labels as statements too; two real instructions
        # produce at least 2, more if labels are counted.
        assert count >= 2

    def test_forward_ref_labels_empty_bytes_ok(self) -> None:
        # jmp forward — one-shot keystone handles the ref; the label
        # walk will fail on the forward ref, so `labels` comes back empty
        # while `bytes` still contain the correct encoding.
        src = "jmp end\nnop\nend:\nret"
        encoded, count, labels = cg.assemble(src, "x64", address=0x1000)
        assert encoded  # bytes are not empty
        assert count >= 3
        # labels may be empty (forward ref) — that's OK per the contract.
        assert isinstance(labels, dict)

    def test_bad_asm_raises_named(self) -> None:
        with pytest.raises(cg.AssembleError) as exc:
            cg.assemble("this is not asm", "x64")
        assert exc.value.kind == "assemble_error"

    def test_round_trip(self) -> None:
        # Assemble, then disassemble, and confirm identity.
        code = "mov rax, 0x1234; add rax, rbx; ret"
        encoded, _, _ = cg.assemble(code, "x64", address=0)
        rows = cg.disasm(encoded, "x64")
        assert rows[0]["mnemonic"] == "mov"
        assert rows[1]["mnemonic"] == "add"
        assert rows[2]["mnemonic"] == "ret"


# ---------------------------------------------------------------------------
# mem_rw dispatch helpers — pure-compute paths only
# ---------------------------------------------------------------------------


class _StubSession:
    """Minimal stub for Session — only what _mem_disasm/_mem_assemble reach."""

    class _Client:
        async def mem_read(self, *a, **k):  # pragma: no cover - unused
            raise RuntimeError("stub: mem_read not expected in pure-compute test")

        async def mem_write(self, *a, **k):  # pragma: no cover - unused
            raise RuntimeError("stub: mem_write not expected in pure-compute test")

        async def mem_modules(self, pid, kernel):  # pragma: no cover
            return []

    def __init__(self, *, connected: bool = False) -> None:
        self._connected = connected
        self.calls: list[dict] = []

    def require_client(self, name: str = ""):
        if not self._connected:
            raise RuntimeError("no target connected")
        return self._Client()

    def record_tool_call(self, tool, action, *, args=None, ok=True, error="") -> None:
        self.calls.append({"tool": tool, "action": action, "ok": ok, "error": error})

    def assert_allowed(self, *_a, **_k) -> None:
        pass


class _StubCtx:
    def __init__(self, *, connected: bool = False) -> None:
        self.session = _StubSession(connected=connected)


@pytest.mark.asyncio
class TestMemDisasmDispatch:
    async def test_bytes_hex_pure_compute(self) -> None:
        out = await mtools._mem_disasm(
            _StubCtx(connected=False),
            name="kernel", pid=0, space="user",
            address=0, bytes_hex="4889e5c3",
            arch="x64", syntax="intel", count=64, size=0,
            detail=False, resolve_symbols=False,
            allow_fault=False, timeout_s=0,
        )
        j = json.loads(out)
        assert j["ok"] is True
        assert j["source"] == "buffer"
        assert [i["mnemonic"] for i in j["instructions"]] == ["mov", "ret"]
        assert j["bytes_used"] == 4

    async def test_bytes_hex_with_spaces(self) -> None:
        out = await mtools._mem_disasm(
            _StubCtx(connected=False),
            name="kernel", pid=0, space="user",
            address=0, bytes_hex="48 89 e5 c3",
            arch="x64", syntax="intel", count=64, size=0,
            detail=False, resolve_symbols=False,
            allow_fault=False, timeout_s=0,
        )
        j = json.loads(out)
        assert j["ok"] is True
        assert len(j["instructions"]) == 2

    async def test_bad_hex(self) -> None:
        out = await mtools._mem_disasm(
            _StubCtx(),
            name="kernel", pid=0, space="user",
            address=0, bytes_hex="not-hex",
            arch="x64", syntax="intel", count=64, size=0,
            detail=False, resolve_symbols=False,
            allow_fault=False, timeout_s=0,
        )
        j = json.loads(out)
        assert j["ok"] is False
        assert j["kind"] == "bad_arg"

    async def test_no_source_error(self) -> None:
        out = await mtools._mem_disasm(
            _StubCtx(),
            name="kernel", pid=0, space="user",
            address=0, bytes_hex="",
            arch="x64", syntax="intel", count=64, size=0,
            detail=False, resolve_symbols=False,
            allow_fault=False, timeout_s=0,
        )
        j = json.loads(out)
        assert j["ok"] is False
        assert j["kind"] == "bad_arg"

    async def test_annotate_symbols_finds_module(self) -> None:
        # jmp 0x00007ff600001234 → 0xE9 with 4-byte rel disp, but simpler:
        # just call cg.disasm then hand-check _annotate_symbols directly.
        rows = cg.disasm(bytes.fromhex("48b820000000f67f0000"), "x64",
                         address=0x140001000)  # mov rax, 0x7ff600000020
        mods = [{"name": "notepad.exe",
                 "base": "0x7ff600000000",
                 "size": "0x100000"}]
        mtools._annotate_symbols(rows, mods)
        assert rows[0]["sym"] == "notepad.exe+0x20"


@pytest.mark.asyncio
class TestMemAssembleDispatch:
    async def test_dry_run_default(self) -> None:
        out = await mtools._mem_assemble(
            _StubCtx(connected=False),
            name="kernel", pid=0, space="user",
            code="mov rax, 1; ret", arch="x64",
            address=0, write_to=0, dry_run=True,
            allow_map_write=False,
        )
        j = json.loads(out)
        assert j["ok"] is True
        assert j["dry_run"] is True
        # _j_hex renders sizes as '0x…' strings and adds a `_int` mirror.
        # 7 (mov rax,1) + 1 (ret) = 8
        assert j["size"] == "0x8"
        assert j["size_int"] == 8
        assert j["ins_count"] == 2
        assert "roundtrip" in j
        assert j["roundtrip"][0]["mnemonic"] == "mov"
        assert j["roundtrip"][1]["mnemonic"] == "ret"

    async def test_labels_returned(self) -> None:
        out = await mtools._mem_assemble(
            _StubCtx(connected=False),
            name="kernel", pid=0, space="user",
            code="entry:\nmov rax, 1\ntail:\nret", arch="x64",
            address=0x1000, write_to=0, dry_run=True,
            allow_map_write=False,
        )
        j = json.loads(out)
        assert j["ok"] is True
        assert j["labels"]["entry"] == "0x1000"
        # mov rax,1 is 7 bytes
        assert j["labels"]["tail"] == "0x1007"

    async def test_bad_asm_error_named(self) -> None:
        out = await mtools._mem_assemble(
            _StubCtx(),
            name="kernel", pid=0, space="user",
            code="this is not asm", arch="x64",
            address=0, write_to=0, dry_run=True,
            allow_map_write=False,
        )
        j = json.loads(out)
        assert j["ok"] is False
        assert j["kind"] == "assemble_error"

    async def test_unsafe_default_write_refused(self) -> None:
        # write_to set + dry_run=True (default) → must refuse.
        out = await mtools._mem_assemble(
            _StubCtx(connected=True),
            name="kernel", pid=1234, space="user",
            code="ret", arch="x64",
            address=0, write_to="0x140001000", dry_run=True,
            allow_map_write=False,
        )
        j = json.loads(out)
        assert j["ok"] is False
        assert j["kind"] == "unsafe_default"

    async def test_empty_code_error(self) -> None:
        out = await mtools._mem_assemble(
            _StubCtx(),
            name="kernel", pid=0, space="user",
            code="", arch="x64",
            address=0, write_to=0, dry_run=True,
            allow_map_write=False,
        )
        j = json.loads(out)
        assert j["ok"] is False
        assert j["kind"] == "bad_arg"
