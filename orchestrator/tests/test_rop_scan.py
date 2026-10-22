"""Tests for the rp++-style gadget scanner (analysis/rop.py).

Fixtures are synthesized by tests/_pefixture.py — a minimal PE64 builder.
Scanner tests skip when capstone is absent (codegen extra).
"""
from __future__ import annotations

import pytest

import _pefixture as fx
from suspex.analysis import pe

pytest.importorskip("capstone")

from suspex.analysis import engine, rop  # noqa: E402

BASE = fx.IMAGE_BASE + fx.TEXT_RVA

# Hand-built code layout. Offsets are into .text; every entry is a real
# gadget the scanner must recover.
CODE = (
    b"\x58\xC3"                       # 0x00 pop rax; ret
    b"\x5F\x5E\xC3"                   # 0x02 pop rdi; pop rsi; ret
    b"\x48\x89\xC4\xC3"               # 0x05 mov rsp, rax; ret
    b"\xC9\xC3"                       # 0x09 leave; ret
    b"\x48\x83\xC4\x20\xC3"           # 0x0B add rsp, 0x20; ret
    b"\x90\x90\x90"                   # 0x10 pad
    b"\xC2\x18\x00"                   # 0x13 ret 0x18
    b"\xB8\xC3\x00\x00\x00"           # 0x16 mov eax, 0xC3 (ret @ +1)
    b"\x48\x8B\x43\x08\xC3"           # 0x1B mov rax, [rbx+8]; ret
    b"\xFF\xE0"                       # 0x20 jmp rax
    b"\xFF\xD0"                       # 0x22 call rax
    b"\xFF\x20"                       # 0x24 jmp [rax]
    b"\x0F\x05"                       # 0x26 syscall
    b"\x0F\x34"                       # 0x28 sysenter
    b"\xCD\x2E"                       # 0x2A int 0x2e
    b"\xEB\x02\xC3"                   # 0x2C jmp short; ret
    b"\xCC\x90\xC3"                   # 0x2F int3; nop; ret
    b"\x5B\xC3"                       # 0x32 pop rbx; ret
    b"\x5B\xC3"                       # 0x34 pop rbx; ret  (duplicate)
)
PAD = 0x200 - len(CODE)


def _view(code: bytes = CODE):
    data = fx.build_pe(code=code + b"\x90" * PAD)
    img = pe.parse(data, layout="file")
    return engine.ImageView(img)


def _index(code: bytes = CODE, **kw):
    return rop.build_index(_view(code), **kw)


def _by_va(index):
    return {g.va: g for g in index.gadgets}


def _row(index, va):
    rows = [r for r in rop.query(index) if r["va"] == va]
    assert rows, f"no gadget at {va:#x}"
    return rows[0]


# ----------------------------------------------------------------- scan ----

class TestScan:
    def test_pop_ret(self) -> None:
        g = _by_va(_index())[BASE + 0x00]
        assert g.text == "pop rax; ret"
        assert g.ending == "ret"
        assert "load" in g.categories
        assert g.raw == b"\x58\xC3"

    def test_multi_pop(self) -> None:
        g = _by_va(_index())[BASE + 0x02]
        assert g.text == "pop rdi; pop rsi; ret"
        assert g.stack_delta == 0x18

    def test_mov_rsp_pivot(self) -> None:
        g = _by_va(_index())[BASE + 0x05]
        assert g.text == "mov rsp, rax; ret"
        assert "stack_pivot" in g.categories
        assert g.stack_delta is None

    def test_leave_pivot(self) -> None:
        g = _by_va(_index())[BASE + 0x09]
        assert g.text == "leave; ret"
        assert "stack_pivot" in g.categories

    def test_add_rsp_adjust(self) -> None:
        g = _by_va(_index())[BASE + 0x0B]
        assert g.text == "add rsp, 0x20; ret"
        assert "stack_adjust" in g.categories
        assert g.stack_delta == 0x28  # 0x20 + ret's 8

    def test_ret_imm(self) -> None:
        g = _by_va(_index())[BASE + 0x13]
        assert g.ending == "ret_imm"
        assert g.ret_imm == 0x18
        assert g.stack_delta == 0x20

    def test_mid_instruction_ret(self) -> None:
        # The 0xC3 inside `mov eax, 0xC3` is a gadget at its own VA.
        g = _by_va(_index())[BASE + 0x17]
        assert g.text == "ret"
        assert "trivial" in g.categories

    def test_mem_load(self) -> None:
        g = _by_va(_index())[BASE + 0x1B]
        assert g.text == "mov rax, qword ptr [rbx + 8]; ret"
        assert "mem_load" in g.categories

    def test_dispatch_endings(self) -> None:
        ix = _by_va(_index())
        assert ix[BASE + 0x20].ending == "jmp_reg"
        assert ix[BASE + 0x22].ending == "call_reg"
        assert ix[BASE + 0x24].ending == "jmp_mem"

    def test_syscall_family(self) -> None:
        ix = _by_va(_index())
        assert ix[BASE + 0x26].ending == "syscall"
        assert ix[BASE + 0x28].ending == "sysenter"
        assert ix[BASE + 0x2A].ending == "int"

    def test_reject_jmp_before_terminator(self) -> None:
        # `EB 02` jumps over the C3 — no gadget may START at the EB.
        assert BASE + 0x2C not in _by_va(_index())

    def test_reject_int3_before_terminator(self) -> None:
        assert BASE + 0x2F not in _by_va(_index())
        # …but the nop; ret right after the int3 is fine.
        assert _by_va(_index())[BASE + 0x30].text == "nop; ret"

    def test_non_exec_not_scanned(self) -> None:
        data = fx.build_pe(code=CODE + b"\x90" * PAD,
                           strings=[(0, b"\x58\xC3\x58\xC3")])
        img = pe.parse(data, layout="file")
        idx = rop.build_index(engine.ImageView(img))
        lo = fx.IMAGE_BASE + fx.RDATA_RVA
        assert not [g for g in idx.gadgets if lo <= g.va < lo + 0x200]

    def test_blob_scan(self) -> None:
        view = engine.wrap_blob(b"\x58\xC3\x90\x5B\xC3", base_va=0x400000)
        idx = rop.build_index(view)
        vas = {g.va: g for g in idx.gadgets}
        assert vas[0x400000].text == "pop rax; ret"
        assert vas[0x400003].text == "pop rbx; ret"

    def test_budget_truncation(self) -> None:
        idx = _index(budget=2)
        assert idx.truncated

    def test_scan_telemetry(self) -> None:
        idx = _index()
        assert idx.bytes_scanned == 0x200
        assert idx.terminators > 0
        assert idx.decode_attempts > 0
        assert not idx.truncated


# ---------------------------------------------------------------- query ----

class TestQuery:
    def test_ending_filter_expands(self) -> None:
        idx = _index()
        rets = rop.query(idx, ending="ret")
        assert any(r["va"] == BASE + 0x00 for r in rets)
        assert any(r["va"] == BASE + 0x13 for r in rets)  # ret_imm
        assert not any(r["ending"].startswith("jmp") for r in rets)

    def test_ending_jmp_shorthand(self) -> None:
        rows = rop.query(_index(), ending="jmp")
        endings = {r["ending"] for r in rows}
        assert endings == {"jmp_reg", "jmp_mem"}

    def test_category_filter(self) -> None:
        rows = rop.query(_index(), category="stack_pivot")
        vas = {r["va"] for r in rows}
        assert BASE + 0x05 in vas and BASE + 0x09 in vas

    def test_reg_filter(self) -> None:
        rows = rop.query(_index(), reg="rdi")
        assert any(r["va"] == BASE + 0x02 for r in rows)

    def test_max_len(self) -> None:
        rows = rop.query(_index(), max_len=1)
        assert all(r["n_insns"] == 1 for r in rows)

    def test_bad_bytes_on_va(self) -> None:
        idx = _index()
        # gadget at .text+0x32 → VA 0x140001032 contains byte 0x32.
        all_rows = rop.query(idx, ending="ret", category="load")
        assert any(r["va"] == BASE + 0x32 for r in all_rows)
        filtered = rop.query(idx, ending="ret", category="load",
                             bad_bytes=frozenset({0x32}))
        assert not any(r["va"] == BASE + 0x32 for r in filtered)
        assert any(r["va"] == BASE + 0x00 for r in filtered)

    def test_unique_dedupes_with_aliases(self) -> None:
        idx = _index()
        plain = [r for r in rop.query(idx)
                 if r["text"] == "pop rbx; ret"]
        assert len(plain) >= 2
        uniq = [r for r in rop.query(idx, unique=True)
                if r["text"] == "pop rbx; ret"]
        assert len(uniq) == 1
        assert uniq[0]["aliases"] >= 2

    def test_rows_sorted_by_va(self) -> None:
        rows = rop.query(_index())
        vas = [r["va"] for r in rows]
        assert vas == sorted(vas)


# --------------------------------------------------------------- helpers ----

class TestHelpers:
    def test_parse_bad_bytes_forms(self) -> None:
        assert rop.parse_bad_bytes("00 0a") == frozenset({0x00, 0x0A})
        assert rop.parse_bad_bytes("00,0a") == frozenset({0x00, 0x0A})
        assert rop.parse_bad_bytes("000a") == frozenset({0x00, 0x0A})
        assert rop.parse_bad_bytes("") == frozenset()
        with pytest.raises(ValueError):
            rop.parse_bad_bytes("0g")
        with pytest.raises(ValueError):
            rop.parse_bad_bytes("000")

    def test_ending_selector(self) -> None:
        assert rop.ending_selector("") is None
        assert rop.ending_selector("all") is None
        assert rop.ending_selector("ret") == frozenset({"ret", "ret_imm"})
        assert rop.ending_selector("syscall") == frozenset({"syscall"})
        with pytest.raises(ValueError):
            rop.ending_selector("bogus")

    def test_scan_ranges_file_layout_clamped(self) -> None:
        view = _view()
        ranges = rop.scan_ranges(view)
        assert ranges == [(BASE, BASE + 0x200, ".text")]


# ------------------------------------------------------------- live base ----

class TestLiveBase:
    def _image_layout(self, code: bytes) -> pe.PeImage:
        """As-mapped buffer: sections at their RVAs, header untouched —
        the shape `source='memory'` produces (header keeps the linker's
        preferred base under KASLR)."""
        file_bytes = fx.build_pe(code=code)
        fimg = pe.parse(file_bytes, layout="file")
        buf = bytearray(max(fimg.size_of_image, len(file_bytes)))
        buf[:0x200] = file_bytes[:0x200]
        for s in fimg.sections:
            buf[s.va:s.va + s.raw_size] = \
                file_bytes[s.raw_off:s.raw_off + s.raw_size]
        return pe.parse(bytes(buf), layout="image")

    def test_base_override_rebases_view(self) -> None:
        img = self._image_layout(b"\x58\xC3" + b"\x90" * (0x200 - 2))
        live = 0xFFFFF801_23400000
        view = engine.ImageView(img, base_va=live)
        assert view.base_va == live
        assert view.read(live + fx.TEXT_RVA, 2) == b"\x58\xC3"
        assert view.is_exec(live + fx.TEXT_RVA)
        assert not view.is_exec(live + fx.RDATA_RVA)
        idx = rop.build_index(view)
        assert any(g.va == live + fx.TEXT_RVA and g.text == "pop rax; ret"
                   for g in idx.gadgets)

    def test_default_base_unchanged(self) -> None:
        img = self._image_layout(b"\x58\xC3" + b"\x90" * (0x200 - 2))
        view = engine.ImageView(img)
        assert view.base_va == fx.IMAGE_BASE
        assert view.read(fx.IMAGE_BASE + fx.TEXT_RVA, 2) == b"\x58\xC3"
        idx = rop.build_index(view)
        assert any(g.va == BASE and g.text == "pop rax; ret"
                   for g in idx.gadgets)
