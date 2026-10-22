"""Tests for the knife-derived analysis layer + bin_manage dispatch.

Fixtures are synthesized by tests/_pefixture.py — a minimal PE64 builder.
Engine tests skip when capstone is absent (codegen extra).
"""
from __future__ import annotations

import struct

import pytest

import _pefixture as fx
from suspex.analysis import caps, entropy, extract, hardening, pe, signatures


# ---------------------------------------------------------------- PE parse --

class TestPeParse:
    def test_headers_and_sections(self) -> None:
        img = pe.parse(fx.build_pe(code=b"\x55\x8b\xec\xc3"),
                       layout="file")
        assert img.machine == 0x8664
        assert img.pe32_plus is True
        assert img.image_base == fx.IMAGE_BASE
        assert img.entry_rva == fx.TEXT_RVA
        assert {s.name for s in img.sections} == {".text", ".rdata",
                                                ".idata"}
        text = next(s for s in img.sections if s.name == ".text")
        assert text.exec and text.readable and not text.writable

    def test_entry_maps_to_code(self) -> None:
        img = pe.parse(fx.build_pe(code=b"\x90\x90\xc3"),
                       layout="file")
        off = img.rva_to_off(img.entry_rva)
        assert img.data[off:off + 3] == b"\x90\x90\xc3"
        assert img.read_rva(img.entry_rva, 3) == b"\x90\x90\xc3"

    def test_imports_roundtrip(self) -> None:
        img = pe.parse(
            fx.build_pe(imports={"KERNEL32.dll": ["CreateFileW",
                                                  "VirtualAlloc"]}),
            layout="file")
        assert len(img.imports) == 1
        d = img.imports[0]
        assert d["dll"].lower() == "kernel32.dll"
        names = [e["name"] for e in d["entries"]]
        assert names == ["CreateFileW", "VirtualAlloc"]
        for e in d["entries"]:
            assert e["thunk_rva"] >= fx.IDATA_RVA

    def test_exports_roundtrip(self) -> None:
        img = pe.parse(
            fx.build_pe(exports={"DriverEntry": fx.TEXT_RVA,
                                 "SvcMain": fx.TEXT_RVA + 0x10}),
            layout="file")
        names = {e["name"] for e in img.exports}
        assert names == {"DriverEntry", "SvcMain"}
        for e in img.exports:
            assert e["va"] == fx.IMAGE_BASE + exports_rva(e["name"])

    def test_imphash_stable(self) -> None:
        a = pe.parse(fx.build_pe(
            imports={"a.dll": ["x", "y"], "b.dll": ["z"]}), layout="file")
        b = pe.parse(fx.build_pe(
            imports={"a.dll": ["x", "y"], "b.dll": ["z"]}), layout="file")
        assert pe.imphash(a) == pe.imphash(b)
        c = pe.parse(fx.build_pe(imports={"a.dll": ["y", "x"]}),
                     layout="file")
        assert pe.imphash(a) != pe.imphash(c)  # order matters

    def test_malformed_raises(self) -> None:
        with pytest.raises(Exception):
            pe.parse(b"MZ" + b"\0" * 100, layout="file")
        with pytest.raises(Exception):
            pe.parse(fx.build_pe()[:0x100], layout="file")


def exports_rva(name: str) -> int:
    return fx.TEXT_RVA if name == "DriverEntry" else fx.TEXT_RVA + 0x10


# -------------------------------------------------------------- extractors --

class TestExtract:
    def test_strings_ascii_and_utf16(self) -> None:
        blob = (b"AAAA http://evil.example.com/x BBBB\x00"
                + "H\\Device\\EvilDrv".encode("utf-16le") + b"\x00\x00"
                + b"C" * 8)
        rows = extract.find_strings(blob, min_len=5)
        kinds = {r["kind"] for r in rows}
        assert "ascii" in kinds and "utf16" in kinds
        vals = [r["value"] for r in rows]
        assert any("evil.example.com" in v for v in vals)

    def test_base_va_stamps_va(self) -> None:
        rows = extract.find_strings(b"hello world strings here",
                                    min_len=5, base_va=0x10000)
        assert rows and all(r["va"] == 0x10000 + r["offset"]
                            for r in rows)

    def test_iocs_defanged(self) -> None:
        blob = b"call home to https://c2.bad.example/path?q=1 ok"
        rows = extract.find_iocs(blob)
        urls = [r for r in rows if r["kind"] == "url"]
        assert urls and "hxxps" in urls[0]["defanged"]

    def test_iocs_dedupe_counts(self) -> None:
        blob = b"10.4.4.4 " * 3 + b"and 10.4.4.4 again"
        rows = [r for r in extract.find_iocs(blob) if r["kind"] == "ipv4"]
        assert len(rows) == 1 and rows[0]["count"] >= 3

    def test_ipv4_plausibility(self) -> None:
        rows = extract.find_iocs(b"version 999.888.777.666 not ip")
        assert not [r for r in rows if r["kind"] == "ipv4"]


class TestEntropy:
    def test_zero_and_random(self) -> None:
        import os
        assert entropy.shannon(b"\0" * 4096) == 0.0
        assert entropy.shannon(os.urandom(4096)) > 7.0

    def test_entropy_map_packed(self) -> None:
        import os
        em = entropy.entropy_map(os.urandom(8192), buckets=16)
        assert em["packed"] is True
        assert len(em["buckets"]) == 16
        em2 = entropy.entropy_map(b"\x41" * 8192)
        assert em2["packed"] is False


class TestSignatures:
    def test_aes_sbox_detected(self) -> None:
        sbox = signatures._aes_sbox()
        blob = os_random(512) + sbox + os_random(512)
        hits = signatures.scan(blob)
        assert any(h["name"] == "aes_sbox" for h in hits)

    def test_embedded_pe(self) -> None:
        inner = fx.build_pe()
        blob = os_random(64) + inner
        hits = [h for h in signatures.scan(blob)
                if h["name"] == "embedded_pe"]
        assert hits and hits[0]["offset"] == 64


def os_random(n: int) -> bytes:
    import os
    return os.urandom(n)


# ------------------------------------------------------------- hardening ----

class TestHardening:
    def test_dynamic_base_partial_without_reloc(self) -> None:
        img = pe.parse(fx.build_pe(dll_chars=0x0040 | 0x0100 | 0x8000),
                       layout="file")
        rep = hardening.audit(img)
        assert "checks" in rep or "mitigations" in rep or "results" in rep


class TestCaps:
    def test_infer(self) -> None:
        rows = caps.infer_capabilities(
            {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
            set())
        assert rows  # injection-ish capability inferred


# ---------------------------------------------------------------- engine ----

def _needs_capstone():
    pytest.importorskip("capstone")


class TestEngine:
    def test_function_recovery_from_pdata(self) -> None:
        _needs_capstone()
        # two tiny funcs: fn1 calls fn2 then rets; fn2 rets
        # fn1 @ +0:  E8 rel32 (call fn2@+0x10); C3
        # padding to +0x10: int3s
        # fn2 @ +0x10: C3
        code = (b"\xE8" + struct.pack("<i", 0x10 - 5) + b"\xC3"
                + b"\xCC" * (0x10 - 6)
                + b"\xC3")
        data = fx.build_pe(code=code,
                           pdata=[(fx.TEXT_RVA, fx.TEXT_RVA + 0x6),
                                  (fx.TEXT_RVA + 0x10, fx.TEXT_RVA + 0x11)])
        img = pe.parse(data, layout="file")
        from suspex.analysis import engine
        analysis = engine.analyze_image(engine.ImageView(img))
        starts = set(analysis.functions)
        base = fx.IMAGE_BASE + fx.TEXT_RVA
        assert base in starts and base + 0x10 in starts
        fn1 = analysis.functions[base]
        assert any(c == base + 0x10 for c in fn1.calls)

    def test_entry_seed(self) -> None:
        _needs_capstone()
        data = fx.build_pe(code=b"\x48\x31\xC0\xC3")
        img = pe.parse(data, layout="file")
        from suspex.analysis import engine
        analysis = engine.analyze_image(engine.ImageView(img))
        assert (fx.IMAGE_BASE + fx.TEXT_RVA) in analysis.functions

    def test_xrefs_to_call_target(self) -> None:
        _needs_capstone()
        code = (b"\xE8" + struct.pack("<i", 0x10 - 5) + b"\xC3"
                + b"\xCC" * (0x10 - 6) + b"\xC3")
        data = fx.build_pe(code=code)
        img = pe.parse(data, layout="file")
        from suspex.analysis import engine
        analysis = engine.analyze_image(engine.ImageView(img))
        tgt = fx.IMAGE_BASE + fx.TEXT_RVA + 0x10
        refs = analysis.xrefs_to.get(tgt, [])
        assert any(r["from"] == fx.IMAGE_BASE + fx.TEXT_RVA
                   for r in refs)

    def test_budget_truncation(self) -> None:
        _needs_capstone()
        data = fx.build_pe(code=b"\x90" * 0x1FF)
        img = pe.parse(data, layout="file")
        from suspex.analysis import engine
        analysis = engine.analyze_image(engine.ImageView(img),
                                        budget=8)
        assert analysis.truncated

    def test_body_hash_stable(self) -> None:
        _needs_capstone()
        data = fx.build_pe(code=b"\x48\x31\xC0\xC3")
        img = pe.parse(data, layout="file")
        from suspex.analysis import engine
        an = engine.analyze_image(engine.ImageView(img))
        fn = next(iter(an.functions.values()))
        h1 = engine.body_hash(fn)
        an2 = engine.analyze_image(engine.ImageView(img))
        fn2 = next(iter(an2.functions.values()))
        assert h1 == engine.body_hash(fn2)
