"""C2-2: `pattern_scan` + `qword_value_scan` in the IDA extension.

The extension imports ``ida_bytes``/``ida_funcs``/``ida_segment`` at
call time. Stub each with a tiny in-memory model of an IDB before
importing the extension so the scanner logic can be exercised
without a live IDA install.
"""
from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest


_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


# --- fake IDA modules --------------------------------------------------


class _FakeSegment:
    def __init__(self, name: str, start_ea: int, end_ea: int):
        self.name = name
        self.start_ea = start_ea
        self.end_ea = end_ea


class _FakeIdb:
    """One flat address space with named segments + a byte payload."""

    def __init__(self) -> None:
        self.segments: list[_FakeSegment] = []
        # ea -> byte
        self.bytes_by_ea: dict[int, int] = {}
        # start_ea -> (start, end, name) for get_func
        self.funcs: dict[int, tuple[int, int, str]] = {}
        # Bad ea (returns None from get_bytes) — simulates an unloaded gap.
        self.bad_range: tuple[int, int] | None = None

    def add_segment(self, name: str, start_ea: int, payload: bytes,
                    func_at: dict[int, str] | None = None) -> None:
        end_ea = start_ea + len(payload)
        self.segments.append(_FakeSegment(name, start_ea, end_ea))
        for i, b in enumerate(payload):
            self.bytes_by_ea[start_ea + i] = b
        if func_at:
            for offset, fn_name in func_at.items():
                fn_start = start_ea + offset
                self.funcs[fn_start] = (fn_start, fn_start + 0x40, fn_name)


_IDB = _FakeIdb()


def _install_ida_stubs() -> None:
    ib = types.ModuleType("ida_bytes")

    def get_bytes(ea: int, size: int):
        if _IDB.bad_range is not None:
            blo, bhi = _IDB.bad_range
            # If the requested range overlaps the bad range at all, mimic
            # a torn read by returning None.
            if not (ea + size <= blo or ea >= bhi):
                return None
        out = bytearray()
        for i in range(size):
            b = _IDB.bytes_by_ea.get(ea + i)
            if b is None:
                # Fill unmapped bytes with 0 for a benign read — the
                # real API returns None for a fully-unmapped range but
                # 0 for individual gaps inside a segment.
                out.append(0)
            else:
                out.append(b)
        return bytes(out)

    def is_loaded(ea: int) -> bool:
        return ea in _IDB.bytes_by_ea

    ib.get_bytes = get_bytes
    ib.is_loaded = is_loaded
    sys.modules["ida_bytes"] = ib

    ifn = types.ModuleType("ida_funcs")

    class _Fn:
        def __init__(self, start: int, end: int):
            self.start_ea = start
            self.end_ea = end

    def get_func(ea: int):
        for start, (fn_lo, fn_hi, _name) in _IDB.funcs.items():
            if fn_lo <= ea < fn_hi:
                return _Fn(fn_lo, fn_hi)
        return None

    def get_func_name(start_ea: int) -> str:
        info = _IDB.funcs.get(start_ea)
        return info[2] if info else ""

    def get_func_qty() -> int:
        return len(_IDB.funcs)

    ifn.get_func = get_func
    ifn.get_func_name = get_func_name
    ifn.get_func_qty = get_func_qty
    sys.modules["ida_funcs"] = ifn

    iseg = types.ModuleType("ida_segment")

    def get_segm_by_name(name: str):
        for s in _IDB.segments:
            if s.name == name:
                return s
        return None

    def get_segm_qty() -> int:
        return len(_IDB.segments)

    def getnseg(i: int):
        return _IDB.segments[i] if 0 <= i < len(_IDB.segments) else None

    iseg.get_segm_by_name = get_segm_by_name
    iseg.get_segm_qty = get_segm_qty
    iseg.getnseg = getnseg
    sys.modules["ida_segment"] = iseg


def _install_core_stub() -> None:
    pkg = types.ModuleType("ida_pro_mcp")
    sys.modules.setdefault("ida_pro_mcp", pkg)
    core = types.ModuleType("ida_pro_mcp.idalib_server")

    class _MCP:
        def add_tool(self, *_args, **_kwargs) -> None:
            return None

    class _IdaPro:
        def open_database(self, *_args, **_kwargs) -> None:
            return None

    core.mcp = _MCP()
    core.idapro = _IdaPro()
    core.main = lambda: None
    sys.modules["ida_pro_mcp.idalib_server"] = core
    pkg.idalib_server = core


@pytest.fixture(scope="module")
def ext_mod():
    _install_core_stub()
    _install_ida_stubs()
    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


@pytest.fixture(autouse=True)
def _reset_idb(ext_mod):  # noqa: ARG001 - fixture dep for import ordering
    _IDB.segments.clear()
    _IDB.bytes_by_ea.clear()
    _IDB.funcs.clear()
    _IDB.bad_range = None
    yield
    _IDB.segments.clear()
    _IDB.bytes_by_ea.clear()
    _IDB.funcs.clear()
    _IDB.bad_range = None


# --- pure helpers -------------------------------------------------------


def test_c2_2_parse_hex_pattern_ok(ext_mod):
    pat, mask = ext_mod._parse_hex_pattern("4C 8D 05 ?? ?? ?? ?? 48 89")
    assert pat == b"\x4c\x8d\x05\x00\x00\x00\x00\x48\x89"
    assert mask == b"\xff\xff\xff\x00\x00\x00\x00\xff\xff"


def test_c2_2_parse_hex_pattern_accepts_0x_prefix(ext_mod):
    pat, mask = ext_mod._parse_hex_pattern("0x4C 0x8D")
    assert pat == b"\x4c\x8d"
    assert mask == b"\xff\xff"


def test_c2_2_parse_hex_pattern_rejects_non_byte(ext_mod):
    # A 4-char hex quad is not a byte; must fail.
    pat, mask = ext_mod._parse_hex_pattern("48AB")
    assert pat == b"" and mask == b""


def test_c2_2_parse_hex_pattern_rejects_junk(ext_mod):
    pat, mask = ext_mod._parse_hex_pattern("XX YY")
    assert pat == b"" and mask == b""


def test_c2_2_parse_hex_pattern_empty_input(ext_mod):
    pat, mask = ext_mod._parse_hex_pattern("")
    assert pat == b"" and mask == b""


# --- pattern_scan behaviour --------------------------------------------


def test_c2_2_pattern_no_wildcards(ext_mod):
    # Segment containing "AA BB CC DD" at offset 0x10, plus filler.
    payload = b"\x90" * 0x10 + b"\xAA\xBB\xCC\xDD" + b"\x90" * 0x10
    _IDB.add_segment(".text", 0x140000000, payload,
                     func_at={0x10: "hit_fn"})
    out = ext_mod.pattern_scan("AA BB CC DD", seg=".text")
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["matches"][0]["ea"] == "0x140000010"
    assert out["matches"][0]["function_name"] == "hit_fn"


def test_c2_2_pattern_with_wildcards(ext_mod):
    # Pattern ends with two wildcard bytes — must still match the two
    # differently-tailed occurrences at 0x100 and 0x110.
    payload = (b"\x90" * 0x100
               + b"\x48\x8B\x05\x11\x22"
               + b"\x90" * (0x10 - 5)
               + b"\x48\x8B\x05\x33\x44"
               + b"\x90" * 0x10)
    _IDB.add_segment(".text", 0x140000000, payload)
    out = ext_mod.pattern_scan("48 8B 05 ?? ??", seg=".text")
    assert out["ok"] is True
    assert out["count"] == 2
    assert [m["ea"] for m in out["matches"]] == [
        "0x140000100", "0x140000110"]


def test_c2_2_pattern_limit_truncates(ext_mod):
    payload = b"\xAA\xBB" * 128 + b"\x00" * 0x40
    _IDB.add_segment(".text", 0x140000000, payload)
    out = ext_mod.pattern_scan("AA BB", seg=".text", limit=4)
    assert out["ok"] is True
    assert out["count"] == 4
    assert out["truncated"] is True


def test_c2_2_pattern_bad_hex_errors(ext_mod):
    _IDB.add_segment(".text", 0x140000000, b"\x00\x00\x00")
    out = ext_mod.pattern_scan("not hex", seg=".text")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"
    assert "hint" in out


def test_c2_2_pattern_seg_not_found(ext_mod):
    _IDB.add_segment(".text", 0x140000000, b"\x00\x00\x00")
    out = ext_mod.pattern_scan("00", seg=".no_such_seg")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"
    assert ".no_such_seg" in out["error"]


def test_c2_2_pattern_all_segments_when_seg_empty(ext_mod):
    # One byte in .text, same byte in .rdata — no seg filter scans both.
    _IDB.add_segment(".text", 0x140001000, b"\x90\xCC\x90")
    _IDB.add_segment(".rdata", 0x140002000, b"\xCC\x00\x00")
    out = ext_mod.pattern_scan("CC")
    assert out["ok"] is True
    eas = [m["ea"] for m in out["matches"]]
    assert "0x140001001" in eas and "0x140002000" in eas


def test_c2_2_pattern_start_end_ea_override_seg(ext_mod):
    payload = b"\x00" * 0x10 + b"\xDE\xAD\xBE\xEF" + b"\x00" * 0x10
    _IDB.add_segment(".text", 0x140000000, payload)
    # start/end ea cover ONLY the last 4 bytes — must miss the match
    # because the ea range starts past 0x140000010.
    out = ext_mod.pattern_scan(
        "DE AD BE EF",
        start_ea="0x140000020", end_ea="0x140000024",
    )
    assert out["ok"] is True
    assert out["count"] == 0


def test_c2_2_pattern_start_end_ea_reversed_errors(ext_mod):
    _IDB.add_segment(".text", 0x140000000, b"\x00\x00")
    out = ext_mod.pattern_scan("00",
                               start_ea="0x140000010",
                               end_ea="0x140000000")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_2_pattern_skips_unmapped_segments(ext_mod):
    # A segment whose get_bytes returns None must NOT crash the scan;
    # its neighbour still yields hits.
    _IDB.add_segment(".bad", 0x140000000, b"\xAA\xBB")
    _IDB.bad_range = (0x140000000, 0x140000002)
    _IDB.add_segment(".text", 0x140001000, b"\xAA\xBB")
    out = ext_mod.pattern_scan("AA BB")
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["matches"][0]["ea"] == "0x140001000"


# --- qword_value_scan ---------------------------------------------------


def test_c2_2_qword_value_scan_finds_ptr(ext_mod):
    # A single QWORD 0xDEADBEEFCAFEBABE (LE) at 0x140000010.
    filler = b"\x00" * 0x10
    qword_le = (0xDEADBEEFCAFEBABE).to_bytes(8, "little")
    _IDB.add_segment(".rdata", 0x140000000, filler + qword_le + filler)
    out = ext_mod.qword_value_scan("0xDEADBEEFCAFEBABE", seg=".rdata")
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["matches"][0]["ea"] == "0x140000010"


def test_c2_2_qword_value_scan_rejects_oversized(ext_mod):
    _IDB.add_segment(".rdata", 0x140000000, b"\x00" * 8)
    out = ext_mod.qword_value_scan("0x1FFFFFFFFFFFFFFFF")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_2_qword_value_scan_bad_value_string(ext_mod):
    out = ext_mod.qword_value_scan("nope")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"
