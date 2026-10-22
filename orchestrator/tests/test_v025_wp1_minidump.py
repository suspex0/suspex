"""v0.25 WP1 — suspex.minidump parser unit tests.

Synthetic DUMP_HEADER64 fixture (triage layout, the C:\\Windows\\Minidump
shape) + an MDMP usermode fixture + corrupt-input handling. Offsets are
pinned in the parser against the WDK-internal Dump.h layout — the
fixture builds the same layout field-by-field so a drifted constant
fails loudly here instead of in the lab.

The real-dump integration path is at the bottom: skipped unless a
MEMORY.DMP / *.dmp exists on this box.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from suspex.minidump import (
    bugcheck_name,
    dump_epoch_ms,
    dump_type_name,
    parse_dump,
    sig_check,
)

_HDR = 0x2000


def _filetime(y: int, m: int, d: int) -> int:
    import datetime as _dt
    dt = _dt.datetime(y, m, d, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return int((dt.timestamp() + 11644473600) * 10_000_000)


def _context64(rsp: int, rip: int) -> bytes:
    """Minimal x64 CONTEXT in the 3000-byte ContextRecord buffer."""
    buf = bytearray(3000)
    struct.pack_into("<I", buf, 0x30, 0x0010001F)  # ContextFlags (AMD64|*)
    struct.pack_into("<I", buf, 0x34, 0x00001F80)  # MxCsr
    for i, seg in enumerate((0x10, 0x2B, 0x2B, 0x53, 0x2B, 0x2B)):
        struct.pack_into("<H", buf, 0x38 + i * 2, seg)
    struct.pack_into("<I", buf, 0x44, 0x00000246)  # EFlags
    struct.pack_into("<Q", buf, 0x48, 0x1)         # Dr0..Dr7 slots
    struct.pack_into("<Q", buf, 0x70, 0x6)
    gprs = [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, rsp, 0xEEEE,
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
            0x7777, 0x8888, 0x9999, 0x0000]
    for i, v in enumerate(gprs):
        struct.pack_into("<Q", buf, 0x78 + i * 8, v)
    struct.pack_into("<Q", buf, 0xF8, rip)
    return bytes(buf)


def _kernel_triage_dump(*, code: int = 0xE2,
                        params=(1, 45000, 40000, 0xD15EA5E),
                        exc_addr: int = 0xFFFFF80077770000,
                        rsp: int = 0xFFFFF80011119000,
                        rip: int = 0xFFFFF80077771234,
                        stack: tuple = (),
                        drivers: tuple = (),
                        kernbase: int | None = None) -> bytes:
    """DUMP_HEADER64 + TRIAGE_DUMP64 body — the small-dump layout.

    ``drivers`` = ((path, DllBase, SizeOfImage), ...) builds the
    embedded DUMP_DRIVER_ENTRY list + string pool + debugger-data block
    exactly as real triage minidumps carry them (0x90-byte entries,
    name offset at +0x00 pointing at a u32-length-prefixed UTF-16 pool
    string, base/size at +0x38/+0x48)."""
    hdr = bytearray(_HDR)
    hdr[0x00:0x04] = b"PAGE"
    hdr[0x04:0x08] = b"DU64"
    struct.pack_into("<I", hdr, 0x08, 15)            # MajorVersion
    struct.pack_into("<I", hdr, 0x0C, 22621)         # MinorVersion
    struct.pack_into("<Q", hdr, 0x10, 0x1AA000)      # DirectoryTableBase
    struct.pack_into("<I", hdr, 0x30, 0x8664)        # MachineImageType
    struct.pack_into("<I", hdr, 0x34, 16)            # NumberProcessors
    struct.pack_into("<I", hdr, 0x38, code)
    struct.pack_into("<4Q", hdr, 0x40, *params)
    hdr[0x60:0x60 + 11] = b"suspex lab\x00"
    struct.pack_into("<Q", hdr, 0x80, 0xFFFFF8000ABC0000)  # KdDebuggerDataBlock
    struct.pack_into("<I", hdr, 0x88, 1)             # PhysMem NumberOfRuns
    struct.pack_into("<Q", hdr, 0x90, 0x100)         # PhysMem NumberOfPages
    struct.pack_into("<Q", hdr, 0x98, 0)             # run0 BasePage
    struct.pack_into("<Q", hdr, 0xA0, 0x100)         # run0 PageCount
    hdr[0x348:0x348 + 3000] = _context64(rsp, rip)
    # EXCEPTION_RECORD64 @0xF00
    struct.pack_into("<I", hdr, 0xF00, 0x80000003)
    struct.pack_into("<Q", hdr, 0xF10, exc_addr)
    struct.pack_into("<I", hdr, 0xF18, 4)
    struct.pack_into("<4Q", hdr, 0xF20, *params)
    struct.pack_into("<I", hdr, 0xF98, 4)            # DumpType = TRIAGE
    struct.pack_into("<Q", hdr, 0xFA8, _filetime(2026, 10, 18))
    hdr[0xFB0:0xFB0 + 10] = b"lab crash\x00"

    stack_b = b"".join(struct.pack("<Q", q) for q in stack)
    # TopOfStack is the capturing thread's Rsp — the saved callstack
    # bytes cover [TopOfStack, TopOfStack + SizeOfCallStack), running
    # UP the stack through the older frames. Pinned against real
    # minidumps (TopOfStack == context.rsp; an earlier reading of the
    # field as the region end emptied stack_qwords for every real
    # triage dump).
    top = rsp
    tri = bytearray(0x80)
    struct.pack_into("<I", tri, 0x00, 22621)         # ServicePackBuild
    struct.pack_into("<I", tri, 0x28, _HDR + 0x80)   # CallStackOffset
    struct.pack_into("<I", tri, 0x2C, len(stack_b))  # SizeOfCallStack
    struct.pack_into("<Q", tri, 0x48, top)           # TopOfStack

    body = bytearray(stack_b)
    if kernbase is not None:
        dd = bytearray(0x30)
        struct.pack_into("<Q", dd, 0x18, kernbase)   # KernBase @+0x18
        struct.pack_into("<I", tri, 0x70, _HDR + 0x80 + len(body))
        struct.pack_into("<I", tri, 0x74, len(dd))
        body += dd
    if drivers:
        dl_off = _HDR + 0x80 + len(body)
        entries_len = 0x90 * len(drivers)
        pool_off = dl_off + entries_len
        pool = bytearray()
        entries = bytearray()
        for (drv_path, base, size) in drivers:
            nameoff = pool_off + len(pool)
            chars = drv_path.encode("utf-16-le")
            pool += struct.pack("<I", len(drv_path)) + chars + b"\x00\x00"
            while len(pool) % 4:
                pool += b"\x00"
            e = bytearray(0x90)
            struct.pack_into("<Q", e, 0x00, nameoff)
            struct.pack_into("<Q", e, 0x38, base)
            struct.pack_into("<Q", e, 0x48, size)
            struct.pack_into("<I", e, 0x80, 0xC817D5)     # TimeDateStamp
            struct.pack_into("<I", e, 0x88, 0xD00D1E5)    # CheckSum
            entries += e
        struct.pack_into("<I", tri, 0x30, dl_off)         # DriverListOffset
        struct.pack_into("<I", tri, 0x34, len(drivers))   # DriverCount
        struct.pack_into("<I", tri, 0x38, pool_off)       # StringPoolOffset
        struct.pack_into("<I", tri, 0x3C, len(pool))      # StringPoolSize
        body += entries + pool
    struct.pack_into("<I", tri, 0x04, _HDR + 0x80 + len(body))
    return bytes(hdr) + bytes(tri) + bytes(body)


def _mdmp(*, exc_code: int = 0xC0000005,
          exc_addr: int = 0x00007FF600001000,
          params=(0, 0xDEADBEEF),
          rip: int = 0x00007FF600002233,
          rsp: int = 0x0000007FE0010000,
          stack: tuple = ()) -> bytes:
    """MINIDUMP: header + dir + ExceptionStream + MemoryList + context."""
    ctx = bytearray(1232)
    struct.pack_into("<I", ctx, 0x30, 0x0010001F)
    struct.pack_into("<Q", ctx, 0x78 + 4 * 8, rsp)   # rsp is gprs[4]
    struct.pack_into("<Q", ctx, 0xF8, rip)

    stack_b = b"".join(struct.pack("<Q", q) for q in stack) or \
        b"\x00" * 256

    # Exception stream + memory list; the context rides along via the
    # exception record's ThreadContext location, not its own stream.
    nstreams = 2
    dir_end = 32 + nstreams * 12
    exc_off = dir_end
    exc_len = 8 + 152 + 8
    memlist_off = exc_off + exc_len
    memlist_len = 4 + 16
    ctx_off = memlist_off + memlist_len
    stack_off = ctx_off + len(ctx)

    exc = struct.pack("<II", 0x1234, 0)
    exc += struct.pack("<IIQQI", exc_code, 0, 0, exc_addr, len(params))
    exc += b"\x00" * 4                                # record alignment pad
    exc += b"".join(struct.pack("<Q", p) for p in params)
    exc += b"\x00" * (15 * 8 - len(params) * 8)
    exc += struct.pack("<II", len(ctx), ctx_off)      # ThreadContext loc
    assert len(exc) == exc_len

    memlist = struct.pack("<I", 1)
    memlist += struct.pack("<QII", rsp, len(stack_b), stack_off)

    streams = [(6, exc_len, exc_off), (4, memlist_len, memlist_off)]
    hdr = struct.pack("<IIIIIIQ", 0x504D444D, 0xA793, nstreams, 32, 0,
                      0x65654321, 0)
    dirent = b"".join(struct.pack("<III", t, s, o) for t, s, o in streams)
    out = bytearray(hdr + dirent + exc + memlist + bytes(ctx) + stack_b)
    return bytes(out)


# ----------------------------------------------------------------------- #
# kernel dump parse
# ----------------------------------------------------------------------- #

def test_kernel_triage_dump_parses_bugcheck_params_context(tmp_path):
    dmp = tmp_path / "Mini101826-01.dmp"
    dmp.write_bytes(_kernel_triage_dump(
        stack=(0xFFFFF80077779999, 0xFFFFF80088880000, 0, 0)))
    res = parse_dump(str(dmp))
    assert res["ok"] is True, res
    assert res["format"] == "kernel_dump"
    assert res["bugcheck"] == {"code": 0xE2,
                              "name": "MANUALLY_INITIATED_CRASH"}
    assert res["params"] == [1, 45000, 40000, 0xD15EA5E]
    assert res["dtb"] == 0x1AA000
    assert res["kd_data_block"] == 0xFFFFF8000ABC0000
    assert res["dump_type"]["name"] == "triage"
    assert res["context"]["rip"] == 0xFFFFF80077771234
    assert res["context"]["rsp"] == 0xFFFFF80011119000
    assert res["context"]["rax"] == 0xAAAA
    assert res["exception"]["address"] == 0xFFFFF80077770000
    assert res["size"] == dmp.stat().st_size
    assert res["path"] == str(dmp)
    # watchdog self-identification — 0xE2 with armed params decodes to
    # the driver watchdog arg layout and tags fired_by.
    assert res["fired_by"] == "suspex_watchdog"
    assert res["watchdog"] == {"id": 1, "deadline_us": 45000,
                              "last_kick_us": 40000,
                              "cookie": 0xD15EA5E}
    # faulting VA = the exception record's address (no 0xE2 param map).
    assert res["faulting_va"] == 0xFFFFF80077770000
    # stack_qwords walk the embedded callstack region from rsp.
    assert [q["value"] for q in res["stack_qwords"]] == [
        0xFFFFF80077779999, 0xFFFFF80088880000, 0, 0]
    assert res["stack_qwords"][0]["va"] == 0xFFFFF80011119000


def test_user_initiated_e2_without_params_is_not_watchdog(tmp_path):
    """A plain `.crash` (params all zero) must NOT self-identify as the
    suspex watchdog firing — that's the false-positive the field exists
    to prevent."""
    dmp = tmp_path / "crash.dmp"
    dmp.write_bytes(_kernel_triage_dump(code=0xE2, params=(0, 0, 0, 0)))
    res = parse_dump(str(dmp))
    assert res["ok"] is True
    assert "watchdog" not in res
    assert "fired_by" not in res


def test_bugcheck_param_heuristics(tmp_path):
    """0xD1's documented layout: p1=memory referenced, p4=faulting PC."""
    dmp = tmp_path / "d1.dmp"
    dmp.write_bytes(_kernel_triage_dump(
        code=0xD1,
        params=(0xFFFFF800DEADBEEF, 2, 1, 0xFFFFF80012345678)))
    res = parse_dump(str(dmp))
    assert res["bugcheck"]["name"] == "DRIVER_IRQL_NOT_LESS_OR_EQUAL"
    assert res["faulting_va"] == 0xFFFFF800DEADBEEF
    assert res["faulting_pc"] == 0xFFFFF80012345678


def test_unknown_bugcheck_code_falls_back_to_hex(tmp_path):
    dmp = tmp_path / "odd.dmp"
    dmp.write_bytes(_kernel_triage_dump(code=0xDEAD))
    res = parse_dump(str(dmp))
    assert res["bugcheck"] == {"code": 0xDEAD, "name": "0xdead"}


def test_system_time_decodes(tmp_path):
    dmp = tmp_path / "time.dmp"
    dmp.write_bytes(_kernel_triage_dump())
    res = parse_dump(str(dmp))
    assert res["system_time_iso"].startswith("2026-10-18T12:00:00")
    # epoch ms sits between "before the dump" and "after the dump" —
    # the freshness comparator needs a real number, not zero.
    assert dump_epoch_ms(res) > 1_700_000_000_000


# ----------------------------------------------------------------------- #
# MDMP parse
# ----------------------------------------------------------------------- #

def test_mdmp_exception_stream_parses(tmp_path):
    dmp = tmp_path / "proc.dmp"
    dmp.write_bytes(_mdmp(stack=(0x4141414141414141, 0x7FF612345678)))
    res = parse_dump(str(dmp))
    assert res["ok"] is True, res
    assert res["format"] == "mdmp"
    assert res["bugcheck"]["code"] == 0xC0000005
    assert res["bugcheck"]["name"] == "STATUS_ACCESS_VIOLATION"
    assert res["exception"]["address"] == 0x00007FF600001000
    assert res["exception"]["parameters"] == [0, 0xDEADBEEF]
    assert res["params"] == [0, 0xDEADBEEF, 0, 0]
    assert res["faulting_va"] == 0x00007FF600001000
    assert res["context"]["rip"] == 0x00007FF600002233
    assert [q["value"] for q in res["stack_qwords"]][:2] == [
        0x4141414141414141, 0x7FF612345678]


# ----------------------------------------------------------------------- #
# corrupt / missing inputs — non-fatal, kind-tagged
# ----------------------------------------------------------------------- #

def test_garbage_file_is_bad_dump(tmp_path):
    dmp = tmp_path / "junk.dmp"
    dmp.write_bytes(b"this is not a dump" * 100)
    res = parse_dump(str(dmp))
    assert res["ok"] is False
    assert res["kind"] == "bad_dump"


def test_truncated_header_is_bad_dump(tmp_path):
    dmp = tmp_path / "short.dmp"
    dmp.write_bytes(b"PAGE" + b"DU64" + b"\x00" * 100)
    res = parse_dump(str(dmp))
    assert res["ok"] is False
    assert res["kind"] == "bad_dump"


def test_missing_file_is_not_found(tmp_path):
    res = parse_dump(str(tmp_path / "nope.dmp"))
    assert res["ok"] is False
    assert res["kind"] == "not_found"


def test_sig_check_probe_bytes():
    assert sig_check(b"PAGE" + b"DU64") == "kernel_dump"
    assert sig_check(b"PAGE" + b"DUMP") == "kernel_dump"
    assert sig_check(b"MDMP" + b"\x00" * 4) == "mdmp"
    assert sig_check(b"MZ" + b"\x00" * 6) is None


def test_name_helpers():
    assert bugcheck_name(0x133) == "DPC_WATCHDOG_VIOLATION"
    assert bugcheck_name(0xE2) == "MANUALLY_INITIATED_CRASH"
    assert bugcheck_name(0x999999) == "0x999999"
    assert dump_type_name(4) == "triage"
    assert dump_type_name(5) == "bitmap_full"


# ----------------------------------------------------------------------- #
# integration: real dump on disk (skip otherwise)
# ----------------------------------------------------------------------- #

_REAL_DUMP_CANDIDATES = [
    # WER user-mode dumps land here and are readable without elevation —
    # C:\Windows\Minidump files are ACL'd to SYSTEM/Administrators.
    Path(os.environ.get("LOCALAPPDATA", "")) / "CrashDumps",
    Path(r"C:\Windows\Minidump"),
    Path(r"C:\Windows\MEMORY.DMP"),
    Path(r"D:\dumps"),
]


def _readable(p: Path) -> bool:
    # os.access can't see DACLs on Windows — the only reliable probe is
    # an actual open. An unreadable dump is "not present" for the test.
    try:
        with open(p, "rb"):
            return True
    except OSError:
        return False


def _find_real_dump() -> Path | None:
    found: list[Path] = []
    for cand in _REAL_DUMP_CANDIDATES:
        if cand.is_dir():
            found.extend(cand.glob("*.dmp"))
        elif cand.is_file():
            found.append(cand)
    for dmp in sorted(found, key=lambda p: p.stat().st_mtime, reverse=True):
        if _readable(dmp):
            return dmp
    return None


async def test_real_dump_parses_when_present():
    dmp = _find_real_dump()
    if dmp is None:
        pytest.skip("no real crash dump on this box")
    res = parse_dump(str(dmp))
    assert res["ok"] is True, res
    assert res["bugcheck"]["code"] != 0 or res["format"] == "mdmp"


# ----------------------------------------------------------------------- #
# triage stack + driver-list extraction (dump_manage action='stack')
# ----------------------------------------------------------------------- #

_KB = 0xFFFFF80000000000


def test_read_triage_stack_walks_frames_and_drivers(tmp_path):
    from suspex.minidump import read_triage_stack
    dmp = tmp_path / "Mini102026-01.dmp"
    dmp.write_bytes(_kernel_triage_dump(
        rsp=0xFFFFF80011119000,
        stack=(0xFFFFF80002000123, 0xFFFFF80000045000, 0x33),
        kernbase=_KB,
        drivers=((
            r"\SystemRoot\system32\ntoskrnl.exe", _KB, 0x1000000),
            (r"\SystemRoot\System32\drivers\mydrv.sys",
             0xFFFFF80002000000, 0x50000))))
    res = read_triage_stack(str(dmp))
    assert res["ok"] is True, res
    assert res["kernbase"] == _KB
    assert res["kernbase_source"] == "debugger_data+0x18"
    assert res["frames_total"] == 3
    assert res["driver_count"] == 2
    names = {d["name"].split("\\")[-1] for d in res["drivers"]}
    assert names == {"ntoskrnl.exe", "mydrv.sys"}
    f0, f1, f2 = res["frames"]
    assert f0["module"] == "mydrv.sys"
    assert f0["text"] == "mydrv.sys+0x123"
    assert f0["attribution"] == "driver_list"
    assert f1["module"] == "ntoskrnl.exe"
    assert f1["text"] == "ntoskrnl.exe+0x45000"
    assert f2["attribution"] == "data"
    assert res["notes"] == []


def test_read_triage_stack_offline_when_no_drivers(tmp_path):
    """No driver list / debugger data — frames still walk, kernbase
    honestly absent, kernel VAs report unresolved."""
    from suspex.minidump import read_triage_stack
    dmp = tmp_path / "bare.dmp"
    dmp.write_bytes(_kernel_triage_dump(
        rsp=0xFFFFF80011119000,
        stack=(0xFFFFF80000045000,)))
    res = read_triage_stack(str(dmp))
    assert res["ok"] is True, res
    assert res["kernbase"] is None
    assert res["frames_total"] == 1
    assert res["frames"][0]["attribution"] == "unresolved"
    assert res["driver_count"] == 0


def test_read_triage_stack_bad_input(tmp_path):
    from suspex.minidump import read_triage_stack
    missing = read_triage_stack(str(tmp_path / "nope.dmp"))
    assert missing["ok"] is False
    assert missing["kind"] == "not_found"
    junk = tmp_path / "junk.dmp"
    junk.write_bytes(b"not a dump" * 10)
    res = read_triage_stack(str(junk))
    assert res["ok"] is False
    assert res["kind"] == "bad_dump"


def test_parse_triage_kernbase_and_pool_offsets(tmp_path):
    dmp = tmp_path / "full.dmp"
    dmp.write_bytes(_kernel_triage_dump(
        rsp=0xFFFFF80011119000,
        stack=(0xFFFFF80000045000,),
        kernbase=_KB,
        drivers=((r"\SystemRoot\system32\ntoskrnl.exe", _KB, 0x1000000),)))
    res = parse_dump(str(dmp))
    assert res["ok"] is True
    tri = res["triage"]
    assert tri["kernbase"] == _KB
    assert tri["string_pool_offset"] > 0
    assert tri["string_pool_size"] > 0
    assert tri["driver_count"] == 1
    # stack_qwords walk the embedded region from rsp again (regression:
    # the region used to be read as [top-size, top) and matched nothing).
    assert [q["value"] for q in res["stack_qwords"]] == [0xFFFFF80000045000]
