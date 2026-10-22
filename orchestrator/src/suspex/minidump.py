"""Pure-Python Windows crash-dump parser — v0.25 WP1.

Covers the kernel crash-dump family (``DUMP_HEADER64`` — full / summary /
triage / bitmap bodies) and, minimally, usermode minidumps ("MDMP").

The stable return shape WP1 callers rely on::

    {"ok": True, "format": "kernel_dump"|"mdmp",
     "bugcheck": {"code": int, "name": str},
     "params": [int, int, int, int],
     "context": {...} | None, "exception": {...} | None,
     "dtb": int|None, "kd_data_block": int|None,
     "size": int, "path": str, ...}

Header offsets were pinned against the WDK-internal ``Dump.h`` (Microsoft
Research Singularity tree mirror) and cross-checked against volatility's
``_DMP_HEADER64`` listing and a Windows-10 dump hexdump. The notable
trap: the 700-byte ``PhysicalMemoryBlockBuffer`` sits inside a union
with the 8-byte-aligned ``PHYSICAL_MEMORY_DESCRIPTOR64``, so the union
is 704 bytes — ``ContextRecord`` lands at 0x348 (not 0x344) and
``EXCEPTION_RECORD64`` at 0xF00.

Body layout depends on ``DumpType`` (@0xF98):

  * FULL(1)          — physical pages stored sequentially after the
                       0x2000 header, in ``PhysicalMemoryBlock`` run order.
  * SUMMARY(2),
    BITMAP_FULL(5),
    BITMAP_KERNEL(6) — ``SUMMARY_DUMP64`` subheader at 0x2000 carrying a
                       PFN-indexed bitmap; page data at its ``HeaderSize``
                       file offset (signature "SDMP"/"FDMP").
  * TRIAGE(4)        — ``TRIAGE_DUMP64`` at 0x2000; the saved call-stack
                       pages are embedded (this is what lives in
                       ``C:\\Windows\\Minidump\\*.dmp``).
  * HEADER(3)        — header only, no page data.
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path
from typing import Any

PAGE_SIG = b"PAGE"
VALID_64 = b"DU64"
VALID_32 = b"DUMP"
MDMP_SIG = b"MDMP"

HEADER_SIZE_64 = 0x2000
PAGE_SIZE = 0x1000

# DUMP_HEADER64 offsets (x64) — see module docstring for provenance.
_OFF_DTB = 0x10
_OFF_PFN_DB = 0x18
_OFF_PSLML = 0x20
_OFF_PSAPH = 0x28
_OFF_MACHINE = 0x30
_OFF_NUMPROC = 0x34
_OFF_BUGCHECK = 0x38
_OFF_PARAMS = 0x40
_OFF_VERSION_USER = 0x60
_OFF_KD_BLOCK = 0x80
_OFF_PHYS_MEM = 0x88          # PHYSICAL_MEMORY_DESCRIPTOR64
_OFF_CONTEXT = 0x348          # x64 CONTEXT inside a 3000-byte buffer
_OFF_EXCEPTION = 0xF00        # EXCEPTION_RECORD64 (152 bytes)
_OFF_DUMP_TYPE = 0xF98
_OFF_REQUIRED_SPACE = 0xFA0
_OFF_SYSTEM_TIME = 0xFA8
_OFF_COMMENT = 0xFB0
_OFF_SYSTEM_UPTIME = 0x1030

# EXCEPTION_RECORD64 field offsets (relative to the record).
_EXC_CODE = 0x00
_EXC_FLAGS = 0x04
_EXC_RECORD = 0x08
_EXC_ADDRESS = 0x10
_EXC_NUMPARAMS = 0x18
_EXC_INFO = 0x20               # 15 ULONG64 slots

# x64 CONTEXT field offsets (relative to ContextRecord start).
_CTX_P1 = 0x00                 # P1Home..P6Home
_CTX_FLAGS = 0x30
_CTX_MXCSR = 0x34
_CTX_SEGCS = 0x38              # segs: cs,ds,es,fs,gs,ss every 2 bytes
_CTX_EFLAGS = 0x44
_CTX_DR0 = 0x48                # dr0..dr3, then dr6, dr7 (8-byte slots)
_CTX_RAX = 0x78
_CTX_RIP = 0xF8

_CONTEXT_AMD64 = 0x00100000    # CONTEXT_AMD64 flag bit

# TRIAGE_DUMP64 offsets (relative to the structure at file 0x2000).
_TRI_SP_BUILD = 0x00
_TRI_SIZE_OF_DUMP = 0x04
_TRI_VALID_OFFSET = 0x08
_TRI_CONTEXT_OFFSET = 0x0C
_TRI_EXCEPTION_OFFSET = 0x10
_TRI_CALLSTACK_OFFSET = 0x28
_TRI_CALLSTACK_SIZE = 0x2C
_TRI_DRIVER_LIST_OFFSET = 0x30
_TRI_DRIVER_COUNT = 0x34
_TRI_STRING_POOL_OFFSET = 0x38
_TRI_STRING_POOL_SIZE = 0x3C
_TRI_BROKEN_DRIVER_OFFSET = 0x40
_TRI_TOP_OF_STACK = 0x48       # ULONG64 — highest VA of the saved stack
_TRI_DATA_PAGE_ADDRESS = 0x60  # ULONG64 VA the data page decodes at
_TRI_DATA_PAGE_OFFSET = 0x68
_TRI_DATA_PAGE_SIZE = 0x6C
_TRI_DEBUGGER_DATA_OFFSET = 0x70
_TRI_DEBUGGER_DATA_SIZE = 0x74
_TRI_DATA_BLOCKS_OFFSET = 0x78
_TRI_DATA_BLOCKS_COUNT = 0x7C

# KernBase sits at +0x18 inside the KDDEBUGGER_DATA64 block the triage
# dump embeds (verified against real minidumps: matches the ntoskrnl
# entry base in the embedded driver list).
_KD_DEBUGGER_KERNBASE = 0x18

# TRIAGE_DUMP64 embedded driver list: fixed 0x90-byte DUMP_DRIVER_ENTRY
# records (verified against real minidumps; name/base/size stable across
# the lab's builds — timestamp/checksum slots best-effort).
_TRI_DRIVER_ENTRY_SIZE = 0x90
_TRI_DRV_NAME_OFFSET = 0x00   # u64: absolute file offset of the name
_TRI_DRV_BASE = 0x38          # u64: DllBase
_TRI_DRV_SIZE = 0x48          # u64: SizeOfImage
_TRI_DRV_TIMESTAMP = 0x80     # u32: TimeDateStamp
_TRI_DRV_CHECKSUM = 0x88      # u32: CheckSum

# String pool: u32 char_count + UTF-16-LE chars + UTF-16 NUL, packed
# back-to-back (4-byte alignment between entries). Entry name offsets
# point at the u32 length field, as absolute dump file offsets.
_MAX_DRV_NAME_CHARS = 520

# SUMMARY_DUMP64 offsets (relative to the structure at file 0x2000).
_SUM_SIGNATURE = 0x00          # "SDMP" (summary/kernel) or "FDMP" (full)
_SUM_VALIDDUMP = 0x04          # "DUMP"
_SUM_DUMP_OPTIONS = 0x08
_SUM_HEADER_SIZE = 0x0C        # file offset where page data starts
_SUM_BITMAP_SIZE = 0x10        # bitmap length in bits (max PFN + 1)
_SUM_PAGES = 0x14              # bits actually set (= pages in file)
_SUM_BITMAP = 0x28             # bitmap bytes start here (after
                              # SizeOfBitMap u32 + ULONG64 reserved)

DUMP_TYPES = {
    0: "unknown",
    1: "full",
    2: "summary",
    3: "header",
    4: "triage",
    5: "bitmap_full",
    6: "bitmap_kernel",
}
_BITMAP_DUMP_TYPES = {2, 5, 6}

# Bugcheck-name table — the codes that matter in the lab (watchdog
# fires, verifier hits, the usual suspects). Unknown codes fall back to
# "0x%x" so the envelope stays honest rather than inventing a name.
BUGCHECK_NAMES = {
    0x0001: "APC_INDEX_MISMATCH",
    0x000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x0024: "NTFS_FILE_SYSTEM",
    0x0027: "RDR_FILE_SYSTEM",
    0x002E: "DATA_BUS_ERROR",
    0x0035: "NO_MORE_IRP_STACK_LOCATIONS",
    0x003B: "SYSTEM_SERVICE_EXCEPTION",
    0x0044: "MULTIPLE_IRP_COMPLETE_REQUESTS",
    0x004D: "NO_PAGES_AVAILABLE",
    0x0050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x0051: "REGISTRY_ERROR",
    0x005A: "CRITICAL_SERVICE_FAILED",
    0x0074: "BAD_SYSTEM_CONFIG_INFO",
    0x0076: "PROCESS_HAS_LOCKED_PAGES",
    0x0077: "KERNEL_STACK_INPAGE_ERROR",
    0x007A: "KERNEL_DATA_INPAGE_ERROR",
    0x007B: "INACCESSIBLE_BOOT_DEVICE",
    0x007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    0x009C: "MACHINE_CHECK_EXCEPTION",
    0x009F: "DRIVER_POWER_STATE_FAILURE",
    0x00A0: "INTERNAL_POWER_ERROR",
    0x00A2: "MEMORY_IMAGE_CORRUPT",
    0x00A5: "ACPI_BIOS_ERROR",
    0x00AB: "SESSION_HAS_VALID_POOL_ON_EXIT",
    0x00BE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0x00C1: "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
    0x00C2: "BAD_POOL_CALLER",
    0x00C4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x00C5: "DRIVER_CORRUPTED_EXPOOL",
    0x00CA: "PNP_DETECTED_FATAL_ERROR",
    0x00CB: "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS",
    0x00CE: "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
    0x00D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x00D5: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
    0x00D8: "DRIVER_USED_EXCESSIVE_PTES",
    0x00DE: "POOL_CORRUPTION_IN_FILE_AREA",
    0x00E1: "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
    0x00E2: "MANUALLY_INITIATED_CRASH",
    0x00E3: "RESOURCE_NOT_OWNED",
    0x00EA: "THREAD_STUCK_IN_DEVICE_DRIVER",
    0x00ED: "UNMOUNTABLE_BOOT_VOLUME",
    0x00EF: "CRITICAL_PROCESS_DIED",
    0x00F4: "CRITICAL_OBJECT_TERMINATION",
    0x00FC: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
    0x00FE: "BUGCODE_USB_DRIVER",
    0x0101: "CLOCK_WATCHDOG_TIMEOUT",
    0x0109: "CRITICAL_STRUCTURE_CORRUPTION",
    0x010D: "WDF_VIOLATION",
    0x010E: "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
    0x0116: "VIDEO_TDR_FAILURE",
    0x0117: "VIDEO_TDR_TIMEOUT_DETECTED",
    0x0119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
    0x0124: "WHEA_UNCORRECTABLE_ERROR",
    0x012B: "FAULTY_HARDWARE_CORRUPTED_PAGE",
    0x0133: "DPC_WATCHDOG_VIOLATION",
    0x0138: "GPIO_CONTROLLER_DRIVER_ERROR",
    0x0139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x013A: "KERNEL_MODE_HEAP_CORRUPTION",
    0x0141: "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE",
    0x0142: "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
    0x014F: "PDC_WATCHDOG_TIMEOUT",
    0x015E: "BUGCODE_NDIS_DRIVER_ERROR",
    0x018B: "SECURE_KERNEL_ERROR",
    0x0190: "WIN32K_CRITICAL_FAILURE",
    0x019C: "WIN32K_POWER_WATCHDOG_TIMEOUT",
    0x01A2: "WIN32K_CALLOUT_WATCHDOG_BUGCHECK",
    0x01C4: "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP",
    0x01C7: "STORE_DATA_STRUCTURE_CORRUPTION",
    0x01C8: "MANUALLY_INITIATED_POWER_BUTTON_HOLD",
    0x01CC: "INVALID_MDL_RANGE",
    0x1000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
    0x1000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
}

# NTSTATUS names for the MDMP "bugcheck-equivalent" exception code.
NTSTATUS_NAMES = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0x80000003: "STATUS_BREAKPOINT",
    0x80000004: "STATUS_SINGLE_STEP",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC000008E: "STATUS_FLOAT_DIVIDE_BY_ZERO",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "STATUS_INTEGER_OVERFLOW",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xE0434352: "CLR_EXCEPTION",
}

# Per-bugcheck-class param decoding: which params hold the faulting
# address (the memory operand) and the faulting PC, when the class has a
# documented layout. Anything not listed gets the generic
# exception.address -> context.rip fallback.
_FAULT_PARAM_MAP = {
    # {memory referenced, IRQL, access type, faulting instruction}
    0x000A: {"faulting_va": 0, "faulting_pc": 3},
    0x00D1: {"faulting_va": 0, "faulting_pc": 3},
    # {memory referenced, access type, faulting instruction, reserved}
    0x0050: {"faulting_va": 0, "faulting_pc": 2},
    0x00D5: {"faulting_va": 0, "faulting_pc": 2},
    # {exception code, address where exception occurred, exc record, ctx}
    0x001E: {"faulting_va": 1, "faulting_pc": 1},
    0x007E: {"faulting_va": 1, "faulting_pc": 1},
    0x008E: {"faulting_va": 1, "faulting_pc": 1},
    # {exception code, exception record addr, context addr, 0}
    0x003B: {"faulting_va": 1, "faulting_pc": 1},
    # {list/corruption type, related address, ...}
    0x0139: {"faulting_va": 1},
    # {failed object/process address, ...}
    0x00EF: {"faulting_va": 0},
    0x00F4: {"faulting_va": 1},
    # CLOCK_WATCHDOG: {PRCB addr of hung processor, ...} is the only
    # useful address; treat p1 as the interesting VA.
    0x0101: {"faulting_va": 1},
    # DPC_WATCHDOG: p4 is the hung DPC's stack/driver for type 0.
    0x0133: {"faulting_va": 3},
}

_SUSPEX_WATCHDOG_CODE = 0xE2


def bugcheck_name(code: int) -> str:
    return BUGCHECK_NAMES.get(code, "0x%x" % code)


def dump_type_name(code: int) -> str:
    return DUMP_TYPES.get(code, "unknown_0x%x" % code)


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _filetime_to_iso(ft: int) -> str | None:
    """Windows FILETIME (100ns since 1601-01-01) -> ISO-8601 UTC."""
    if not ft:
        return None
    import datetime as _dt
    try:
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
        ts = epoch + _dt.timedelta(microseconds=ft / 10)
        return ts.isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_to_epoch_ms(ft: int) -> int:
    if not ft:
        return 0
    # 116444736000000000 = FILETIME ticks between 1601 and 1970.
    return int((ft - 116444736000000000) // 10000)


def dump_epoch_ms(parsed: dict) -> int:
    """Crash time as unix epoch ms (0 when unknown) — for same-boot
    freshness checks against status().boot_epoch_ms."""
    return _filetime_to_epoch_ms(int(parsed.get("system_time_filetime") or 0))


def _decode_context64(buf: bytes) -> dict[str, Any] | None:
    """Decode an x64 CONTEXT out of the 3000-byte ContextRecord buffer.

    Returns None when the buffer is absent/filler — post-Vista dumps pad
    unused header space with the "PAGE" loop and pre-SP1 fields can be
    zeros, so the CONTEXT_AMD64 flag bit is the only honest check.
    """
    if len(buf) < _CTX_RIP + 8:
        return None
    flags = _u32(buf, _CTX_FLAGS)
    if not (flags & _CONTEXT_AMD64):
        return None
    gprs = {}
    for i, name in enumerate(("rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                            "rsi", "rdi", "r8", "r9", "r10", "r11",
                            "r12", "r13", "r14", "r15")):
        gprs[name] = _u64(buf, _CTX_RAX + i * 8)
    ctx: dict[str, Any] = {
        "arch": "x64",
        "context_flags": flags,
        "mxcsr": _u32(buf, _CTX_MXCSR),
        "eflags": _u32(buf, _CTX_EFLAGS),
        "seg_cs": _u16(buf, _CTX_SEGCS),
        "seg_ds": _u16(buf, _CTX_SEGCS + 2),
        "seg_es": _u16(buf, _CTX_SEGCS + 4),
        "seg_fs": _u16(buf, _CTX_SEGCS + 6),
        "seg_gs": _u16(buf, _CTX_SEGCS + 8),
        "seg_ss": _u16(buf, _CTX_SEGCS + 10),
        "dr0": _u64(buf, _CTX_DR0),
        "dr1": _u64(buf, _CTX_DR0 + 8),
        "dr2": _u64(buf, _CTX_DR0 + 0x10),
        "dr3": _u64(buf, _CTX_DR0 + 0x18),
        "dr6": _u64(buf, _CTX_DR0 + 0x20),
        "dr7": _u64(buf, _CTX_DR0 + 0x28),
        "rip": _u64(buf, _CTX_RIP),
    }
    ctx.update(gprs)
    return ctx


def _decode_exception64(buf: bytes) -> dict[str, Any] | None:
    """Decode the embedded EXCEPTION_RECORD64. Returns None for an empty
    record (code 0 and address 0 means "not populated", not a real
    exception)."""
    if len(buf) < _EXC_INFO:
        return None
    code = _u32(buf, _EXC_CODE)
    addr = _u64(buf, _EXC_ADDRESS)
    if not code and not addr:
        return None
    n = min(_u32(buf, _EXC_NUMPARAMS), 15)
    return {
        "code": code,
        "flags": _u32(buf, _EXC_FLAGS),
        "record": _u64(buf, _EXC_RECORD),
        "address": addr,
        "num_parameters": _u32(buf, _EXC_NUMPARAMS),
        "parameters": [_u64(buf, _EXC_INFO + i * 8) for i in range(n)],
    }


class _PhysReader:
    """Physical-address -> bytes for the kernel-dump body layouts.

    ``runs``  : [(base_pfn, page_count, file_offset)] — run-based bodies
                (DumpType FULL=1) where pages are packed in run order.
    ``bitmap``: (bitmap_bytes, data_start_file_offset) — PFN-indexed
                bodies (SUMMARY/BITMAP_*), bit i = PFN i present.
    """

    def __init__(self, fh, runs=None, bitmap=None, data_start=0):
        self._fh = fh
        self._runs = runs
        self._bitmap = bitmap
        self._data_start = data_start

    def _run_offset(self, pa: int) -> int | None:
        for base_pfn, page_count, file_off in self._runs or ():
            base = base_pfn * PAGE_SIZE
            if base <= pa < base + page_count * PAGE_SIZE:
                return file_off + (pa - base)
        return None

    def _bitmap_rank(self, pfn: int) -> int:
        """Number of set bits below ``pfn`` in the PFN bitmap."""
        bitmap = self._bitmap
        nbytes, rem = divmod(pfn, 8)
        count = 0
        for byte in bitmap[:nbytes]:
            count += bin(byte).count("1")
        if rem:
            count += bin(bitmap[nbytes] & ((1 << rem) - 1)).count("1")
        return count

    def pa_to_file(self, pa: int) -> int | None:
        if self._runs is not None:
            return self._run_offset(pa)
        if self._bitmap is not None:
            pfn = pa // PAGE_SIZE
            nbits = len(self._bitmap) * 8
            if pfn >= nbits:
                return None
            if not (self._bitmap[pfn // 8] >> (pfn % 8)) & 1:
                return None
            return self._data_start + self._bitmap_rank(pfn) * PAGE_SIZE
        return None

    def read(self, pa: int, n: int) -> bytes | None:
        off = self.pa_to_file(pa)
        if off is None or off < 0:
            return None
        self._fh.seek(off)
        data = self._fh.read(n)
        return data if len(data) == n else None

    def read_u64(self, pa: int) -> int | None:
        data = self.read(pa, 8)
        return _u64(data, 0) if data else None


def _vtop(phys: _PhysReader, dtb: int, va: int) -> int | None:
    """4-level x64 VA -> PA walk against the dump's stored pages."""
    if not dtb:
        return None
    cr3 = dtb & ~0xFFF
    masks = {
        4: 0x000FFFFFFFFFF000,   # entry points at next-level table
        3: 0x000FFFFFC0000000,   # 1 GiB page
        2: 0x000FFFFFFFE00000,   # 2 MiB page
        1: 0x000FFFFFFFFFF000,
    }
    e = phys.read_u64(cr3 + ((va >> 39) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    e = phys.read_u64((e & masks[4]) + ((va >> 30) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    if e & 0x80:  # PS — 1 GiB leaf
        return (e & masks[3]) + (va & 0x3FFFFFFF)
    e = phys.read_u64((e & masks[4]) + ((va >> 21) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    if e & 0x80:  # PS — 2 MiB leaf
        return (e & masks[2]) + (va & 0x1FFFFF)
    e = phys.read_u64((e & masks[4]) + ((va >> 12) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    return (e & masks[1]) + (va & 0xFFF)


def _stack_qwords(read_va, rsp: int, count: int = 32) -> list[dict[str, int]]:
    """qwords up the stack from ``rsp``; stops at the first unmapped gap."""
    out: list[dict[str, int]] = []
    va = rsp
    for _ in range(max(0, count)):
        data = read_va(va, 8)
        if data is None:
            break
        out.append({"va": va, "value": _u64(data, 0)})
        va += 8
    return out


def _phys_reader_from_header(fh, data: bytes, dump_type: int) -> _PhysReader | None:
    """Build the physical-memory reader matching the dump body layout."""
    if dump_type == 1:  # FULL — run-based pages right after the header
        num_runs = _u32(data, _OFF_PHYS_MEM)
        runs = []
        file_off = HEADER_SIZE_64
        for i in range(min(num_runs, 256)):
            base = _u64(data, _OFF_PHYS_MEM + 0x10 + i * 16)
            cnt = _u64(data, _OFF_PHYS_MEM + 0x18 + i * 16)
            runs.append((base, cnt, file_off))
            file_off += cnt * PAGE_SIZE
        return _PhysReader(fh, runs=runs)
    if dump_type in _BITMAP_DUMP_TYPES:
        fh.seek(HEADER_SIZE_64)
        sub = fh.read(_SUM_BITMAP)
        if len(sub) < _SUM_BITMAP:
            return None
        sig = bytes(sub[_SUM_SIGNATURE:_SUM_SIGNATURE + 4])
        if sig not in (b"SDMP", b"FDMP", b"DUMP"):
            return None
        header_size = _u32(sub, _SUM_HEADER_SIZE)
        bitmap_bits = _u32(sub, _SUM_BITMAP_SIZE)
        bitmap_len = (bitmap_bits + 7) // 8
        fh.seek(HEADER_SIZE_64 + _SUM_BITMAP)
        bitmap = fh.read(bitmap_len)
        if len(bitmap) != bitmap_len:
            return None
        data_start = header_size if header_size >= HEADER_SIZE_64 else \
            HEADER_SIZE_64 + _SUM_BITMAP + bitmap_len
        return _PhysReader(fh, bitmap=bitmap, data_start=data_start)
    return None


def _parse_kernel_dump(fh, size: int, path: str) -> dict[str, Any]:
    fh.seek(0)
    hdr = fh.read(HEADER_SIZE_64)
    if len(hdr) < HEADER_SIZE_64:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated DUMP_HEADER64 "
                         f"({len(hdr)} of {HEADER_SIZE_64} bytes)"}
    params = [_u64(hdr, _OFF_PARAMS + i * 8) for i in range(4)]
    code = _u32(hdr, _OFF_BUGCHECK)
    context = _decode_context64(hdr[_OFF_CONTEXT:_OFF_CONTEXT + 3000])
    exception = _decode_exception64(hdr[_OFF_EXCEPTION:_OFF_EXCEPTION + 152])
    dtb = _u64(hdr, _OFF_DTB)
    dump_type = _u32(hdr, _OFF_DUMP_TYPE)
    system_time = _u64(hdr, _OFF_SYSTEM_TIME)

    out: dict[str, Any] = {
        "ok": True,
        "format": "kernel_dump",
        "bugcheck": {"code": code, "name": bugcheck_name(code)},
        "params": params,
        "context": context,
        "exception": exception,
        "dtb": dtb,
        "kd_data_block": _u64(hdr, _OFF_KD_BLOCK) or None,
        "machine_image_type": _u32(hdr, _OFF_MACHINE),
        "num_processors": _u32(hdr, _OFF_NUMPROC),
        "ps_loaded_module_list": _u64(hdr, _OFF_PSLML) or None,
        "ps_active_process_head": _u64(hdr, _OFF_PSAPH) or None,
        "version_user": hdr[_OFF_VERSION_USER:_OFF_VERSION_USER + 32]
                        .split(b"\0", 1)[0].decode("utf-8", "replace"),
        "os_version": {"major": _u32(hdr, 0x08), "minor": _u32(hdr, 0x0C)},
        "dump_type": {"code": dump_type, "name": dump_type_name(dump_type)},
        "system_time_filetime": system_time,
        "system_time_iso": _filetime_to_iso(system_time),
        "comment": hdr[_OFF_COMMENT:_OFF_COMMENT + 128]
                   .split(b"\0", 1)[0].decode("utf-8", "replace"),
        "required_dump_space": _u64(hdr, _OFF_REQUIRED_SPACE),
        "system_uptime_100ns": _u64(hdr, _OFF_SYSTEM_UPTIME),
    }

    # faulting_va heuristic — class-specific param first, then the
    # exception record's faulting address, then rip.
    spec = _FAULT_PARAM_MAP.get(code, {})
    faulting_va = None
    if "faulting_va" in spec:
        faulting_va = params[spec["faulting_va"]]
    if not faulting_va and exception:
        faulting_va = exception.get("address") or None
    if not faulting_va and context:
        faulting_va = context.get("rip")
    out["faulting_va"] = faulting_va
    if "faulting_pc" in spec:
        out["faulting_pc"] = params[spec["faulting_pc"]]
    elif context:
        out["faulting_pc"] = context.get("rip")

    # suspex watchdog self-identification: the driver's DPC watchdog
    # bugchecks 0xE2 with params {id, deadline_us, last_kick_us, cookie}
    # (see driver/Watchdog.c). A user-initiated crash leaves them 0.
    if code == _SUSPEX_WATCHDOG_CODE and any(params):
        out["watchdog"] = {
            "id": params[0],
            "deadline_us": params[1],
            "last_kick_us": params[2],
            "cookie": params[3],
        }
        out["fired_by"] = "suspex_watchdog"

    # Stack qwords — how they're read depends on the body layout.
    stack: list[dict[str, int]] = []
    rsp = (context or {}).get("rsp") or 0
    if dump_type == 4 and size >= HEADER_SIZE_64 + 0x80:
        fh.seek(HEADER_SIZE_64)
        tri = fh.read(0x80)
        if len(tri) == 0x80:
            cs_off = _u32(tri, _TRI_CALLSTACK_OFFSET)
            cs_size = _u32(tri, _TRI_CALLSTACK_SIZE)
            top = _u64(tri, _TRI_TOP_OF_STACK)
            dp_addr = _u64(tri, _TRI_DATA_PAGE_ADDRESS)
            dp_off = _u32(tri, _TRI_DATA_PAGE_OFFSET)
            dp_size = _u32(tri, _TRI_DATA_PAGE_SIZE)
            out["triage"] = {
                "service_pack_build": _u32(tri, _TRI_SP_BUILD),
                "size_of_dump": _u32(tri, _TRI_SIZE_OF_DUMP),
                "callstack_offset": cs_off,
                "callstack_size": cs_size,
                "top_of_stack": top,
                "driver_list_offset": _u32(tri, _TRI_DRIVER_LIST_OFFSET),
                "driver_count": _u32(tri, _TRI_DRIVER_COUNT),
                "broken_driver_offset": _u32(tri, _TRI_BROKEN_DRIVER_OFFSET),
                "string_pool_offset": _u32(tri, _TRI_STRING_POOL_OFFSET),
                "string_pool_size": _u32(tri, _TRI_STRING_POOL_SIZE),
                "debugger_data_offset": _u32(tri, _TRI_DEBUGGER_DATA_OFFSET),
                "debugger_data_size": _u32(tri, _TRI_DEBUGGER_DATA_SIZE),
                "data_blocks_offset": _u32(tri, _TRI_DATA_BLOCKS_OFFSET),
                "data_blocks_count": _u32(tri, _TRI_DATA_BLOCKS_COUNT),
            }
            # KernBase from the embedded debugger-data block — the anchor
            # for offline nt-relative attribution when no live map exists.
            dd_off = _u32(tri, _TRI_DEBUGGER_DATA_OFFSET)
            dd_size = _u32(tri, _TRI_DEBUGGER_DATA_SIZE)
            if (dd_off and dd_size > _KD_DEBUGGER_KERNBASE + 8
                    and dd_off + dd_size <= size):
                fh.seek(dd_off)
                dd = fh.read(_KD_DEBUGGER_KERNBASE + 8)
                if len(dd) == _KD_DEBUGGER_KERNBASE + 8:
                    kb = _u64(dd, _KD_DEBUGGER_KERNBASE)
                    if kb >= 0xFFFF800000000000:
                        out["triage"]["kernbase"] = kb

            def read_va(va: int, n: int) -> bytes | None:
                # The saved callstack bytes cover VAs [TopOfStack,
                # TopOfStack + SizeOfCallStack): TopOfStack is the
                # capturing thread's Rsp (the stack grows down, so rsp is
                # the top of the in-use stack and the save runs upward
                # through the older frames). Pinned against real
                # minidumps: TopOfStack == context.rsp and stack[rsp]
                # decodes to a return address. An earlier reading of the
                # field as the region END (base = top - size) matched
                # nothing — that bug emptied stack_qwords for every
                # real triage dump.
                if cs_size and top <= va and va + n <= top + cs_size:
                    fh.seek(cs_off + (va - top))
                    data = fh.read(n)
                    return data if len(data) == n else None
                if dp_size and dp_addr <= va and va + n <= dp_addr + dp_size:
                    fh.seek(dp_off + (va - dp_addr))
                    data = fh.read(n)
                    return data if len(data) == n else None
                return None

            if rsp:
                stack = _stack_qwords(read_va, rsp)
            if not stack and top:
                # rsp below/outside the saved region — still walk what
                # was saved rather than returning nothing.
                stack = _stack_qwords(read_va, top)
    else:
        phys = _phys_reader_from_header(fh, hdr, dump_type)
        if phys is not None and rsp:
            def read_va(va: int, n: int) -> bytes | None:
                pa = _vtop(phys, dtb, va)
                return phys.read(pa, n) if pa is not None else None

            stack = _stack_qwords(read_va, rsp)
    out["stack_qwords"] = stack
    return out


def _parse_kernel_dump32(fh, size: int, path: str) -> dict[str, Any]:
    """Minimal 32-bit DUMP_HEADER parse — bugcheck + params only.

    The x86 header predates this codebase's scope (the lab is x64); the
    fixed early fields still decode so the caller gets the answer that
    matters instead of a bad_dump rejection.
    """
    fh.seek(0)
    hdr = fh.read(0x40)
    if len(hdr) < 0x3C:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated 32-bit DUMP_HEADER"}
    params = [_u32(hdr, 0x2C + i * 4) for i in range(4)]
    code = _u32(hdr, 0x28)
    out: dict[str, Any] = {
        "ok": True,
        "format": "kernel_dump32",
        "bugcheck": {"code": code, "name": bugcheck_name(code)},
        "params": params,
        "context": None,
        "exception": None,
        "dtb": _u32(hdr, 0x10),
        "kd_data_block": None,
        "stack_qwords": [],
        "note": "32-bit header: context/exception/stack not decoded",
    }
    spec = _FAULT_PARAM_MAP.get(code, {})
    out["faulting_va"] = (params[spec["faulting_va"]]
                          if "faulting_va" in spec else None)
    if code == _SUSPEX_WATCHDOG_CODE and any(params):
        out["watchdog"] = {
            "id": params[0], "deadline_us": params[1],
            "last_kick_us": params[2], "cookie": params[3],
        }
        out["fired_by"] = "suspex_watchdog"
    return out


# ---------------------------------------------------------------------------
# Triage stack + driver-list extraction (dump_manage action='stack').
#
# One call answers "what's on the stack and which module owns each
# return address" for a triage minidump — including stale-boot dumps
# where the live module map is useless. Everything comes from the dump
# file itself: the embedded callstack bytes, KernBase out of the
# debugger-data block, and the triage driver list (name/base/size).
# ---------------------------------------------------------------------------


def _read_pool_string(fh, file_offset: int, file_size: int) -> str:
    """Decode a u32-length-prefixed UTF-16 pool string at an absolute
    dump file offset (u32 char count, then count UTF-16-LE chars — a
    NUL terminator follows but is not counted). Empty string on any
    malformed input."""
    if not (0 <= file_offset < file_size - 4):
        return ""
    fh.seek(file_offset)
    raw = fh.read(4)
    if len(raw) < 4:
        return ""
    n = _u32(raw, 0)
    if n <= 0 or n > _MAX_DRV_NAME_CHARS:
        return ""
    if file_offset + 4 + n * 2 > file_size:
        return ""
    return fh.read(n * 2).decode("utf-16-le", "replace")


def _triage_driver_list(fh, size: int, dl_off: int, driver_count: int
                        ) -> tuple[list[dict[str, Any]], list[str]]:
    """Walk the embedded DUMP_DRIVER_ENTRY records. Returns
    ``(drivers, notes)`` — drivers carry name/base/size/timestamp/
    checksum; notes carry honest truncation reasons. Stops at the first
    entry whose base is not a kernel VA (stride drift guard)."""
    drivers: list[dict[str, Any]] = []
    notes: list[str] = []
    want = driver_count * _TRI_DRIVER_ENTRY_SIZE
    if dl_off <= 0 or dl_off + _TRI_DRIVER_ENTRY_SIZE > size:
        notes.append(f"driver list offset 0x{dl_off:x} outside file")
        return drivers, notes
    fh.seek(dl_off)
    blob = fh.read(min(want, size - dl_off))
    n_entries = len(blob) // _TRI_DRIVER_ENTRY_SIZE
    if n_entries < driver_count:
        notes.append(
            f"driver list truncated: {n_entries} of {driver_count} "
            "entries inside file")
    for i in range(min(driver_count, n_entries)):
        e = blob[i * _TRI_DRIVER_ENTRY_SIZE:(i + 1) * _TRI_DRIVER_ENTRY_SIZE]
        name_off = _u64(e, _TRI_DRV_NAME_OFFSET)
        base = _u64(e, _TRI_DRV_BASE)
        drv_size = _u64(e, _TRI_DRV_SIZE)
        if not base or base < 0xFFFF800000000000:
            notes.append(
                f"driver entry {i}: base 0x{base:x} is not a kernel VA "
                "— list walk stopped (format drift?)")
            break
        row: dict[str, Any] = {
            "name": _read_pool_string(fh, name_off, size),
            "base": base,
            "size": drv_size,
        }
        if i == 0 and not row["name"]:
            notes.append("driver entry 0 name undecodable — string pool "
                         "layout may have drifted")
        ts = e[_TRI_DRV_TIMESTAMP:_TRI_DRV_TIMESTAMP + 4]
        cs = e[_TRI_DRV_CHECKSUM:_TRI_DRV_CHECKSUM + 4]
        if len(ts) == 4 and len(cs) == 4:
            row["timestamp"] = _u32(ts, 0)
            row["checksum"] = _u32(cs, 0)
        drivers.append(row)
    return drivers, notes


def read_triage_stack(path: str | Path, max_frames: int = 256
                      ) -> dict[str, Any]:
    """Walk a kernel dump's saved stack and attribute every qword.

    Triage dumps (the ``C:\\Windows\\Minidump`` shape): walks the
    embedded callstack bytes end to end, pulls KernBase from the
    debugger-data block, parses the embedded driver list, and
    attributes each frame to its module — all offline, so stale-boot
    dumps still resolve. Full/bitmap dumps: walks up to ``max_frames``
    qwords from Rsp via the page tables stored in the dump; no driver
    list exists in those bodies (the live map or ``mem_rw modules``
    is the attribution path there).

    Never raises; ``{ok: False, kind: ...}`` on bad input.
    """
    p = Path(path)
    try:
        fsize = p.stat().st_size
    except OSError as exc:
        return {"ok": False, "kind": "not_found",
                "error": f"{path}: {exc}", "path": str(p)}
    try:
        fh = open(p, "rb")
    except OSError as exc:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: {exc}", "path": str(p)}
    with fh:
        fh.seek(0)
        magic = fh.read(8)
        if magic[:4] != PAGE_SIG:
            return {"ok": False, "kind": "bad_dump",
                    "error": f"{path}: not a kernel crash dump",
                    "path": str(p)}
        is_triage = magic[4:8] == VALID_64  # refined below via DumpType
        fh.seek(0)
        hdr = fh.read(HEADER_SIZE_64)
        if len(hdr) < HEADER_SIZE_64:
            return {"ok": False, "kind": "bad_dump",
                    "error": f"{path}: truncated DUMP_HEADER64",
                    "path": str(p)}
        dump_type = _u32(hdr, _OFF_DUMP_TYPE)
        is_triage = dump_type == 4
        context = _decode_context64(hdr[_OFF_CONTEXT:_OFF_CONTEXT + 3000])
        rsp = (context or {}).get("rsp") or 0
        dtb = _u64(hdr, _OFF_DTB)

        out: dict[str, Any] = {
            "ok": True,
            "path": str(p),
            "dump_type": {"code": dump_type,
                          "name": dump_type_name(dump_type)},
            "rsp": rsp,
            "system_time_filetime": _u64(hdr, _OFF_SYSTEM_TIME),
            "notes": [],
        }
        frames: list[dict[str, int]] = []
        drivers: list[dict[str, Any]] = []
        kernbase = None

        if is_triage:
            if fsize < HEADER_SIZE_64 + 0x80:
                out["notes"].append("file too small for a triage body")
            else:
                fh.seek(HEADER_SIZE_64)
                tri = fh.read(0x80)
                cs_off = _u32(tri, _TRI_CALLSTACK_OFFSET)
                cs_size = _u32(tri, _TRI_CALLSTACK_SIZE)
                top = _u64(tri, _TRI_TOP_OF_STACK)
                out["top_of_stack"] = top
                out["callstack"] = {"file_offset": cs_off, "size": cs_size}
                dd_off = _u32(tri, _TRI_DEBUGGER_DATA_OFFSET)
                dd_size = _u32(tri, _TRI_DEBUGGER_DATA_SIZE)
                if (dd_off and dd_size > _KD_DEBUGGER_KERNBASE + 8
                        and dd_off + dd_size <= fsize):
                    fh.seek(dd_off)
                    dd = fh.read(_KD_DEBUGGER_KERNBASE + 8)
                    if len(dd) == _KD_DEBUGGER_KERNBASE + 8:
                        kb = _u64(dd, _KD_DEBUGGER_KERNBASE)
                        if kb >= 0xFFFF800000000000:
                            kernbase = kb
                            out["kernbase_source"] = "debugger_data+0x18"
                drivers, dnotes = _triage_driver_list(
                    fh, fsize, _u32(tri, _TRI_DRIVER_LIST_OFFSET),
                    _u32(tri, _TRI_DRIVER_COUNT))
                out["notes"].extend(dnotes)
                if not cs_size:
                    out["notes"].append("no callstack bytes saved")
                elif not (0 < cs_off and cs_off + cs_size <= fsize):
                    out["notes"].append(
                        f"callstack region 0x{cs_off:x}+0x{cs_size:x} "
                        "outside file")
                else:
                    fh.seek(cs_off)
                    blob = fh.read(cs_size)
                    va = top
                    for off in range(0, len(blob) - 7, 8):
                        frames.append({"va": va, "value": _u64(blob, off)})
                        va += 8
        else:
            phys = _phys_reader_from_header(fh, hdr, dump_type)
            if phys is None:
                out["notes"].append(
                    "dump body has no page data this parser can read")
            elif not rsp:
                out["notes"].append("context has no Rsp")
            else:
                def read_va(v: int, n: int) -> bytes | None:
                    pa = _vtop(phys, dtb, v)
                    return phys.read(pa, n) if pa is not None else None
                va = rsp
                for _ in range(max(0, max_frames)):
                    data = read_va(va, 8)
                    if data is None:
                        break
                    frames.append({"va": va, "value": _u64(data, 0)})
                    va += 8

        # Offline attribution against the embedded driver list first —
        # this is what makes stale-boot triage dumps usable.
        for q in frames:
            val = q["value"]
            if not (0xFFFF800000000000 <= val < 0xFFFFF90000000000):
                q["text"] = f"0x{val:016x}"
                q["attribution"] = "data"
                continue
            hit = None
            for d in drivers:
                b = int(d.get("base") or 0)
                s = int(d.get("size") or 0)
                if b and s and b <= val < b + s:
                    hit = (d, b, s)
                    break
            if kernbase and hit is None and kernbase <= val < kernbase + 0x10000000:
                q["module"] = "nt"
                q["offset"] = val - kernbase
                q["text"] = f"nt+0x{val - kernbase:x}"
                q["attribution"] = "kernbase_range"
                continue
            if hit is not None:
                d, b, _s = hit
                name = str(d.get("name") or "?")
                name = name.replace("/", "\\").split("\\")[-1]
                q["module"] = name
                q["offset"] = val - b
                q["text"] = f"{name}+0x{val - b:x}"
                q["attribution"] = "driver_list"
            else:
                q["text"] = f"0x{val:016x}"
                q["attribution"] = "unresolved"

        out["kernbase"] = kernbase
        out["frames_total"] = len(frames)
        out["frames"] = frames[:max(0, max_frames)]
        out["drivers"] = drivers
        out["driver_count"] = len(drivers)
        return out


# ---------------------------------------------------------------------------
# MDMP (usermode minidump) — minimal: header -> ExceptionStream (+ the
# memory-list streams for stack reads).
# ---------------------------------------------------------------------------

_MDMP_EXCEPTION_STREAM = 6
_MDMP_MEMORY_LIST_STREAM = 4
_MDMP_MEMORY64_LIST_STREAM = 9


def _mdmp_exception(buf: bytes) -> dict[str, Any] | None:
    if len(buf) < 4 + 4 + 152 + 8:
        return None
    exc_off = 8  # past ThreadId + alignment
    code = _u32(buf, exc_off)
    n = min(_u32(buf, exc_off + 0x18), 15)
    loc_off = exc_off + 152
    return {
        "thread_id": _u32(buf, 0),
        "code": code,
        "flags": _u32(buf, exc_off + 0x04),
        "record": _u64(buf, exc_off + 0x08),
        "address": _u64(buf, exc_off + 0x10),
        "num_parameters": _u32(buf, exc_off + 0x18),
        "parameters": [_u64(buf, exc_off + 0x20 + i * 8) for i in range(n)],
        "context_rva": _u32(buf, loc_off + 4),
        "context_size": _u32(buf, loc_off),
    }


def _parse_mdmp(fh, size: int, path: str) -> dict[str, Any]:
    fh.seek(0)
    hdr = fh.read(32)
    if len(hdr) < 32:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated MINIDUMP_HEADER"}
    _sig, _ver, nstreams, dir_rva, _cksum, _tstamp, _flags = \
        struct.unpack("<IIIIIIQ", hdr)
    if nstreams > 4096 or dir_rva >= size:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: implausible stream directory "
                         f"(nstreams={nstreams}, rva=0x{dir_rva:x})"}
    fh.seek(dir_rva)
    streams: dict[int, tuple[int, int]] = {}
    for _ in range(nstreams):
        entry = fh.read(12)
        if len(entry) < 12:
            break
        stype, dsize, rva = struct.unpack("<III", entry)
        if rva + dsize <= size:
            streams.setdefault(stype, (rva, dsize))

    exc = None
    context = None
    if _MDMP_EXCEPTION_STREAM in streams:
        rva, dsize = streams[_MDMP_EXCEPTION_STREAM]
        fh.seek(rva)
        exc = _mdmp_exception(fh.read(dsize))
        if exc is not None:
            ctx_rva = exc.pop("context_rva", 0)
            ctx_size = exc.pop("context_size", 0)
            if ctx_rva and ctx_size and ctx_rva + ctx_size <= size:
                fh.seek(ctx_rva)
                context = _decode_context64(fh.read(ctx_size))

    # VA -> file ranges from the memory-list streams (for stack reads).
    ranges: list[tuple[int, int, int]] = []  # (va, size, file_off)
    if _MDMP_MEMORY_LIST_STREAM in streams:
        rva, dsize = streams[_MDMP_MEMORY_LIST_STREAM]
        fh.seek(rva)
        blob = fh.read(dsize)
        if len(blob) >= 4:
            count = _u32(blob, 0)
            off = 4
            for _i in range(count):
                if off + 16 > len(blob):
                    break
                va = _u64(blob, off)
                dsz = _u32(blob, off + 8)
                drva = _u32(blob, off + 12)
                ranges.append((va, dsz, drva))
                off += 16
    if _MDMP_MEMORY64_LIST_STREAM in streams:
        rva, dsize = streams[_MDMP_MEMORY64_LIST_STREAM]
        fh.seek(rva)
        blob = fh.read(dsize)
        if len(blob) >= 16:
            count = _u64(blob, 0)
            base_rva = _u64(blob, 8)
            off = 16
            cur = base_rva
            for _i in range(count):
                if off + 16 > len(blob):
                    break
                va = _u64(blob, off)
                dsz = _u64(blob, off + 8)
                ranges.append((va, dsz, cur))
                cur += dsz
                off += 16

    def read_va(va: int, n: int) -> bytes | None:
        for base, rsz, roff in ranges:
            if base <= va and va + n <= base + rsz:
                fh.seek(roff + (va - base))
                data = fh.read(n)
                return data if len(data) == n else None
        return None

    stack = _stack_qwords(read_va, (context or {}).get("rsp") or 0)

    code = (exc or {}).get("code") or 0
    params = ((exc or {}).get("parameters") or [])[:4]
    params += [0] * (4 - len(params))
    out: dict[str, Any] = {
        "ok": True,
        "format": "mdmp",
        "bugcheck": {"code": code,
                     "name": NTSTATUS_NAMES.get(code, "0x%08x" % code)},
        "params": params,
        "context": context,
        "exception": exc,
        "dtb": None,
        "kd_data_block": None,
        "faulting_va": (exc or {}).get("address"),
        "stack_qwords": stack,
        "note": "usermode minidump: exception record stands in for "
                "the bugcheck fields",
    }
    return out


def parse_dump(path: str | Path) -> dict[str, Any]:
    """Parse a crash dump into the stable WP1 shape (module docstring).

    Never raises: failures come back as ``{ok: False, kind: ...}`` —
    ``not_found`` for a missing file, ``bad_dump`` for unrecognized or
    truncated content. Reads are lazy/random-access so a multi-GB
    MEMORY.DMP doesn't get slurped for a header answer.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        return {"ok": False, "kind": "not_found",
                "error": f"{path}: {exc}", "path": str(p)}
    try:
        with open(p, "rb") as fh:
            head = fh.read(8)
            if head[:4] == PAGE_SIG and head[4:8] == VALID_64:
                out = _parse_kernel_dump(fh, size, str(p))
            elif head[:4] == PAGE_SIG and head[4:8] == VALID_32:
                out = _parse_kernel_dump32(fh, size, str(p))
            elif head[:4] == MDMP_SIG:
                out = _parse_mdmp(fh, size, str(p))
            else:
                return {"ok": False, "kind": "bad_dump",
                        "error": f"{path}: not a crash dump "
                                 f"(magic {head!r})",
                        "path": str(p)}
    except OSError as exc:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: {exc}", "path": str(p)}
    out["size"] = size
    out["path"] = str(p)
    return out


def sig_check(head: bytes) -> str | None:
    """Signature sniff for a probe buffer (first 8 bytes). Returns the
    format tag or None — used by the ``latest`` header probe."""
    if head[:4] == PAGE_SIG and head[4:8] in (VALID_64, VALID_32):
        return "kernel_dump"
    if head[:4] == MDMP_SIG:
        return "mdmp"
    return None


async def resolve_va(ctx, c, va: int, *, kernel: bool = True,
                     pid: int = 0) -> dict[str, Any] | None:
    """VA -> ``{module, offset, base, text, symbol?}`` against the live
    target's module map, with best-effort PDB symbolization.

    Deliberately a second copy of mem_rw ``resolve``'s ~15-line module
    walk — mem.py is owned by WP2, so WP1 carries its own per _shared.md.
    Returns None when the VA falls outside every known module (or the
    module list can't be fetched).
    """
    try:
        mods = await c.mem_modules(pid, kernel)
    except Exception:
        return None
    hit: tuple[dict, int, int] | None = None
    for m in mods:
        try:
            base_i = int(m.get("base") or 0)
            size_i = int(m.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if base_i and base_i <= va < base_i + size_i:
            hit = (m, base_i, size_i)
            break
        if base_i > va:
            break
    if hit is None:
        return None
    m, base_i, size_i = hit
    off = va - base_i
    name = str(m.get("name") or "?")
    row: dict[str, Any] = {
        "va": va, "module": name, "path": m.get("path"),
        "base": base_i, "offset": off, "module_size": size_i,
        "text": f"{name}+0x{off:x}",
    }
    # Symbolization is gravy: _resolve_image needs a local copy of the
    # module (dumped/ingested), dbghelp needs the PDB — either failing is
    # silent, the module+offset text stands.
    try:
        from . import symbols as _sym
        from .mcp.tools.symbols import _resolve_image
        img, _img_name = _resolve_image(ctx, name, "")
        if img:
            cfg = ctx.cfg
            pdb_cache = (str(cfg.pdb_cache_dir())
                         if hasattr(cfg, "pdb_cache_dir")
                         else str(getattr(getattr(cfg, "artifacts", None),
                                          "pdb_cache", "") or ""))
            symcfg = getattr(cfg, "symbols", None)
            hit2 = await asyncio.to_thread(
                _sym.lookup_rva, img, off, pdb_cache,
                getattr(symcfg, "allow_download", True),
                getattr(symcfg, "servers", None) or None)
            if isinstance(hit2, dict) and hit2.get("found"):
                row["symbol"] = hit2["name"]
                row["symbol_rva"] = hit2.get("rva")
                disp = int(hit2.get("displacement") or 0)
                row["symbol_disp"] = disp
                row["text"] = f"{name}!{hit2['name']}+0x{disp:x}"
    except Exception:
        pass
    return row
