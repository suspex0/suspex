"""Minimal PE64 fixture builder — synthesizes parseable images in-test.

Not a general PE emitter: enough structure for the analysis passes
(imports, exports, .pdata, code bytes) without depending on a real binary
in the repo. Section layout: headers at 0, .text at RVA 0x1000, .rdata at
0x2000, .idata (imports) at 0x3000 — each 0x200 file bytes, file-aligned.
"""

from __future__ import annotations

import struct

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
IDATA_RVA = 0x3000
SEC_FILE = 0x200
SEC_RAW = {TEXT_RVA: 0x200, RDATA_RVA: 0x400, IDATA_RVA: 0x600}
CHARS = {TEXT_RVA: 0x60000020, RDATA_RVA: 0x40000040, IDATA_RVA: 0x40000040}


def _pad(b: bytearray, size: int) -> bytearray:
    if len(b) < size:
        b += b"\0" * (size - len(b))
    return b


def build_pe(*, code: bytes = b"\xC3", entry_rva: int = TEXT_RVA,
             imports: dict[str, list[str]] | None = None,
             exports: dict[str, int] | None = None,
             subsystem: int = 3,
             dll_chars: int = 0x8160,
             strings: list[tuple[int, bytes]] | None = None,
             pdata: list[tuple[int, int]] | None = None) -> bytes:
    """Build a PE64. *code* lands at .text start; *imports* is
    {dll: [names]}; *exports* {name: rva}; *pdata* [(begin,end) rv];
    *strings* [(rdata_rva_offset, bytes)].
    """
    img = bytearray(0x200 + 3 * SEC_FILE)
    # --- DOS header ---
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    nt = 0x80
    img[nt:nt + 4] = b"PE\0\0"
    # --- COFF: machine 8664, 3 sections, characteristics ---
    struct.pack_into("<HHIIIHH", img, nt + 4,
                     0x8664, 3, 0x5E2A5B00, 0, 0, 0xF0, 0x2022)
    opt = nt + 24
    struct.pack_into("<H", img, opt, 0x20B)          # PE32+
    img[opt + 16] = 0  # linker
    struct.pack_into("<I", img, opt + 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<I", img, opt + 20, TEXT_RVA)   # BaseOfCode
    struct.pack_into("<Q", img, opt + 24, IMAGE_BASE)
    struct.pack_into("<II", img, opt + 32, 0x1000, SEC_FILE)
    struct.pack_into("<HHHHHH", img, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", img, opt + 56, 0x4000)     # SizeOfImage
    struct.pack_into("<I", img, opt + 60, 0x200)      # SizeOfHeaders
    struct.pack_into("<H", img, opt + 68, subsystem)
    struct.pack_into("<H", img, opt + 70, dll_chars)
    struct.pack_into("<QQQQII", img, opt + 72,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dd = opt + 112
    # --- section headers ---
    sec = opt + 0xF0
    for i, (name, rva) in enumerate(((b".text", TEXT_RVA),
                                    (b".rdata", RDATA_RVA),
                                    (b".idata", IDATA_RVA))):
        off = sec + i * 40
        img[off:off + 8] = name.ljust(8, b"\0")
        # vsize=0x200, va=rva, raw_size=0x200, raw_off=file offset
        struct.pack_into("<IIIIIIHHI", img, off + 8,
                         SEC_FILE, rva, SEC_FILE, SEC_RAW[rva],
                         0, 0, 0, 0, CHARS[rva])
    # --- .text ---
    img[SEC_RAW[TEXT_RVA]:SEC_RAW[TEXT_RVA] + len(code)] = code
    # --- .rdata content ---
    for off, blob in (strings or []):
        img[SEC_RAW[RDATA_RVA] + off:
            SEC_RAW[RDATA_RVA] + off + len(blob)] = blob
    # --- .pdata (exception dir index 3) ---
    if pdata:
        for i, (beg, end) in enumerate(pdata):
            struct.pack_into("<III", img,
                             SEC_RAW[RDATA_RVA] + 0x100 + i * 12,
                             beg, end, 0)
        struct.pack_into("<II", img, dd + 3 * 8, RDATA_RVA + 0x100,
                         len(pdata) * 12)
    # --- imports (index 1 + delay index 13 untouched) ---
    if imports:
        idata = SEC_RAW[IDATA_RVA]
        ndll = len(imports)
        # IMAGE_IMPORT_DESCRIPTORs at 0; per-DLL: name, ILT, IAT, then
        # hint/name records — reserve all fixed-size areas first.
        cur = idata + (ndll + 1) * 20
        desc_i = 0
        for dll, names in imports.items():
            cur = (cur + 7) & ~7
            dll_rva_off = cur - idata
            img[cur:cur + len(dll) + 1] = dll.encode() + b"\0"
            cur += len(dll) + 1
            cur = (cur + 7) & ~7
            ilt_off = cur - idata                       # thunk array 1
            iat_off = ilt_off + (len(names) + 1) * 8    # thunk array 2
            cur = idata + iat_off + (len(names) + 1) * 8
            for i, nm in enumerate(names):
                cur = (cur + 7) & ~7
                hint_name = cur - idata
                struct.pack_into("<H", img, cur, 0)
                img[cur + 2:cur + 3 + len(nm)] = nm.encode() + b"\0"
                cur += 2 + len(nm) + 1
                struct.pack_into(
                    "<Q", img, idata + ilt_off + i * 8,
                    IDATA_RVA + hint_name)
                struct.pack_into(
                    "<Q", img, idata + iat_off + i * 8,
                    IDATA_RVA + hint_name)
            struct.pack_into(
                "<IIIII", img, idata + desc_i * 20,
                IDATA_RVA + ilt_off, 0, 0, IDATA_RVA + dll_rva_off,
                IDATA_RVA + iat_off)
            desc_i += 1
        struct.pack_into("<II", img, dd + 8, IDATA_RVA, ndll * 20 + 20)
    # --- exports (index 0) ---
    if exports:
        exp_off = SEC_RAW[IDATA_RVA] + 0x180
        names = sorted(exports)
        n = len(names)
        # ExportDirectoryTable(40) + EAT(n*4) + ords(n*2) + names(n*4)
        eat = exp_off + 40
        ords = eat + n * 4
        nptr = ords + n * 2
        cur = nptr + n * 4
        name_rvas = []
        for i, nm in enumerate(names):
            struct.pack_into("<I", img, eat + i * 4, exports[nm])
            struct.pack_into("<H", img, ords + i * 2, i)
            name_rva = IDATA_RVA + (cur - SEC_RAW[IDATA_RVA])
            struct.pack_into("<I", img, nptr + i * 4, name_rva)
            img[cur:cur + len(nm) + 1] = nm.encode() + b"\0"
            cur += len(nm) + 1
            name_rvas.append(name_rva)
        struct.pack_into("<IIHHIIIIIII", img, exp_off,
                         0, 0x5E2A5B00, 0, 0, IDATA_RVA + 0x180 + 40 + n * 6,
                         1, n, n, IDATA_RVA + (eat - SEC_RAW[IDATA_RVA]),
                         IDATA_RVA + (nptr - SEC_RAW[IDATA_RVA]),
                         IDATA_RVA + (ords - SEC_RAW[IDATA_RVA]))
        struct.pack_into("<II", img, dd, IDATA_RVA + 0x180,
                         cur - exp_off)
    return bytes(img)
