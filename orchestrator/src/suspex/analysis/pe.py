"""Hand-rolled PE parser over a bytes buffer — the ``bin_manage`` substrate.

Parses both layouts:

* ``layout="file"``  — raw section bytes at ``PointerToRawData`` offsets
  (what ``dump_module`` / ``moddump`` artifacts look like on disk).
* ``layout="image"`` — as-mapped image where RVA == buffer offset (what a
  live ``mem_rw read`` of a module base produces).

Every table walk is bounds-checked against the buffer and count-capped —
a hostile or corrupt header must not grow loops unboundedly. Raises
:class:`PeError` with a ``kind`` slug on structural failure; individual
directory parse failures degrade to empty lists, never raise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .entropy import shannon

MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 512
MAX_IMPORT_THUNKS = 65536
MAX_EXPORTS = 65536
MAX_PDATA_ENTRIES = 262144
MAX_RELOC_BLOCKS = 4096
MAX_DEBUG_ENTRIES = 256

MACHINE_NAMES = {
    0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0x01C4: "armv7",
    0xAA64: "aarch64", 0x0200: "ia64", 0x5032: "riscv32",
    0x5064: "riscv64", 0x5128: "riscv128",
}

SUBSYSTEM_NAMES = {
    1: "native", 2: "windows_gui", 3: "windows_cui", 7: "posix_cui",
    9: "windows_ce_gui", 10: "efi_application", 11: "efi_boot_service_driver",
    12: "efi_runtime_driver", 13: "efi_rom", 14: "xbox",
    16: "windows_boot_application",
}

# Data-directory indices.
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_CERT, DIR_RELOC, \
    DIR_DEBUG, DIR_ARCH, DIR_GLOBALPTR, DIR_TLS, DIR_LOADCFG, \
    DIR_BOUNDIMP, DIR_IAT, DIR_DELAYIMP, DIR_COM, _RESERVED = range(16)

SEC_X = 0x20000000
SEC_R = 0x40000000
SEC_W = 0x80000000


class PeError(Exception):
    """Structural parse failure. Carries a ``kind`` for the envelope."""

    def __init__(self, kind: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint


@dataclass
class Section:
    name: str
    va: int          # RVA of the mapped section
    vsize: int       # virtual size
    raw_off: int     # file offset (layout="file") — 0 for image layout
    raw_size: int
    characteristics: int

    @property
    def exec(self) -> bool:
        return bool(self.characteristics & SEC_X)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & SEC_R)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SEC_W)


@dataclass
class PeImage:
    """Parsed PE with a VA↔offset map over the source buffer."""

    data: bytes
    layout: str  # "file" | "image"
    machine: int
    pe32_plus: bool
    image_base: int
    entry_rva: int
    size_of_image: int
    subsystem: int
    dll_characteristics: int
    characteristics: int
    timestamp: int
    checksum: int
    sections: list[Section]
    directories: list[tuple[int, int]]  # (rva_or_off, size) per index
    e_lfanew: int
    overlay_off: int = 0
    overlay_size: int = 0
    imports: list[dict] = field(default_factory=list)   # populated lazily
    exports: list[dict] = field(default_factory=list)
    exports_dll_name: str = ""
    pdata: list[dict] = field(default_factory=list)
    load_config: dict = field(default_factory=dict)
    debug: list[dict] = field(default_factory=list)
    cert_off: int = 0
    cert_size: int = 0
    reloc_present: bool = False
    reloc_blocks: int = 0

    # ------------------------------------------------------------- mapping --
    def rva_to_off(self, rva: int) -> int | None:
        """RVA → buffer offset, or None when unmapped in this layout."""
        if rva < 0:
            return None
        if self.layout == "image":
            return rva if 0 <= rva < len(self.data) else None
        # file layout: headers live at their file offsets; sections map
        # via raw_off + (rva - va).
        hdr_end = self.e_lfanew + 4 + 20 + (self._opt_size or 0)
        if rva < hdr_end + (self.sections[0].va if self.sections else 0):
            # inside headers region — file offset == rva while within
            # SizeOfHeaders; be permissive.
            if rva < len(self.data):
                return rva
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.va <= rva < s.va + span:
                off = s.raw_off + (rva - s.va)
                if 0 <= off < len(self.data):
                    return off
                return None
        return None

    def va_to_off(self, va: int) -> int | None:
        if va < self.image_base:
            return None
        return self.rva_to_off(va - self.image_base)

    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_off(rva)
        if off is None:
            return b""
        return self.data[off:off + size]

    def read_va(self, va: int, size: int) -> bytes:
        return self.read_rva(va - self.image_base, size)

    def off_to_va(self, off: int) -> int:
        """Buffer offset → VA (image_base + rva), or -1 when unmapped."""
        if self.layout == "image":
            return self.image_base + off
        hdr_end = self.e_lfanew + 4 + 20 + (self._opt_size or 0)
        if off < hdr_end:
            return self.image_base + off
        for s in self.sections:
            if s.raw_off <= off < s.raw_off + s.raw_size:
                return self.image_base + s.va + (off - s.raw_off)
        return -1

    def is_exec_rva(self, rva: int) -> bool:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s.exec
        return rva < (self.sections[0].va if self.sections else 0)

    # ------------------------------------------------------------- helpers --
    _opt_size: int = 0

    def cstr_rva(self, rva: int, cap: int = 260) -> str:
        off = self.rva_to_off(rva)
        if off is None:
            return ""
        end = self.data.find(b"\0", off, off + cap)
        if end < 0:
            end = min(off + cap, len(self.data))
        try:
            return self.data[off:end].decode("ascii", "replace")
        except Exception:
            return ""

    def u32_rva(self, rva: int) -> int:
        b = self.read_rva(rva, 4)
        return struct.unpack_from("<I", b)[0] if len(b) == 4 else 0


def header_extent(hdr: bytes) -> int:
    """Bytes needed at the image base to cover DOS+NT headers + the full
    section table — the minimum read for a headers-only parse.

    Returns 0 when *hdr* is too short to locate the NT headers at all
    (caller should grow the read and retry); otherwise the byte count to
    fetch from the module base, capped sensibly."""
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return 0
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if e_lfanew + 0x18 > len(hdr):
        return 0x10000
    nsec = struct.unpack_from("<H", hdr, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", hdr, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    soh = 0
    if opt + 0x64 <= len(hdr):
        # SizeOfHeaders sits at optional+0x3C on both PE32 and PE32+.
        soh = struct.unpack_from("<I", hdr, opt + 60)[0]
    sec_end = opt + opt_size + min(nsec, MAX_SECTIONS) * 40
    return max(soh, sec_end)


def parse(data: bytes, *, layout: str = "file") -> PeImage:
    """Parse *data* as a PE. ``layout`` selects file vs image offset math."""
    n = len(data)
    if n < 0x40 or data[0:2] != b"MZ":
        raise PeError("bad_magic", "not a PE (missing MZ)",
                      hint="supply a PE32/PE32+ image or dump")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > n or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PeError("bad_magic", "bad PE signature at e_lfanew",
                      hint="e_lfanew out of bounds or corrupt")
    coff = e_lfanew + 4
    machine, nsec, timestamp, _symtab, _nsyms, opt_size, characteristics = \
        struct.unpack_from("<HHIIIHH", data, coff)
    if nsec > MAX_SECTIONS:
        raise PeError("overflow", f"section count {nsec} exceeds cap",
                      hint="corrupt COFF header")
    opt = coff + 20
    if opt + opt_size > n:
        raise PeError("truncated", "optional header exceeds buffer")
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = magic == 0x20B
    if not pe32p and magic != 0x10B:
        raise PeError("bad_magic", f"unknown optional magic {magic:#x}")
    # PE32+ drops BaseOfData, so ImageBase sits at +24 (Q); PE32 has it
    # at +28 (I) after the extra dword.
    image_base = struct.unpack_from(
        "<Q" if pe32p else "<I", data, opt + (24 if pe32p else 28))[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    # Subsystem/DllCharacteristics sit at +68/+70 in BOTH PE32 and PE32+
    # (only the trailing stack/heap reserve/commit fields change width).
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
    checksum = struct.unpack_from("<I", data, opt + 64)[0]
    n_dirs = struct.unpack_from(
        "<I", data, opt + (108 if pe32p else 92))[0]
    dir_base = opt + (112 if pe32p else 96)
    directories: list[tuple[int, int]] = []
    for i in range(min(n_dirs, 16)):
        off = dir_base + i * 8
        if off + 8 <= n:
            directories.append(struct.unpack_from("<II", data, off))
        else:
            directories.append((0, 0))
    while len(directories) < 16:
        directories.append((0, 0))

    sec_table = opt + opt_size
    sections: list[Section] = []
    for i in range(nsec):
        s = sec_table + i * 40
        if s + 40 > n:
            break
        name = data[s:s + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, s + 8)
        chars = struct.unpack_from("<I", data, s + 36)[0]
        sections.append(Section(name=name, va=va, vsize=vsize,
                                raw_off=raw_off, raw_size=raw_size,
                                characteristics=chars))

    img = PeImage(data=data, layout=layout, machine=machine,
                  pe32_plus=pe32p, image_base=image_base,
                  entry_rva=entry_rva, size_of_image=size_of_image,
                  subsystem=subsystem, dll_characteristics=dll_chars,
                  characteristics=characteristics, timestamp=timestamp,
                  checksum=checksum, sections=sections,
                  directories=directories, e_lfanew=e_lfanew)
    img._opt_size = opt_size

    # Overlay: bytes past the last mapped section's raw end (cert table
    # excluded so signed binaries don't read as packed).
    if layout == "file" and sections:
        last_end = max(s.raw_off + s.raw_size for s in sections)
        cert_off, cert_size = directories[DIR_CERT]
        if cert_size:
            last_end = max(last_end, cert_off + cert_size)
        if n > last_end:
            img.overlay_off = last_end
            img.overlay_size = n - last_end
    img.cert_off, img.cert_size = directories[DIR_CERT]

    _parse_directories(img)
    return img


# ---------------------------------------------------------------------------
# Directory walks — each is individually guarded so one corrupt directory
# cannot sink the parse.
# ---------------------------------------------------------------------------

def _parse_directories(img: PeImage) -> None:
    for fn in (_parse_imports, _parse_exports, _parse_pdata,
               _parse_load_config, _parse_debug, _parse_relocs):
        try:
            fn(img)
        except Exception:
            continue


def _walk_thunks(img: PeImage, thunk_table: int, iat: int) -> list[dict]:
    """Walk one import thunk table → [{name|ordinal, thunk_rva}]."""
    entries: list[dict] = []
    w = 8 if img.pe32_plus else 4
    ordinal_flag = 0x8000000000000000 if img.pe32_plus else 0x80000000
    for j in range(MAX_IMPORT_THUNKS):
        tb = img.read_rva(thunk_table + j * w, w)
        if len(tb) < w:
            break
        val = struct.unpack_from("<Q" if w == 8 else "<I", tb)[0]
        if val == 0:
            break
        slot_rva = iat + j * w
        if val & ordinal_flag:
            entries.append({"ordinal": val & 0xFFFF, "name": None,
                            "thunk_rva": slot_rva})
        else:
            entries.append({"ordinal": None,
                            "name": img.cstr_rva(val + 2),  # skip hint word
                            "thunk_rva": slot_rva})
    return entries


def _parse_imports(img: PeImage) -> None:
    """Regular imports (20-byte IMAGE_IMPORT_DESCRIPTOR) + delay-load
    imports (32-byte IMAGE_DELAYLOAD_DESCRIPTOR)."""
    rva, _size = img.directories[DIR_IMPORT]
    if rva:
        for i in range(MAX_IMPORT_DLLS):
            desc = img.read_rva(rva + i * 20, 20)
            if len(desc) < 20:
                break
            ilt, _ts, _fwd, name_rva, iat = \
                struct.unpack_from("<IIIII", desc)
            if not (ilt or name_rva or iat):
                break
            dll_name = img.cstr_rva(name_rva) or f"<unnamed-{i}>"
            entries = _walk_thunks(img, ilt or iat, iat)
            img.imports.append({"dll": dll_name, "delayed": False,
                                "entries": entries})
    drva, _dsize = img.directories[DIR_DELAYIMP]
    if drva:
        _parse_delay_imports(img, drva)


def _parse_delay_imports(img: PeImage, rva: int) -> None:
    for i in range(MAX_IMPORT_DLLS):
        desc = img.read_rva(rva + i * 32, 32)
        if len(desc) < 32:
            break
        (_attrs, name_rva, _hmod, iat, ilt, _bound, _unload) = \
            struct.unpack_from("<IIIIIIII", desc)
        if not (name_rva or iat or ilt):
            break
        dll_name = img.cstr_rva(name_rva) or f"<unnamed-delay-{i}>"
        entries = _walk_thunks(img, ilt or iat, iat)
        img.imports.append({"dll": dll_name, "delayed": True,
                            "entries": entries})


def _parse_exports(img: PeImage) -> None:
    rva, _size = img.directories[DIR_EXPORT]
    if not rva:
        return
    hdr = img.read_rva(rva, 40)
    if len(hdr) < 40:
        return
    (_c, _ts, _maj, _min, name_rva, ordinal_base, nfuncs, nnames,
     funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", hdr)
    dll_name = img.cstr_rva(name_rva)
    out: list[dict] = []
    seen_rvas: set[int] = set()
    for i in range(min(nnames, MAX_EXPORTS)):
        nb = img.read_rva(names_rva + i * 4, 4)
        ob = img.read_rva(ords_rva + i * 2, 2)
        if len(nb) < 4 or len(ob) < 2:
            break
        name_r = struct.unpack_from("<I", nb)[0]
        ord_i = struct.unpack_from("<H", ob)[0]
        if ord_i >= nfuncs:
            continue
        fb = img.read_rva(funcs_rva + ord_i * 4, 4)
        if len(fb) < 4:
            continue
        frva = struct.unpack_from("<I", fb)[0]
        seen_rvas.add(frva)
        forwarder = ""
        er = img.directories[DIR_EXPORT]
        if er[0] <= frva < er[0] + er[1]:
            forwarder = img.cstr_rva(frva)
        out.append({"name": img.cstr_rva(name_r), "rva": frva,
                    "va": img.image_base + frva,
                    "ordinal": ordinal_base + ord_i,
                    "forwarder": forwarder or None})
    # Unnamed exports reachable only by ordinal.
    for i in range(min(nfuncs, MAX_EXPORTS)):
        fb = img.read_rva(funcs_rva + i * 4, 4)
        if len(fb) < 4:
            break
        frva = struct.unpack_from("<I", fb)[0]
        if frva and frva not in seen_rvas:
            out.append({"name": None, "rva": frva,
                        "va": img.image_base + frva,
                        "ordinal": ordinal_base + i, "forwarder": None})
    img.exports = out
    img.exports_dll_name = dll_name


def _parse_pdata(img: PeImage) -> None:
    """.pdata RUNTIME_FUNCTION table — function-start seeds (x64)."""
    rva, size = img.directories[DIR_EXCEPTION]
    if not rva or not size:
        return
    count = min(size // 12, MAX_PDATA_ENTRIES)
    out = []
    for i in range(count):
        b = img.read_rva(rva + i * 12, 12)
        if len(b) < 12:
            break
        begin, end, unwind = struct.unpack_from("<III", b)
        if not begin or not end or end <= begin:
            continue
        out.append({"begin_rva": begin, "end_rva": end,
                    "begin_va": img.image_base + begin,
                    "end_va": img.image_base + end,
                    "unwind_rva": unwind})
    img.pdata = out


def _parse_load_config(img: PeImage) -> None:
    rva, size = img.directories[DIR_LOADCFG]
    if not rva or size < 0x40:
        return
    raw = img.read_rva(rva, min(size, 0x200))
    if len(raw) < 0x40:
        return
    lc: dict[str, Any] = {"size": struct.unpack_from("<I", raw, 0)[0]}
    q = "<Q" if img.pe32_plus else "<I"
    w = 8 if img.pe32_plus else 4

    def field(off32: int, off64: int) -> int:
        off = off64 if img.pe32_plus else off32
        if off + w > len(raw):
            return 0
        return struct.unpack_from(q, raw, off)[0]

    lc["security_cookie_va"] = field(0x3C, 0x58)
    lc["seh_table_va"] = field(0x40, 0x60)
    lc["seh_count"] = field(0x44, 0x68)
    lc["guard_cf_check_va"] = field(0x48, 0x70)
    lc["guard_cf_dispatch_va"] = field(0x50, 0x78)
    lc["guard_cf_table_va"] = field(0x58, 0x80)
    lc["guard_cf_count"] = field(0x5C, 0x88)
    lc["guard_flags"] = struct.unpack_from(
        "<I", raw, 0x60 if not img.pe32_plus else 0x90)[0] \
        if len(raw) >= (0x64 if not img.pe32_plus else 0x94) else 0
    img.load_config = lc


def _parse_debug(img: PeImage) -> None:
    rva, size = img.directories[DIR_DEBUG]
    if not rva or not size:
        return
    out = []
    for i in range(min(size // 28, MAX_DEBUG_ENTRIES)):
        b = img.read_rva(rva + i * 28, 28)
        if len(b) < 28:
            break
        (_c, _ts, _t, _m, dtype, dsize, drva, doff) = \
            struct.unpack_from("<IIHHIIII", b)
        row: dict[str, Any] = {"type": dtype, "size": dsize}
        if dtype == 2 and dsize >= 24:  # CodeView
            cv = img.read_rva(drva, min(dsize, 4096))
            if cv[:4] == b"RSDS" and len(cv) >= 24:
                guid = cv[4:20]
                guid_s = (
                    f"{struct.unpack_from('<I', guid, 0)[0]:08X}-"
                    f"{struct.unpack_from('<H', guid, 4)[0]:04X}-"
                    f"{struct.unpack_from('<H', guid, 6)[0]:04X}-"
                    f"{guid[8]:02X}{guid[9]:02X}-"
                    + "".join(f"{x:02X}" for x in guid[10:16]))
                pdb_path = cv[24:].split(b"\0", 1)[0].decode(
                    "ascii", "replace")
                row.update({"format": "RSDS", "guid": guid_s,
                            "age": struct.unpack_from("<I", cv, 20)[0],
                            "pdb_path": pdb_path})
            elif cv[:4] == b"NB10" and len(cv) >= 16:
                row.update({"format": "NB10",
                            "pdb_path": cv[16:].split(b"\0", 1)[0].decode(
                                "ascii", "replace")})
        out.append(row)
    img.debug = out


def _parse_relocs(img: PeImage) -> None:
    rva, size = img.directories[DIR_RELOC]
    img.reloc_present = bool(rva and size)
    if not rva:
        return
    blocks = 0
    off = rva
    end = rva + size
    while blocks < MAX_RELOC_BLOCKS:
        b = img.read_rva(off, 8)
        if len(b) < 8:
            break
        _page, bsize = struct.unpack_from("<II", b)
        if bsize < 8 or off + bsize > end:
            break
        blocks += 1
        off += bsize
    img.reloc_blocks = blocks


def imphash(img: PeImage) -> str:
    """Mandiant-style imphash: md5 of 'lib.func' tuples in import order.

    Normalization: library name lowercased with the extension stripped;
    function names lowercased; ordinal-only imports become 'ord<N>'.
    """
    import hashlib
    parts: list[str] = []
    for dll in img.imports:
        lib = dll["dll"].lower()
        for ext in (".dll", ".ocx", ".sys"):
            if lib.endswith(ext):
                lib = lib[: -len(ext)]
                break
        for e in dll["entries"]:
            fn = e["name"].lower() if e["name"] else f"ord{e['ordinal']}"
            parts.append(f"{lib}.{fn}")
    return hashlib.md5(",".join(parts).encode()).hexdigest()
