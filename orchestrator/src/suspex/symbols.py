"""PDB-backed kernel symbol resolution (phase 2).

Public symbol streams of the shipped ntoskrnl/ci PDBs contain the
unexported globals the lab tooling needs (PiDDBCacheTable,
MmUnloadedDrivers, MmLastUnloadedDriver, ...). Resolution path:

  read_pdb_info(binary)   -> RSDS GUID/age from the PE debug directory
  ensure_pdb(...)         -> cache-first download from the symbol server
  resolve_rvas(...)       -> dbghelp SymLoadModuleExW + SymFromNameW -> RVA

No third-party PDB parser: ctypes + system dbghelp.dll. PDBs give symbol
ADDRESSES only — struct field layouts stay in recipes (_patterns.yaml).
"""

from __future__ import annotations

import ctypes
import threading
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SERVERS = ["https://msdl.microsoft.com/download/symbols"]

_USER_AGENT = "suspex0-lab-symbol-fetch/1.0"
_DOWNLOAD_TIMEOUT_S = 180


class SymbolError(RuntimeError):
    pass


# ------------------------------------------------------- PE debug directory ----

def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 4], "little")


@dataclass
class PdbInfo:
    name: str
    guid: str  # 32-hex symsrv-formatted GUID
    age: int

    @property
    def store_rel(self) -> str:
        return f"{self.name}/{self.guid}{self.age}/{self.name}"


def format_guid(raw: bytes) -> str:
    """16 GUID bytes as stored in RSDS -> symsrv directory token."""
    if len(raw) != 16:
        raise SymbolError("GUID must be 16 bytes")
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    return f"{d1:08X}{d2:04X}{d3:04X}{raw[8:16].hex().upper()}"


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int]]) -> int | None:
    """(va, vsize, raw_ptr) table -> file offset."""
    for va, vsize, raw in sections:
        span = max(vsize, 0x1000)
        if va <= rva < va + span:
            return raw + (rva - va)
    return None


def _debug_dir_offsets(data: bytes, dbg_rva: int,
                       sections: list[tuple[int, int, int]]) -> list[int]:
    """File offsets where the debug directory may live.

    On-disk images map the directory RVA through the section table
    (PointerToRawData form). VA-layout dump_module outputs keep the file
    layout identical to the memory layout, so the bare RVA is itself the
    file offset — try both."""
    outs: list[int] = []
    mapped = _rva_to_offset(dbg_rva, sections)
    if mapped is not None and mapped + 28 <= len(data):
        outs.append(mapped)
    if dbg_rva + 28 <= len(data) and dbg_rva not in outs:
        outs.append(dbg_rva)
    return outs


def _cv_blobs(data: bytes, rva: int, ptr: int, size: int,
              sections: list[tuple[int, int, int]]) -> list[bytes]:
    """CodeView blob candidates, most-likely first.

    File form: the blob lives at PointerToRawData. VA-layout dumps (the
    agent's dump_module output zeroes PointerToRawData and keeps
    AddressOfRawData authoritative so dbghelp/IDA can parse the dump):
    the blob lives at the bare RVA."""
    outs: list[bytes] = []
    for off in (ptr, rva):
        if not off:
            continue
        blob = data[off : off + size]
        if len(blob) >= 24 and blob not in outs:
            outs.append(blob)
    mapped = _rva_to_offset(rva, sections) if rva else None
    if mapped:
        blob = data[mapped : mapped + size]
        if len(blob) >= 24 and blob not in outs:
            outs.append(blob)
    return outs


def read_pdb_info(path: str | Path) -> PdbInfo:
    """Extracts pdb name/GUID/age from the CodeView debug directory."""
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise SymbolError(f"not a PE image: {path}")
    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SymbolError(f"bad PE signature: {path}")
    num_sections = _u16(data, e_lfanew + 6)
    opt_size = _u16(data, e_lfanew + 20)
    opt = e_lfanew + 24
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise SymbolError(f"unknown optional header magic {magic:#x}")
    dd = opt + (112 if magic == 0x20B else 96)
    dbg_rva = _u32(data, dd + 6 * 8)
    dbg_size = _u32(data, dd + 6 * 8 + 4)
    if not dbg_rva or not dbg_size:
        raise SymbolError(f"no debug directory in {path}")

    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        s = sec + i * 40
        sections.append((_u32(data, s + 12), _u32(data, s + 8), _u32(data, s + 20)))

    dir_offs = _debug_dir_offsets(data, dbg_rva, sections)
    if not dir_offs:
        raise SymbolError("debug directory RVA not mapped by any section")

    for doff in dir_offs:
        for i in range(dbg_size // 28):
            entry = doff + i * 28
            if _u32(data, entry + 12) != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            size = _u32(data, entry + 16)
            rva = _u32(data, entry + 20)  # AddressOfRawData
            ptr = _u32(data, entry + 24)  # PointerToRawData
            for blob in _cv_blobs(data, rva, ptr, size, sections):
                if blob[:4] != b"RSDS":
                    continue
                name = blob[24:].split(b"\0", 1)[0].decode("utf-8", "replace")
                return PdbInfo(name=name, guid=format_guid(blob[4:20]),
                               age=_u32(blob, 20))
    raise SymbolError(f"no RSDS CodeView entry in {path}")


# ------------------------------------------------------------ cache + fetch ----

def ensure_pdb(binary_path: str | Path, cache_dir: str | Path = "",
               allow_download: bool = True,
               servers: list[str] | None = None,
               pdb_info: PdbInfo | None = None) -> Path:
    """Returns the cached PDB matching the binary, downloading if allowed.

    ``pdb_info=`` overrides the image's own debug directory (escape hatch
    for images whose CodeView entry is stripped or unparseable — take
    name/GUID/age from ``bin_manage info``'s pdb_path in that case)."""
    info = pdb_info or read_pdb_info(binary_path)
    base = Path(cache_dir) if cache_dir else Path.cwd() / "symbols"
    final = base / info.store_rel
    if final.is_file():
        return final
    if not allow_download:
        raise SymbolError(
            f"pdb not cached and download disabled: {info.store_rel}")
    final.parent.mkdir(parents=True, exist_ok=True)
    last_err: Exception | None = None
    for server in servers or DEFAULT_SERVERS:
        url = f"{server.rstrip('/')}/{info.store_rel.replace(chr(92), '/')}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT_S) as resp:
                blob = resp.read()
            final.write_bytes(blob)
            return final
        except Exception as exc:  # try the next server
            last_err = exc
    raise SymbolError(f"pdb download failed for {info.store_rel}: {last_err}")


# ---------------------------------------------------------------- dbghelp ----

_MAX_SYM_NAME = 256
_SYM_INFO_SIZEOF = 88  # x64 sizeof(SYMBOL_INFOW) up to (not incl.) Name[]

# IMAGEHLP_SYMBOL_TYPE_INFO ordinals (dbghelp.h) used by the type walk.
_TI_GET_SYMTAG = 0
_TI_GET_SYMNAME = 1
_TI_GET_LENGTH = 2
_TI_GET_TYPE = 3
_TI_GET_TYPEID = 4
_TI_GET_BASETYPE = 5
_TI_GET_ARRAYINDEXTYPEID = 6
_TI_FINDCHILDREN = 7
_TI_GET_DATAKIND = 8
_TI_GET_OFFSET = 10
_TI_GET_VALUE = 11
_TI_GET_COUNT = 12
_TI_GET_CHILDRENCOUNT = 13
_TI_GET_BITPOSITION = 14

# SymTag* (cvconst.h) — only the tags the walker names.
_SYMTAG_NAMES = {
    0: "null", 1: "exe", 5: "function", 6: "block", 7: "data",
    10: "public_symbol", 11: "udt", 12: "enum", 13: "function_type",
    14: "pointer", 15: "array", 16: "base_type", 17: "typedef",
    18: "base_class", 20: "function_arg",
}

# BasicType (cvconst.h bt*).
_BT_NAMES = {
    0: "none", 1: "void", 2: "char", 3: "wchar", 6: "int", 7: "uint",
    8: "float", 9: "bcd", 10: "bool", 13: "long", 14: "ulong",
    25: "currency", 26: "date", 27: "variant", 28: "complex",
    29: "bit", 30: "bstr", 31: "hresult", 32: "char16", 33: "char8",
}

# DataKind (cvconst.h) — children of a UDT that are real members.
_DATAKIND_MEMBER = 7
_DATAKIND_STATIC_MEMBER = 8


class _VARIANT_I64(ctypes.Structure):
    """VARIANT truncated to the integer arm — vt (u16) + pad + llVal."""
    _fields_ = [
        ("vt", ctypes.c_uint16),
        ("_pad", ctypes.c_byte * 6),
        ("val", ctypes.c_int64),
    ]


class _SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ctypes.c_uint32),
        ("TypeIndex", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", ctypes.c_uint32),
        ("Size", ctypes.c_uint32),
        ("ModBase", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", ctypes.c_uint32),
        ("Scope", ctypes.c_uint32),
        ("Tag", ctypes.c_uint32),
        ("NameLen", ctypes.c_uint32),
        ("MaxNameLen", ctypes.c_uint32),
        ("Name", ctypes.c_wchar * _MAX_SYM_NAME),
    ]


class DbgHelp:
    """Thin process-wide dbghelp wrapper; one instance per runner."""

    def __init__(self) -> None:
        self._dll = ctypes.WinDLL("dbghelp.dll", use_last_error=True)
        self._dll.SymInitializeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                             ctypes.c_int]
        self._dll.SymSetSearchPathW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._dll.SymLoadModuleExW.restype = ctypes.c_uint64
        self._dll.SymLoadModuleExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_wchar_p, ctypes.c_wchar_p,
                                               ctypes.c_uint64, ctypes.c_uint32,
                                               ctypes.c_void_p, ctypes.c_uint32]
        self._dll.SymUnloadModule64.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self._dll.SymFromNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                           ctypes.POINTER(_SYMBOL_INFOW)]
        # v0.22: SymFromAddrW for va->symbol+displacement, and the
        # SymGetTypeFromNameW/SymGetTypeInfo pair for the layout walk.
        self._dll.SymFromAddrW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(_SYMBOL_INFOW)]
        self._dll.SymGetTypeFromNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_wchar_p,
            ctypes.POINTER(_SYMBOL_INFOW)]
        self._dll.SymGetTypeInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32,
            ctypes.c_int, ctypes.c_void_p]
        self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p
        self._handle = ctypes.c_void_p(0x53585030)  # any unique value
        self._initialized = False
        self._search_path = ""
        self._next_base = 0x18000000
        # DbgHelp is process-global and NOT thread-safe — every public
        # op serializes on this lock (SymInitialize once, search-path
        # mutation is process-wide).
        self._lock = threading.Lock()

    def _set_search_path(self, path: str) -> None:
        if not self._initialized:
            if not self._dll.SymInitializeW(self._handle, path, False):
                raise SymbolError(f"SymInitializeW failed: {ctypes.get_last_error()}")
            self._initialized = True
            self._search_path = path
            return
        if path != self._search_path:
            if not self._dll.SymSetSearchPathW(self._handle, path):
                raise SymbolError(f"SymSetSearchPathW failed: {ctypes.get_last_error()}")
            self._search_path = path

    def _load_module(self, binary_path: str, pdb_dir: str | Path) -> int:
        """Set the search path and map ``binary_path`` at a fresh scratch
        base. Caller must hold ``_lock``; returns the base to pass back
        to ``_unload_module``."""
        self._set_search_path(str(pdb_dir))
        base = self._next_base
        self._next_base += 0x1000000
        loaded = self._dll.SymLoadModuleExW(
            self._handle, None, str(binary_path), None, base, 0, None, 0)
        if not loaded:
            raise SymbolError(
                f"SymLoadModuleExW({binary_path}) failed: "
                f"{ctypes.get_last_error()}")
        return base

    def _unload_module(self, base: int) -> None:
        self._dll.SymUnloadModule64(self._handle, base)

    def resolve(self, binary_path: str, names: list[str], pdb_dir: str | Path) -> dict[str, int]:
        with self._lock:
            base = self._load_module(binary_path, pdb_dir)
            try:
                out: dict[str, int] = {}
                for name in names:
                    sym = _SYMBOL_INFOW()
                    sym.SizeOfStruct = _SYM_INFO_SIZEOF
                    sym.MaxNameLen = _MAX_SYM_NAME
                    if self._dll.SymFromNameW(self._handle, name, ctypes.byref(sym)):
                        out[name] = sym.Address - base
                return out
            finally:
                self._unload_module(base)

    def lookup(self, binary_path: str, rva: int, pdb_dir: str | Path) -> dict[str, Any]:
        """VA->symbol: nearest symbol at-or-before ``rva`` plus the
        displacement. Returns ``{found, name, rva, displacement}`` —
        ``found`` False when no symbol covers the address."""
        with self._lock:
            base = self._load_module(binary_path, pdb_dir)
            try:
                sym = _SYMBOL_INFOW()
                sym.SizeOfStruct = _SYM_INFO_SIZEOF
                sym.MaxNameLen = _MAX_SYM_NAME
                disp = ctypes.c_uint64(0)
                ok = self._dll.SymFromAddrW(self._handle, base + rva,
                                            ctypes.byref(disp),
                                            ctypes.byref(sym))
                if not ok:
                    return {"found": False, "rva": rva}
                name = sym.Name[: sym.NameLen] if sym.NameLen else ""
                return {
                    "found": True,
                    "name": name,
                    "rva": sym.Address - base,
                    "displacement": int(disp.value),
                }
            finally:
                self._unload_module(base)

    # ------------------------------------------------------------------
    # Type walk (SymGetTypeFromNameW + SymGetTypeInfo) — v0.22
    # ------------------------------------------------------------------

    def _ti_u32(self, base: int, type_id: int, which: int) -> int:
        out = ctypes.c_uint32(0)
        if not self._dll.SymGetTypeInfo(self._handle, base, type_id,
                                        which, ctypes.byref(out)):
            raise SymbolError(
                f"SymGetTypeInfo({which}) failed: {ctypes.get_last_error()}")
        return int(out.value)

    def _ti_u64(self, base: int, type_id: int, which: int) -> int:
        out = ctypes.c_uint64(0)
        if not self._dll.SymGetTypeInfo(self._handle, base, type_id,
                                        which, ctypes.byref(out)):
            raise SymbolError(
                f"SymGetTypeInfo({which}) failed: {ctypes.get_last_error()}")
        return int(out.value)

    def _ti_wstr(self, base: int, type_id: int, which: int) -> str:
        ptr = ctypes.c_wchar_p()
        if not self._dll.SymGetTypeInfo(self._handle, base, type_id,
                                        which, ctypes.byref(ptr)):
            raise SymbolError(
                f"SymGetTypeInfo({which}) failed: {ctypes.get_last_error()}")
        try:
            return ptr.value or ""
        finally:
            if ptr.value:
                self._kernel32.LocalFree(
                    ctypes.cast(ptr, ctypes.c_void_p))

    def _ti_children(self, base: int, type_id: int, count: int) -> list[int]:
        """TI_FINDCHILDREN: {Count, Start, ChildId[Count]} over a UDT."""
        if count <= 0:
            return []
        buf = (ctypes.c_uint32 * (2 + count))()
        buf[0] = count
        buf[1] = 0
        if not self._dll.SymGetTypeInfo(self._handle, base, type_id,
                                        _TI_FINDCHILDREN,
                                        ctypes.byref(buf)):
            raise SymbolError(
                f"SymGetTypeInfo(TI_FINDCHILDREN) failed: "
                f"{ctypes.get_last_error()}")
        return [int(buf[2 + i]) for i in range(count)]

    def _describe_type(self, base: int, type_id: int, depth: int) -> dict[str, Any]:
        """One-level type description for a member — pointer/array/typedef
        are unwrapped so the rendered name is C-shaped."""
        try:
            tag = self._ti_u32(base, type_id, _TI_GET_SYMTAG)
        except SymbolError:
            return {"type_id": type_id, "tag": "?"}
        out: dict[str, Any] = {"type_id": type_id,
                               "tag": _SYMTAG_NAMES.get(tag, str(tag))}
        try:
            out["size"] = self._ti_u64(base, type_id, _TI_GET_LENGTH)
        except SymbolError:
            pass
        try:
            name = self._ti_wstr(base, type_id, _TI_GET_SYMNAME)
            if name:
                out["name"] = name
        except SymbolError:
            pass
        if tag == 14:  # pointer — name the pointee, don't recurse members
            try:
                pointee = self._ti_u32(base, type_id, _TI_GET_TYPEID)
                sub = self._describe_type(base, pointee, depth + 1) \
                    if depth < 4 else {}
                out["points_to"] = sub.get("name") or sub.get("tag") or \
                    f"type_id {pointee}"
            except SymbolError:
                pass
        elif tag == 15:  # array — element type + count
            try:
                out["count"] = self._ti_u64(base, type_id, _TI_GET_COUNT)
            except SymbolError:
                pass
            try:
                elem = self._ti_u32(base, type_id, _TI_GET_TYPE)
                sub = self._describe_type(base, elem, depth + 1) \
                    if depth < 4 else {}
                out["element"] = sub.get("name") or sub.get("tag") or \
                    f"type_id {elem}"
            except SymbolError:
                pass
        elif tag == 16:  # base_type — bt* name
            try:
                bt = self._ti_u32(base, type_id, _TI_GET_BASETYPE)
                out["base"] = _BT_NAMES.get(bt, f"bt{bt}")
            except SymbolError:
                pass
        elif tag == 17 and depth < 4:  # typedef — unwrap to the aliased type
            try:
                aliased = self._ti_u32(base, type_id, _TI_GET_TYPEID)
                sub = self._describe_type(base, aliased, depth + 1)
                if sub.get("name"):
                    out["alias_for"] = sub["name"]
            except SymbolError:
                pass
        return out

    def type_layout(self, binary_path: str, type_name: str,
                    pdb_dir: str | Path, max_depth: int = 3) -> dict[str, Any]:
        """Walk a named type's member layout out of its PDB — no IDA.

        Returns ``{name, size, tag, members: [{name, offset, size,
        type, bit_position?, bit_length?, children?}]}``. Pointer and
        array members carry their pointee/element name; UDT members
        recurse up to ``max_depth``.
        """
        with self._lock:
            base = self._load_module(binary_path, pdb_dir)
            try:
                sym = _SYMBOL_INFOW()
                sym.SizeOfStruct = _SYM_INFO_SIZEOF
                sym.MaxNameLen = _MAX_SYM_NAME
                if not self._dll.SymGetTypeFromNameW(
                        self._handle, base, type_name, ctypes.byref(sym)):
                    return {"ok": False, "kind": "type_not_found",
                            "error": f"type {type_name!r} not in PDB for "
                                     f"{binary_path!r}",
                            "gle": ctypes.get_last_error()}
                return self._walk_udt(base, sym.TypeIndex, type_name,
                                      max_depth)
            finally:
                self._unload_module(base)

    def _walk_udt(self, base: int, type_id: int, name: str,
                  depth: int) -> dict[str, Any]:
        tag = self._ti_u32(base, type_id, _TI_GET_SYMTAG)
        size = self._ti_u64(base, type_id, _TI_GET_LENGTH)
        out: dict[str, Any] = {
            "ok": True, "name": name,
            "tag": _SYMTAG_NAMES.get(tag, str(tag)),
            "size": size, "members": [],
        }
        if tag == 12:  # enum — members are (name, value) constants
            count = self._ti_u32(base, type_id, _TI_GET_CHILDRENCOUNT)
            for cid in self._ti_children(base, type_id, count):
                cname = self._ti_wstr(base, cid, _TI_GET_SYMNAME)
                var = _VARIANT_I64()
                if self._dll.SymGetTypeInfo(self._handle, base, cid,
                                            _TI_GET_VALUE,
                                            ctypes.byref(var)):
                    val: Any = int(var.val)
                else:
                    val = None
                out["members"].append({"name": cname, "value": val})
            out["member_count"] = len(out["members"])
            return out
        if tag != 11:  # not a UDT — describe it but don't walk children
            out.update(self._describe_type(base, type_id, 0))
            out["ok"] = True
            out["name"] = name
            return out
        if depth <= 0:
            out["truncated"] = True
            return out
        count = self._ti_u32(base, type_id, _TI_GET_CHILDRENCOUNT)
        members: list[dict[str, Any]] = []
        for cid in self._ti_children(base, type_id, count):
            try:
                kind = self._ti_u32(base, cid, _TI_GET_DATAKIND)
            except SymbolError:
                kind = _DATAKIND_MEMBER  # assume member when unanswerable
            if kind not in (_DATAKIND_MEMBER, _DATAKIND_STATIC_MEMBER):
                continue  # methods, vtables, base-class pseudo-members
            try:
                mname = self._ti_wstr(base, cid, _TI_GET_SYMNAME)
            except SymbolError:
                mname = ""
            entry: dict[str, Any] = {"name": mname}
            try:
                entry["offset"] = self._ti_u32(base, cid, _TI_GET_OFFSET)
            except SymbolError:
                pass
            try:
                mtype = self._ti_u32(base, cid, _TI_GET_TYPE)
                desc = self._describe_type(base, mtype, 1)
                entry["size"] = desc.get("size", 0)
                if desc.get("name"):
                    entry["type"] = desc["name"]
                if "points_to" in desc:
                    entry["type"] = f"{desc['points_to']}*"
                if "element" in desc:
                    entry["type"] = (
                        f"{desc['element']}[{desc.get('count', '?')}]")
                if desc.get("tag") == "udt" and depth - 1 > 0:
                    nested = self._walk_udt(base, mtype,
                                            desc.get("name", ""), depth - 1)
                    if nested.get("members"):
                        entry["children"] = nested["members"]
                # Bitfields: TI_GET_BITPOSITION + member TI_GET_LENGTH
                # is the bit length, not the container size.
                try:
                    bitpos = self._ti_u32(base, cid, _TI_GET_BITPOSITION)
                    bitlen = self._ti_u64(base, cid, _TI_GET_LENGTH)
                    if bitlen and bitlen < entry.get("size", 0) * 8:
                        entry["bit_position"] = bitpos
                        entry["bit_length"] = bitlen
                except SymbolError:
                    pass
            except SymbolError:
                pass
            members.append(entry)
        out["members"] = members
        out["member_count"] = len(members)
        return out


_instance: DbgHelp | None = None


def _dbghelp() -> DbgHelp:
    global _instance
    if _instance is None:
        _instance = DbgHelp()
    return _instance


def resolve_rvas(binary_path: str | Path, names: list[str], cache_dir: str | Path = "",
                 allow_download: bool = True,
                 servers: list[str] | None = None) -> dict[str, int]:
    """name -> RVA for the given binary. Missing names are simply absent."""
    if not names:
        return {}
    pdb = ensure_pdb(binary_path, cache_dir, allow_download, servers)
    return _dbghelp().resolve(str(binary_path), names, str(pdb.parent))


def lookup_rva(binary_path: str | Path, rva: int, cache_dir: str | Path = "",
               allow_download: bool = True,
               servers: list[str] | None = None) -> dict[str, Any]:
    """RVA -> nearest symbol + displacement (SymFromAddrW)."""
    pdb = ensure_pdb(binary_path, cache_dir, allow_download, servers)
    return _dbghelp().lookup(str(binary_path), rva, str(pdb.parent))


def type_layout(binary_path: str | Path, type_name: str,
                cache_dir: str | Path = "", allow_download: bool = True,
                servers: list[str] | None = None,
                max_depth: int = 3) -> dict[str, Any]:
    """Named-type member layout straight from the PDB — no IDA needed.
    Public MSDL PDBs carry kernel type info, so this works on ntoskrnl
    et al. without a cached dump_layout."""
    pdb = ensure_pdb(binary_path, cache_dir, allow_download, servers)
    return _dbghelp().type_layout(str(binary_path), type_name,
                                  str(pdb.parent), max_depth=max_depth)
