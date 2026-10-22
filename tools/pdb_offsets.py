"""Extract struct field offsets/bitfields from a module's PDB via dbghelp.

Usage:
  python pdb_offsets.py <binary.exe> <StructName> [StructName ...]

Prints every field of each struct: offset, size, bitfield position if any.
Reuse of suspex.symbols ensure_pdb for GUID-matched cache/download.
"""
import ctypes
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))
from suspex.symbols import ensure_pdb  # noqa: E402

SYMBOL_INFOW = struct.Struct("IIQQIIQQQIIII")  # up to Name[], x64
MAX_SYM_NAME = 2000

TI_GET_OFFSET = 35
TI_GET_LENGTH = 36
TI_GET_CHILDRENCOUNT = 37
TI_FINDCHILDREN = 38
TI_GET_SYMNAME = 39
TI_GET_BITPOSITION = 48
TI_GET_DATAKIND = 41

SYMTAG = {0: "Null", 1: "Exe", 2: "Compiland", 5: "Data", 6: "Function",
          11: "UDT", 12: "Enum", 13: "FuncType", 15: "PointerType",
          16: "ArrayType", 17: "BaseType", 18: "Typedef"}
DATAKIND = {0: "Unknown", 1: "Local", 2: "StaticGlobal", 3: "Param",
            4: "ObjectPtr", 5: "FileStatic", 6: "Global", 7: "Member",
            8: "StaticMember", 9: "Constant"}


def main() -> None:
    binary = sys.argv[1]
    names = sys.argv[2:]
    dll = ctypes.WinDLL("dbghelp.dll", use_last_error=True)
    h = ctypes.c_void_p(0x53585031)

    c = ctypes
    dll.SymSetOptions.argtypes = [c.c_uint32]
    dll.SymInitializeW.argtypes = [c.c_void_p, c.c_wchar_p, c.c_int]
    dll.SymLoadModuleExW.argtypes = [c.c_void_p, c.c_void_p, c.c_wchar_p,
                                     c.c_wchar_p, c.c_uint64, c.c_uint32,
                                     c.c_void_p, c.c_uint32]
    dll.SymGetTypeFromNameW.argtypes = [c.c_void_p, c.c_uint64, c.c_wchar_p, c.c_void_p]
    dll.SymGetTypeInfo.argtypes = [c.c_void_p, c.c_uint64, c.c_uint32, c.c_uint32, c.c_void_p]

    dll.SymSetOptions(0x00000002)  # SYMOPT_UNDNAME
    symbols_dir = os.environ.get(
        "SUSPEX_SYMBOLS",
        str(Path(__file__).resolve().parents[1] / "artifacts" / "symbols"))
    pdb = ensure_pdb(binary, symbols_dir, True)
    print(f"[*] pdb: {pdb}")
    pdb_dir = str(pdb.parent)
    if not dll.SymInitializeW(h, pdb_dir, False):
        raise SystemExit(f"SymInitializeW failed: {ctypes.get_last_error()}")
    base = 0x180000000
    if not dll.SymLoadModuleExW(h, None, str(Path(binary).resolve()), None, base, 0, None, 0):
        raise SystemExit(f"SymLoadModuleExW failed: {ctypes.get_last_error()}")

    # SyGetTypeFromNameW(h, BaseOfModule, Name, SYMBOL_INFOW*)
    SymGetTypeFromNameW = dll.SymGetTypeFromNameW
    SymGetTypeInfo = dll.SymGetTypeInfo

    def type_info(ti: int, tid: int, gid: int):
        val = ctypes.c_uint64(0)
        if not SymGetTypeInfo(h, base, tid, gid, ctypes.byref(val)):
            return None
        return val.value

    def type_name(tid: int) -> str:
        buf = ctypes.c_wchar_p()
        if not SymGetTypeInfo(h, base, tid, TI_GET_SYMNAME, ctypes.byref(buf)):
            return f"<tid{tid}>"
        s = buf.value or ""
        # dbghelp allocates; leak is fine for a lab tool
        return s

    for want in names:
        class SYMINFO(ctypes.Structure):
            _fields_ = [("SizeOfStruct", ctypes.c_uint32),
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
                        ("Name", ctypes.c_wchar * MAX_SYM_NAME)]

        si = SYMINFO()
        si.SizeOfStruct = SYMBOL_INFOW.size
        si.MaxNameLen = MAX_SYM_NAME
        if not SymGetTypeFromNameW(h, base, want, ctypes.byref(si)):
            print(f"[!] {want}: SymGetTypeFromNameW failed err={ctypes.get_last_error()}")
            continue
        tid = si.TypeIndex
        size = type_info(want, tid, TI_GET_LENGTH)
        size_s = f"{size:#x}" if size is not None else "?"
        print(f"\n=== {want}  (tid={tid} size={size_s} tag={SYMTAG.get(si.Tag, si.Tag)}) ===")
        nchild = type_info(want, tid, TI_GET_CHILDRENCOUNT)
        if not nchild:
            print("    (no children)")
            continue

        class FINDCHILDREN(ctypes.Structure):
            _fields_ = [("Count", ctypes.c_ulong), ("Start", ctypes.c_ulong),
                        ("ChildId", ctypes.c_ulong * nchild)]

        fc = FINDCHILDREN()
        fc.Count = nchild
        if not SymGetTypeInfo(h, base, tid, TI_FINDCHILDREN, ctypes.byref(fc)):
            print(f"[!] FINDCHILDREN failed err={ctypes.get_last_error()}")
            continue
        for i in range(fc.Count):
            cid = fc.ChildId[i]
            nm = type_name(cid)
            off = type_info(want, cid, TI_GET_OFFSET)
            ln = type_info(want, cid, TI_GET_LENGTH)
            dk = type_info(want, cid, TI_GET_DATAKIND)
            bits = type_info(want, cid, TI_GET_BITPOSITION)
            extra = ""
            if bits is not None and ln is not None and ln <= 8:
                # bitfield: bit position within the *byte-converted* unit
                # dbghelp BitPosition = bit index; length via TI_GET_LENGTH (bits for bitfields? bytes)
                extra = f" BIT(pos={bits}, len={ln})"
            if dk is not None and DATAKIND.get(dk) not in ("Member", "StaticMember") and nm:
                extra += f" kind={DATAKIND.get(dk, dk)}"
            print(f"  +0x{off:05x} {nm:44s} size={ln}{extra}")


if __name__ == "__main__":
    main()
