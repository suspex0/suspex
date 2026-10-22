"""Disassemble a range from a PE driver/image file, by RVA.

usage: python disas_handler.py <image_path> <rva_hex> [n_bytes]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))
import capstone  # noqa: E402

BASE = 0x140000000


def rva_to_off(path: str, rva: int) -> int:
    import struct
    with open(path, "rb") as f:
        data = f.read(0x1000)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_size
    with open(path, "rb") as f:
        blob = f.read()
    for i in range(nsec):
        s = sec0 + i * 40
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", blob, s + 8)
        if va <= rva < va + max(vsize, rsize):
            off = rptr + (rva - va)
            if off >= len(blob):
                raise ValueError("offset beyond EOF")
            return off
    raise ValueError("rva not mapped")


def main() -> None:
    image = sys.argv[1]
    rva = int(sys.argv[2], 16)
    n = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x180
    off = rva_to_off(image, rva)
    with open(image, "rb") as f:
        f.seek(off)
        code = f.read(n)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    print(f"; rva {rva:#x} file_off {off:#x}")
    for ins in md.disasm(code, BASE + rva):
        print(f"  {ins.address - BASE:#x}:  {ins.mnemonic} {ins.op_str}")


main()
