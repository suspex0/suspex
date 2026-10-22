"""PE header math: parse DOS/NT/section headers from memory reads, plus
the RVA→file-offset lookup that goes with them."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .reader import ReadFn, Reader, SuspexError


# ------------------------------------------------------------------ PE ----

@dataclass
class PeInfo:
    base: int
    image_base: int
    size_of_image: int
    machine: int
    sections: list[dict[str, Any]] = field(default_factory=list)


async def parse_pe(read: ReadFn | Reader, base: int = 0) -> PeInfo:
    """Parses DOS/NT/section headers from memory reads (image must be mapped
    at base, or base=0 for a file-layout buffer)."""
    r = read if isinstance(read, Reader) else Reader(read)
    if await r.u16(base) != 0x5A4D:
        raise SuspexError("bad MZ")
    e_lfanew = await r.u32(base + 0x3C)
    pe = base + e_lfanew
    if await r.u32(pe) != 0x00004550:
        raise SuspexError("bad PE signature")
    machine = await r.u16(pe + 4)
    num_sections = await r.u16(pe + 6)
    opt_size = await r.u16(pe + 20)
    opt = pe + 24
    magic = await r.u16(opt)
    pe32p = magic == 0x20B
    if not pe32p and magic != 0x10B:
        raise SuspexError(f"unknown optional header magic {hex(magic)}")
    image_base = await r.u64(opt + 24) if pe32p else await r.u32(opt + 28)
    size_of_image = await r.u32(opt + 56)
    sections = []
    table = opt + opt_size
    for i in range(num_sections):
        s = table + i * 40
        name_bytes = await r.read(s, 8)
        sections.append({
            "name": name_bytes.split(b"\0", 1)[0].decode("ascii", "replace"),
            "virtual_size": await r.u32(s + 8),
            "virtual_address": await r.u32(s + 12),
            "raw_size": await r.u32(s + 16),
            "raw_ptr": await r.u32(s + 20),
        })
    return PeInfo(base=base, image_base=image_base, size_of_image=size_of_image,
                  machine=machine, sections=sections)


def rva_to_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    """Memory RVA -> file offset using the section table (PE header math)."""
    for s in sections:
        size = s["virtual_size"] or s["raw_size"]
        if s["virtual_address"] <= rva < s["virtual_address"] + size:
            return s["raw_ptr"] + (rva - s["virtual_address"])
    return None
