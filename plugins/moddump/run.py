from __future__ import annotations

import hashlib
from pathlib import Path

from suspex.sdk import Reader, parse_pe


def _u32(buf: bytearray, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "little")


async def run(sdk, params: dict) -> dict:
    module: str = params["module"]
    chunk_size: int = max(4096, int(params.get("chunk", 1 << 20)))

    mod = await sdk.mods.find(module, kernel=True)
    if not mod:
        return {"ok": False, "severity": "warning",
                "summary": f"kernel module not found: {module}"}
    base = int(mod["base"])

    async def kread(addr: int, size: int) -> bytes:
        return await sdk.mem.read(0, addr, size, "kernel")

    r = Reader(kread)
    info = await parse_pe(r, base)

    image = bytearray()
    off = 0
    while off < info.size_of_image:
        n = min(chunk_size, info.size_of_image - off)
        part = await kread(base + off, n)
        if not part:
            break
        image += part
        off += len(part)
    partial = off < info.size_of_image
    if len(image) < info.size_of_image:
        image += b"\x00" * (info.size_of_image - len(image))

    e_lfanew = _u32(image, 0x3C)
    opt = e_lfanew + 24
    size_of_headers = _u32(image, opt + 60)

    out_size = size_of_headers
    for s in info.sections:
        out_size = max(out_size, s["raw_ptr"] + s["raw_size"])
    fout = bytearray(out_size)
    fout[:size_of_headers] = image[:size_of_headers]

    holes: list[str] = []
    for s in info.sections:
        raw = image[s["virtual_address"] : s["virtual_address"] + s["raw_size"]]
        if len(raw) < s["raw_size"]:
            raw += b"\x00" * (s["raw_size"] - len(raw))
            holes.append(s["name"])
        fout[s["raw_ptr"] : s["raw_ptr"] + s["raw_size"]] = raw

    out = params.get("out") or f"artifacts/dumps/{module}.rt.sys"
    p = Path(out)
    if not p.is_absolute():
        # Relative paths resolve under the canonical artifacts dir passed
        # down from the orchestrator config, not the launch cwd.
        p = Path(getattr(sdk, "artifacts_dir", "") or Path.cwd() / "artifacts") / p
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(bytes(fout))

    return {
        "ok": True,
        "severity": "info",
        "summary": (f"dumped {module} from kernel memory (base {base:#x}, "
                    f"{info.size_of_image:#x} bytes) -> {p}"),
        "module": module,
        "module_path": mod.get("path", ""),
        "runtime_base": hex(base),
        "image_base": hex(info.image_base),
        "size_of_image": hex(info.size_of_image),
        "size_of_headers": hex(size_of_headers),
        "sections": [{"name": s["name"], "va": hex(s["virtual_address"]),
                      "file": hex(s["raw_ptr"]), "size": hex(s["raw_size"])}
                     for s in info.sections],
        "holes_zero_filled": holes,
        "partial_read": partial,
        "path": str(p),
        "bytes": len(fout),
        "raw_va_sha256": hashlib.sha256(bytes(image)).hexdigest(),
        "sha256": hashlib.sha256(bytes(fout)).hexdigest(),
        "ida_hint": f"ida_manage(action='open', path='{p}')",
    }
