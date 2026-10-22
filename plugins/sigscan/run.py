from __future__ import annotations

import re

from suspex.sdk import parse_mask


def _parse_pattern(s: str) -> tuple[bytes, str]:
    if re.fullmatch(r"([0-9A-Fa-f]{2} ?)+", s.strip()):
        return parse_mask(s.strip())
    return bytes.fromhex(s), ""


def _basename(p: str) -> str:
    return re.split(r"[\\/]", p)[-1].lower()


async def run(sdk, params: dict) -> dict:
    view = params["view"]
    kernel = view == "kernel"
    mods = await sdk.mods.list(params["pid"], kernel=kernel, view=view)
    want = _basename(params["module"])
    mod = next((m for m in mods if _basename(str(m.get("name", ""))) == want), None)
    if mod is None:
        seen = [_basename(str(m.get("name", ""))) for m in mods[:8]]
        raise RuntimeError(f"module {params['module']!r} not found in {view} view "
                           f"({len(mods)} modules, first: {seen})")

    pattern, mask = _parse_pattern(params["pattern"])
    size = int(mod["size"], 0) if isinstance(mod["size"], str) else int(mod["size"])
    base = int(mod["base"], 0) if isinstance(mod["base"], str) else int(mod["base"])
    space = "kernel" if kernel else "user"

    hits = await sdk.mem.scan_range(params["pid"], base, size, pattern, mask,
                                    view=view, space=space, max_results=params["max_results"])

    ctx_len = max(0, params["context"])
    results = []
    for addr in hits:
        entry = {"address": hex(addr)}
        if ctx_len:
            start = max(base, addr - 8)
            data = await sdk.mem.read(params["pid"], start, ctx_len + (addr - start),
                                      space=space, view=view)
            entry["context_hex"] = data.hex()
        results.append(entry)

    return {
        "ok": True,
        "module": str(mod.get("name")),
        "module_base": hex(base),
        "module_size": size,
        "view": view,
        "pattern": params["pattern"],
        "hits": results,
        "severity": "info",
        "summary": f"{len(hits)} hit(s) for {params['pattern']!r} in "
                   f"{mod.get('name')} ({view} view)",
    }
