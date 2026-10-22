from __future__ import annotations

import asyncio


def _u64(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


async def run(sdk, params: dict) -> dict:
    pid = params["pid"]
    view = params["view"]
    space = "user"

    if params["module"]:
        mod = await sdk.mods.find(params["module"], pid=pid, view=view)
        if mod is None:
            return {
                "ok": True, "status": "no_module", "severity": "warning",
                "summary": f"memdiff: module {params['module']!r} not found in pid {pid}",
            }
        base, size = mod["base"], mod["size"]
    else:
        base, size = _u64(params["base"]), _u64(params["size"])
    if not base or not size:
        return {
            "ok": True, "status": "no_range", "severity": "warning",
            "summary": "memdiff: provide module or base+size",
        }

    all_changes: list[dict] = []
    for round_no in range(max(1, params["rounds"])):
        snap = await sdk.mem.snapshot(pid, [(base, size)], view=view, space=space)
        await asyncio.sleep(max(0, params["delay_ms"]) / 1000.0)
        changes = await sdk.mem.diff(snap, pid, view=view, space=space)
        for ch in changes:
            ch["round"] = round_no
        all_changes.extend(changes)

    severity = "warning" if all_changes else "info"
    summary = (f"memdiff pid={pid} {params['module'] or hex(base)} "
               f"x{params['rounds']}: {len(all_changes)} changed range(s)")
    return {
        "ok": True,
        "status": "changed" if all_changes else "stable",
        "base": hex(base),
        "size": size,
        "rounds": params["rounds"],
        "delay_ms": params["delay_ms"],
        "changes": all_changes,
        "severity": severity,
        "summary": summary,
    }
