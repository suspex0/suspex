"""iat_diff — walk a live module's IAT and file any hooked slots as findings.

`hooked` is set server-side (agent) when the resolved pointer sits outside
the declared source DLL's [base, base+size) range, or outside any loaded
module (nearly always a trampoline into unlinked memory).
"""

from __future__ import annotations


def _basename(p: str) -> str:
    import re

    return re.split(r"[\\/]", str(p))[-1].lower()


async def run(sdk, params: dict) -> dict:
    pid = int(params["pid"])
    module = str(params["module"])
    view = params.get("view", "user") or "user"
    kernel = bool(params.get("kernel", False))

    entries = await sdk.mods.imports(pid, module, kernel=kernel, view=view)
    hooked = [e for e in entries if e.get("hooked")]

    # Trim the per-entry payload we surface for hooked rows so the finding
    # stays readable when a large binary has many hits.
    trimmed = [
        {
            "dll": e.get("dll"),
            "name": e.get("name") or f"#{e.get('ordinal')}",
            "iat_slot": e.get("iat_slot"),
            "resolved": e.get("resolved"),
            "resolved_module": e.get("resolved_module") or "<unmapped>",
        }
        for e in hooked
    ]

    return {
        "ok": True,
        "severity": "high" if hooked else "info",
        "summary": (f"{len(hooked)} hooked / {len(entries)} imports in "
                    f"{_basename(module)} (pid {pid}, view={view})"),
        "totals": {"imports": len(entries), "hooked": len(hooked)},
        "module": module,
        "view": view,
        "kernel": kernel,
        "hooked": trimmed,
    }
