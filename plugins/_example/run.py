from __future__ import annotations


def run(sdk, params: dict) -> dict:
    lines = [params["message"]] * max(0, params["count"])
    out = {
        "ok": True,
        "severity": "info",
        "echo": lines,
        "views": sorted(sdk.clients),
        "nt_build": sdk.nt_build,
        "summary": f"echoed {len(lines)} line(s); views {sorted(sdk.clients)}",
    }
    if params["require_user_view"]:
        sdk.mem.view("user")
        out["user_view"] = "present"
    return out
