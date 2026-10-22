from __future__ import annotations


async def run(sdk, params: dict) -> dict:
    rule = params.get("rule") or ""
    if not rule:
        return {
            "ok": True, "status": "no_rule", "severity": "warning",
            "summary": "yara_mem: 'rule' param is required",
        }
    if not sdk.yara.available():
        return {
            "ok": True, "status": "no_yara", "severity": "warning",
            "summary": "yara_mem: yara-python not installed (pip install suspex0[yara])",
        }
    matches = await sdk.yara.scan_module(params["pid"], params["module"], rule)
    severity = "high" if matches else "info"
    summary = (f"yara_mem pid={params['pid']} {params['module']}: "
               f"{len(matches)} rule match(es)")
    return {
        "ok": True,
        "status": "matched" if matches else "clean",
        "pid": params["pid"],
        "module": params["module"],
        "matches": matches,
        "severity": severity,
        "summary": summary,
    }
