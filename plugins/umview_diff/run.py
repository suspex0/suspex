from __future__ import annotations

from suspex.parity import verdict


async def run(sdk, params: dict) -> dict:
    report = await sdk.parity(params["pid"], samples=params["samples"],
                              read_bytes=params["read_bytes"], seed=params["seed"])
    severity, reason = verdict(report)
    return {
        "ok": True,
        "severity": severity,
        "summary": f"parity pid={params['pid']}: {reason}",
        "report": report,
    }
