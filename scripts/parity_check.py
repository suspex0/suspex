#!/usr/bin/env python
"""Kernel-vs-usermode memory parity harness (suspex0 phase 1, PLAN_NEXT section 6).

Reads sampled committed regions of one target pid through BOTH views —
the suspex_agent kernel path (driver Memory.Read, space=user) and the
umagent usermode path (ReadProcessMemory) — byte-compares, times both
paths, and files the result into the findings ledger.

Local lab usage (both agents running on this PC):
  orchestrator\\.venv\\Scripts\\python.exe scripts\\parity_check.py --pid <pid>

Options default from --config (targets.user for the usermode view).
Exit codes: 0 zero-mismatch parity, 2 mismatch/asymmetry, 1 harness error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

try:
    from suspex.agent_client import AgentClient
    from suspex.config import PRIMARY_TARGET, load_config
    from suspex.findings import FindingsLedger
    from suspex.parity import format_report, run_parity, verdict
except ImportError:  # running without the venv: fall back to the source tree
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))
    from suspex.agent_client import AgentClient
    from suspex.config import PRIMARY_TARGET, load_config
    from suspex.findings import FindingsLedger
    from suspex.parity import format_report, run_parity, verdict


def parse_endpoint(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    if not host or not port:
        raise ValueError(f"endpoint must be host:port, got {s!r}")
    return host, int(port)


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=None, help="orchestrator yaml (endpoint defaults)")
    ap.add_argument("--kernel", default="", help="kernel view endpoint host:port")
    ap.add_argument("--user", default="", help="usermode view endpoint host:port")
    ap.add_argument("--token", default="", help="bearer token (defaults from config)")
    ap.add_argument("--pid", type=lambda x: int(x, 0), required=True, help="target process")
    ap.add_argument("--samples", type=int, default=16)
    ap.add_argument("--read-bytes", type=int, default=4096)
    ap.add_argument("--seed", type=int, default=0, help="deterministic sample offsets")
    ap.add_argument("--out", default="", help="write the full JSON report here")
    ap.add_argument("--ledger", default="", help="findings sqlite db to record into")
    ap.add_argument("--session-id", default="", help="existing ledger session id")
    args = ap.parse_args()

    cfg = load_config(args.config)
    khost, kport = parse_endpoint(args.kernel) if args.kernel else (cfg.target.host, cfg.target.port)
    try:
        ut = cfg.target_for("user")
        udef = (ut.host, ut.port, ut.token or cfg.target.token)
    except KeyError:
        udef = ("127.0.0.1", 50075, cfg.target.token)
    uhost, uport = parse_endpoint(args.user) if args.user else udef[:2]
    token = args.token or udef[2]

    kclient = AgentClient(khost, kport, token, cfg.target.connect_timeout_ms)
    uclient = AgentClient(uhost, uport, token, cfg.target.connect_timeout_ms)
    try:
        await kclient.connect()
        await uclient.connect()
        kstatus = await kclient.status()
        ustatus = await uclient.status()
        print(f"kernel view {khost}:{kport} -> {kstatus.get('agent_version')} "
              f"(driver_state={kstatus.get('driver_state')})")
        print(f"user view  {uhost}:{uport} -> {ustatus.get('agent_version')}")
        if not ustatus.get("ok"):
            print("user view not healthy", file=sys.stderr)
            return 1

        report = await run_parity(kclient, uclient, args.pid, samples=args.samples,
                                  read_bytes=args.read_bytes, seed=args.seed)
    finally:
        await kclient.close()
        await uclient.close()

    print(format_report(report))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report written to {args.out}")

    if args.ledger:
        ledger = FindingsLedger(args.ledger)
        try:
            severity, reason = verdict(report)
            sid = args.session_id or ledger.start_session(f"parity {khost}:{kport}+{uhost}:{uport}")
            fid = ledger.record(sid, severity, f"parity pid={args.pid}: kernel vs usermode",
                                reason, refs="parity_check")
            ledger.add_evidence(fid, "parity_report", json.dumps(report, indent=2))
            print(f"finding {fid} ({severity}) recorded in {args.ledger} (session {sid})")
        finally:
            ledger.close()

    summary = report["summary"]
    if summary["mismatches"] or summary["compared"] == 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
