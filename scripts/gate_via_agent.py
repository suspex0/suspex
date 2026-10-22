"""Driver gate over the agent's exec RPC (no WinRM required).

Ordering: exec does not touch the driver IOCTL surface; driver_load runs the
agent's internal ABI gate first. Only after the exerciser matrix is green are
driver-backed RPCs considered cleared.

Usage:
  .venv/Scripts/python.exe scripts\\gate_via_agent.py --host 192.168.56.10 --token <tok>
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

from suspex.agent_client import AgentClient  # noqa: E402

GATE_CMDS = [
    ["ping"],
    ["selftest"],
    ["procs"],
    ["mods"],
    ["mods", "--kernel"],
    ["kalloc", "--size", "4096"],
    ["phys_oob"],
    ["vad"],
    ["handles"],
]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=50074)
    ap.add_argument("--umport", type=int, default=50075)
    ap.add_argument("--token", required=True)
    ap.add_argument("--exe", default="C:\\suspex\\drv_exerciser.exe")
    args = ap.parse_args()

    c = AgentClient(args.host, args.port, args.token)
    try:
        await asyncio.wait_for(c.connect(), timeout=10)
    except Exception as exc:
        print(f"CONNECT FAILED {args.host}:{args.port} - {type(exc).__name__}: {exc}")
        print("is SuspexAgent running on the VM?  Start-Service SuspexAgent")
        return 1
    try:
        st = await c.status()
        print(f"agent: os={st.get('os_version')} build={st.get('os_build')} "
              f"testsigning={st.get('testsigning')} hvci={st.get('hvci')} "
              f"driver={st.get('driver_state')}")

        print("==> driver_load (agent runs its own ABI gate first)")
        res = await c.driver_load(method="service")
        print(f"    {res}")
        if not res.get("ok", False):
            print("DRIVER LOAD FAILED - fix testsigning/reboot, then re-run.")
            return 1

        failed = False
        for cmd in GATE_CMDS:
            print(f"==> {' '.join(cmd)}")
            out = await c.run_exe(args.exe, cmd, "", 30000)
            text = (out.get("stdout") or "") + (out.get("stderr") or "")
            for line in text.strip().splitlines()[:8]:
                print(f"    {line}")
            if "FAIL" in text or out.get("exit_code") != 0:
                print(f"    FAILED (exit {out.get('exit_code')})")
                failed = True

        u = None
        try:
            u = AgentClient(args.host, args.umport, args.token)
            await asyncio.wait_for(u.connect(), timeout=10)
            ust = await u.status()
            print(f"==> umagent :{args.umport} -> ok={ust.get('ok', True)}")
        except Exception as exc:
            print(f"==> umagent :{args.umport} -> FAILED: {type(exc).__name__}: {exc!r}")
            failed = True
        finally:
            if u is not None:
                await u.close()

        print()
        if failed:
            print("DRIVER GATE FAILED - do not use driver-backed RPCs.")
            return 1
        print("DRIVER GATE PASSED - driver-backed RPCs cleared.")
        return 0
    finally:
        await c.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
