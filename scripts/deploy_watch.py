"""One-shot deploy of the status watch window to C:\\suspex\\watch\\ on the VM.

After running this, on the VM's console open C:\\suspex\\watch\\ and
double-click watch.cmd. It stays open until closed and refreshes every 2s.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

from suspex.agent_client import AgentClient  # noqa: E402


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=50074)
    ap.add_argument("--token", required=True)
    args = ap.parse_args()

    here = Path(__file__).with_name("watch")
    files = [(here / "watch.ps1", r"C:\suspex\watch\watch.ps1"),
             (here / "watch.cmd", r"C:\suspex\watch\watch.cmd")]

    c = AgentClient(args.host, args.port, args.token)
    await asyncio.wait_for(c.connect(), timeout=10)
    try:
        mk = await c.run_shell(r'if not exist "C:\suspex\watch" md "C:\suspex\watch"',
                               "cmd", "", 5000)
        print(f"  mkdir exit={mk.get('exit_code')}")
        for local, remote in files:
            r = await c.file_upload(str(local), remote)
            print(f"  {remote}: ok={r.get('ok')} bytes={r.get('bytes_written')} "
                  f"err={r.get('error')!r}")
        print("done - on the VM open C:\\suspex\\watch\\ and double-click watch.cmd")
    finally:
        await c.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
