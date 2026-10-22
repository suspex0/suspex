"""v8 smoke over gRPC: Watchdog arm/kick/list/disarm + LogFollow stream."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))
from suspex.agent_client import AgentClient  # noqa: E402

HOST = os.environ.get("SUSPEX_HOST", "127.0.0.1")
PORT = int(os.environ.get("SUSPEX_PORT", "50074"))
KERNEL_LOG = os.environ.get("SUSPEX_KERNEL_LOG", r"C:\Users\Public\Desktop\suspex_kernel.log")


async def main() -> int:
    tok = os.environ.get("SUSPEX_TOKEN", "")
    if not tok:
        sys.exit("set SUSPEX_TOKEN to the agent token (see configs/local.yaml)")
    c = AgentClient(HOST, PORT, tok)
    await c.connect()
    try:
        # --- Watchdog gRPC ---
        arm = await c.watchdog_arm(0xC0FFEE, 30000, label="v8smoke")
        print("arm:", arm.get("ok"), arm.get("error", ""))
        kick = await c.watchdog_kick(0xC0FFEE)
        print("kick:", kick.get("ok"), "kick_count=", kick.get("kick_count"))
        lst = await c.watchdog_list()
        entries = lst.get("entries", [])
        print("list:", lst.get("ok"), "count=", len(entries))
        for e in entries:
            print("   ", {k: e.get(k) for k in ("id", "label", "kick_count", "deadline_ms")})
        dis = await c.watchdog_disarm(0xC0FFEE)
        print("disarm:", dis.get("ok"))
        if not (arm.get("ok") and kick.get("ok") and dis.get("ok") and len(entries) >= 1):
            print("WATCHDOG SMOKE FAIL")
            return 1

        # --- LogFollow stream (bounded) ---
        n_chunks = 0
        total = 0
        async for chunk in c.log_follow_iter(KERNEL_LOG, initial_tail_bytes=4096,
                                             max_bytes=16384, duration_s=15):
            n_chunks += 1
            total += len(chunk.data)
            print(f"follow chunk {n_chunks}: eof={chunk.eof} bytes={len(chunk.data)} "
                  f"total={total} reason={chunk.reason!r}")
            if chunk.eof or n_chunks >= 5:
                break
        print("follow chunks:", n_chunks)
        if n_chunks == 0 or total == 0:
            print("LOGFOLLOW SMOKE FAIL (no data)")
            return 1
        print("V8 GRPC SMOKE OK")
        return 0
    finally:
        await c.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
