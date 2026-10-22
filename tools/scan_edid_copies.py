"""Chunked kernel-pool EDID-copy scanner (host-side, AgentClient direct).

Scans a VA range in 64KB chunks with inter-call delays; tolerates unmapped
chunks. Reports hits for two patterns: REAL (09d1327f) and FORGED (09d1337f).

usage: python scan_edid_copies.py [start_hex] [len_hex]
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))
from suspex.agent_client import AgentClient  # noqa: E402

HOST = os.environ.get("SUSPEX_HOST", "127.0.0.1")
PORT = int(os.environ.get("SUSPEX_PORT", "50074"))
TOKEN = os.environ.get("SUSPEX_TOKEN", "")
CHUNK = 0x8000
DELAY_S = 0.05
HDR = bytes.fromhex("00ffffffffffff00")
SIG = {"REAL": bytes.fromhex("09d1327f"), "FORGED": bytes.fromhex("09d1337f")}


async def main() -> None:
    start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xffffa40380000000
    total = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x20000000
    if not TOKEN:
        sys.exit("set SUSPEX_TOKEN to the agent token (see configs/local.yaml)")
    cl = AgentClient(HOST, PORT, TOKEN, timeout_ms=8000)
    await cl.connect()
    print(f"[*] connected; scan {start:#x} .. {start + total:#x} ({total >> 20} MB)")
    hits = []
    fails = 0
    scan_fail_streak = 0
    for off in range(0, total, CHUNK):
        addr = start + off
        try:
            data = await asyncio.wait_for(
                cl.mem_read(0, addr, CHUNK, "kernel"), timeout=8)
        except Exception:
            fails += 1
            scan_fail_streak += 1
            if scan_fail_streak >= 256:
                print(f"[!] 256 consecutive unreadable chunks at {addr:#x}; aborting")
                break
            continue
        scan_fail_streak = 0
        for tag, sig in SIG.items():
            i = data.find(HDR + sig)
            while i != -1:
                hits.append((addr + i, tag))
                print(f"[HIT] {addr + i:#x} {tag}")
                i = data.find(HDR + sig, i + 1)
        if off % (CHUNK * 64) == 0:
            print(f"    ..{addr:#x}")
        await asyncio.sleep(DELAY_S)
    print(f"[*] done: {len(hits)} hits, {fails} unreadable chunks")
    for a, t in hits:
        print(f"  {a:#x} {t}")


asyncio.run(main())
