"""WP4 lab smoke: write_path reporting, STRICT_VA, va_translate cr3/user, IdtList.

Run: orchestrator/.venv/Scripts/python.exe scripts/smoke_wp4.py
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

from suspex.agent_client import AgentClient  # noqa: E402

HOST = os.environ.get("SUSPEX_HOST", "127.0.0.1")
PORT = int(os.environ.get("SUSPEX_PORT", "50074"))
TOKEN = os.environ.get("SUSPEX_TOKEN", "")

fails = []


def check(name: str, cond: bool, detail: str = "") -> None:
    tag = "PASS" if cond else "FAIL"
    print(f"[{tag}] {name} {detail}")
    if not cond:
        fails.append(name)


async def main() -> int:
    if not TOKEN:
        sys.exit("set SUSPEX_TOKEN to the agent token (see configs/local.yaml)")
    c = AgentClient(HOST, PORT, TOKEN, timeout_ms=15000)
    await c.connect()
    try:
        # ---- idt_list: current CPU ----
        r = await c.idt_list(all_cpus=False)
        ents = r["entries"]
        check("idt_list single-cpu rows", len(ents) > 0 and len(ents) <= 256,
              f"count={len(ents)} base={hex(r['idt_base'])} limit={hex(r['idt_limit'])}")
        good = sum(1 for e in ents
                   if (e["handler_va"] >> 48) == 0xFFFF or e["handler_va"] == 0)
        check("idt_list handlers canonical", good == len(ents), f"{good}/{len(ents)}")
        check("idt_list per-row base", all(e.get("idt_base") for e in ents),
              f"sample={hex(ents[0].get('idt_base', 0))}")

        # ---- idt_list: all CPUs ----
        r2 = await c.idt_list(all_cpus=True)
        cpus = sorted({e["cpu"] for e in r2["entries"]})
        check("idt_list all_cpus rows", len(r2["entries"]) > len(ents),
              f"count={len(r2['entries'])} cpus={cpus}")

        # ---- kernel write: direct path ----
        va = await c.mem_alloc(0, 0x1000, 4, kernel=True)
        check("kmem_alloc", va > 0xFFFF000000000000, hex(va))
        w = await c.mem_write(0, va, b"WP4WP4WP", "kernel")
        check("kernel write path direct_va", w["write_path"] == "direct_va",
              f"res={w}")
        back = await c.mem_read(0, va, 8, "kernel")
        check("kernel write landed", back == b"WP4WP4WP", back.hex())

        # ---- strict_va on a read-only kernel page ----
        # ntoskrnl .text is RX — direct VA store faults; strict must refuse
        # the remap, non-strict must report phys_remap. Write back the byte
        # that's already there so the phys write is content-identical.
        mods = await c.mem_modules(0, True)
        nt = next(m for m in mods if m["name"].lower() == "ntoskrnl.exe")
        _b = nt["base"]
        ro_va = (int(_b, 0) if isinstance(_b, str) else _b) + 0x1000
        cur = (await c.mem_read(0, ro_va, 1, "kernel"))[0]
        try:
            await c.mem_write(0, ro_va, bytes([cur]), "kernel", strict_va=True)
            check("strict_va refuses RO page", False, "write succeeded")
        except RuntimeError as exc:
            check("strict_va refuses RO page", True, str(exc)[:80])
        w2 = await c.mem_write(0, ro_va, bytes([cur]), "kernel")
        check("non-strict falls back phys_remap",
              w2["write_path"] == "phys_remap", f"res={w2}")
        back2 = (await c.mem_read(0, ro_va, 1, "kernel"))[0]
        check("RO page byte unchanged", back2 == cur,
              f"before={cur:#x} after={back2:#x}")

        # ---- va_translate: kernel ----
        t = await c.mem_va_translate(va, space="kernel")
        check("va_translate kernel", t["present"] and t["pa"] != 0,
              f"{t}")
        check("va_translate reports cr3+shift",
              t["cr3"] != 0 and t["page_size_shift"] in (12, 21, 30), f"{t}")

        # ---- va_translate: user (agent's own process + its image base) ----
        procs = await c.mem_processes()
        agent_pid = next(int(p["pid"]) for p in procs
                         if "suspex_agent" in str(p.get("image_name", "")).lower())
        umods = await c.mem_modules(agent_pid)
        _ub = umods[0]["base"]
        ubase = int(_ub, 0) if isinstance(_ub, str) else _ub
        t2 = await c.mem_va_translate(ubase, space="user", pid=agent_pid)
        check("va_translate user", t2["present"] and t2["pa"] != 0, f"{t2}")
        check("va_translate user cr3 != kernel cr3",
              t2["cr3"] != t["cr3"], f"user={hex(t2['cr3'])} kern={hex(t['cr3'])}")

        # ---- va_translate: explicit cr3 override ----
        t3 = await c.mem_va_translate(ubase, space="user", pid=agent_pid,
                                    cr3=t2["cr3"])
        check("va_translate explicit cr3", t3["pa"] == t2["pa"], f"{t3}")

        # ---- foreign-cr3 write (stretch): write under the user proc's CR3.
        # Target must be present+writable under the foreign root — a fresh
        # user alloc is; the image header page is RO and (correctly) refused.
        uva = await c.mem_alloc(agent_pid, 0x1000, 4)
        seed = await c.mem_read(agent_pid, uva, 16, "user")
        try:
            w3 = await c.mem_write(0, uva, b"FGN-CR3-TEST....", "kernel",
                                   cr3=t2["cr3"])
            check("foreign_cr3 write", w3["write_path"] == "foreign_cr3",
                  f"res={w3}")
            uback = await c.mem_read(agent_pid, uva, 16, "user")
            check("foreign_cr3 landed", uback == b"FGN-CR3-TEST....",
                  uback.hex())
            # restore
            await c.mem_write(agent_pid, uva, seed, "user")
            # and a refusal: user RO page (image header) under same cr3
            try:
                await c.mem_write(0, ubase, b"X", "kernel", cr3=t2["cr3"])
                check("foreign_cr3 refuses RO dst", False, "write succeeded")
            except RuntimeError as exc:
                check("foreign_cr3 refuses RO dst", True, str(exc)[:60])
        except RuntimeError as exc:
            check("foreign_cr3 write", False, str(exc)[:100])
        await c.mem_free(agent_pid, uva)

        await c.mem_free(0, va, True)
    finally:
        await c.close()

    print()
    if fails:
        print("FAILURES:", fails)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
