"""End-to-end breakpoint test over the agent gRPC (bypasses MCP param layer).

Flow: launch cmd.exe under DbgEng (break at entry) -> set a software breakpoint
at a computed address (ntdll!NtCreateFile resolved via the VM's own kernel32 /
ntdll export table walk - no symbol server needed) -> continue -> expect a
breakpoint hit -> read RIP -> cleanup.

Usage:
  .venv/Scripts/python.exe scripts\\bp_e2e_test.py --host 192.168.56.10 --token <tok>
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

from suspex.agent_client import AgentClient  # noqa: E402


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


async def resolve_export(c: AgentClient, pid: int, module: str, export: str) -> int:
    """Resolve an exported function VA by walking the module's export table
    through memory reads (no PDB/symbols required)."""
    mods = await c.mem_modules(pid)
    target = None
    for m in mods:
        if str(m.get("name", "")).lower() == module:
            target = m
            break
    if target is None:
        raise RuntimeError(f"module {module} not found")
    base = int(target["base"], 0) if isinstance(target["base"], str) else int(target["base"])

    hdr = await c.mem_read(pid, base, 0x1000, "user")
    if hdr[:2] != b"MZ":
        raise RuntimeError(f"bad MZ at {hex(base)} (pid {pid}): first bytes {hdr[:16].hex()}")
    pe = _u32(hdr, 0x3C)
    if hdr[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError(f"bad PE sig at {hex(base)}: e_lfanew={pe} bytes={hdr[pe:pe+8].hex()}")
    opt = pe + 24
    magic = _u32(hdr, opt) & 0xFFFF
    if magic != 0x20B:
        raise RuntimeError(f"not PE32+: magic={hex(magic)} base={hex(base)} pid={pid} "
                           f"nt_hdrs={hdr[pe:pe+24].hex()}")
    exp_rva = _u32(hdr, opt + 112)
    exp_size = _u32(hdr, opt + 116)
    if not exp_rva:
        raise RuntimeError("no export directory")

    blob = await c.mem_read(pid, base + exp_rva, min(exp_size, 0x100000), "user")
    names_count = _u32(blob, 0x18)
    funcs_rva = _u32(blob, 0x1C)
    names_rva = _u32(blob, 0x20)
    ords_rva = _u32(blob, 0x24)
    # the three tables live at module RVAs; blob starts at exp_rva
    f = lambda rva: rva - exp_rva

    name_rvas = [_u32(blob, f(names_rva) + i * 4) for i in range(names_count)]
    # batch-read the name strings: one block covering min..max
    lo, hi = min(name_rvas), max(name_rvas) + 64
    block = await c.mem_read(pid, base + lo, hi - lo, "user")

    for i in range(names_count):
        off = name_rvas[i] - lo
        name = block[off:off + 64].split(b"\0")[0].decode("ascii", "replace")
        if name.lower() == export.lower():
            # AddressOfNameOrdinals[i] is a direct index into AddressOfFunctions
            # (a 16-bit slot number, NOT an ordinal relative to `ordinal_base`).
            fn_idx = int.from_bytes(blob[f(ords_rva) + i * 2:f(ords_rva) + i * 2 + 2],
                                    "little")
            fn_rva = _u32(blob, f(funcs_rva) + fn_idx * 4)
            return base + fn_rva
    raise RuntimeError(f"export {export} not found in {module}")


def _i(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=50074)
    ap.add_argument("--token", required=True)
    args = ap.parse_args()

    c = AgentClient(args.host, args.port, args.token)
    await asyncio.wait_for(c.connect(), timeout=10)
    try:
        # 0. make sure the driver is up (user-mode reads route through it)
        res = await c.driver_load(method="service")
        print(f"==> driver_load: {res.get('ok')}")

        # consume the debug event stream locally (nothing else pumps it)
        events: list[dict] = []

        async def pump() -> None:
            try:
                async for ev in c.debug_events(from_seq=0):
                    events.append(ev)
            except Exception:
                pass

        pump_task = asyncio.create_task(pump())

        # 1. launch a LONG-RUNNING debuggee (short-lived targets race the
        #    session-end semantics of dbgeng on 24H2+)
        print("==> launch ping (under debugger, break at entry)")
        try:
            res = await c.debug_launch(
                r"ping.exe -n 30 127.0.0.1", "", break_on_entry=True)
        except RuntimeError as exc:
            if "already active" not in str(exc):
                raise
            print("    stale session found - detaching with kill, retrying")
            await c.debug_detach(True)
            await asyncio.sleep(1)
            res = await c.debug_launch(
                r"ping.exe -n 30 127.0.0.1", "", break_on_entry=True)
        print(f"    {res}")
        dbg_pid = _i(res["pid"])

        # 2. current regs at the entry breakpoint
        regs = await c.debug_regs()
        rip = _i(regs["rip"])
        print(f"==> at entry breakpoint: rip={hex(rip)} rsp={hex(_i(regs['rsp']))}")

        # 3. resolve ntdll!NtDelayExecution and set an int3. On modern Windows
        #    kernel32.dll is a compatibility shim that forwards to KERNELBASE
        #    via ApiSet - a bp on kernel32!Sleep never fires because ping.exe's
        #    IAT is redirected. NtDelayExecution is the syscall stub every
        #    Sleep call must cross.
        addr = await resolve_export(c, dbg_pid, "ntdll.dll", "NtDelayExecution")
        print(f"==> ntdll!NtDelayExecution = {hex(addr)}")
        orig = await c.debug_read(addr, 1)
        print(f"==> original byte at target: {orig.hex()}")

        bp = await c.bp_add("sw", addr, 0, 1, "exec", False, 0, 0)
        print(f"==> bp_add: {bp}")

        # 4. continue: ping will call NtDelayExecution between echo requests.
        # Hit detection goes through debug EVENTS (regs-success alone is a
        # false positive once the process exits - stale context is returned).
        seq0 = max((_i(e.get("seq", 0)) for e in events), default=0)
        entry_rip = _i(regs["rip"])
        print("==> debug_continue, then wait for hit (watching event stream)...")
        cr = await c.debug_continue()
        print(f"    debug_continue: {cr}")
        t0 = time.time()
        hit = False
        regs = {}
        hit_ev = None
        while time.time() - t0 < 15:
            evs = [e for e in events if _i(e.get("seq", 0)) > seq0]
            for ev in evs:
                k = str(ev.get("kind", "")).lower()
                # agent event.kind values are "bp_sw" / "bp_hw" / "exception"
                if k.startswith("bp_") or "breakpoint" in k or "exception" in k:
                    hit, hit_ev = True, ev
                    break
            if hit:
                break
            await asyncio.sleep(0.3)
        if not hit:
            rip_now = None
            try:
                regs = await c.debug_regs()
                rip_now = _i(regs["rip"])
            except RuntimeError:
                rip_now = None  # still running
            ran = None
            try:
                await c.file_hash(r"C:\suspex\bp_hit_test.txt")
                ran = True
            except Exception:
                ran = False
            print(f"FAIL: no breakpoint event within 15s (events seen: "
                  f"{[str(e.get('kind')) for e in events][-6:]})")
            print(f"    rip_now={hex(rip_now) if rip_now is not None else 'RUNNING'} "
                  f"(entry was {hex(entry_rip)}); cmd wrote file: {ran}")
            try:
                le = await c.dbg_cmd(".lastevent")
                print("    .lastevent:", le[:300])
                rr = await c.dbg_cmd("r")
                print("    r:", rr[:300])
            except Exception as exc:
                print(f"    diag cmds failed: {exc}")
            pump_task.cancel()
            await c.debug_detach(True)
            return 1

        # 5. stopped on the int3: read registers now
        await asyncio.sleep(0.3)
        regs = await c.debug_regs()
        rip = _i(regs["rip"])
        print(f"==> HIT after {time.time() - t0:.1f}s: rip={hex(rip)} (bp at {hex(addr)})")
        if hit_ev:
            print(f"==> event: seq={hit_ev.get('seq')} kind={hit_ev.get('kind')} "
                  f"addr={hex(_i(hit_ev.get('address', 0)))}")
        rip_hits = rip == addr or rip == addr + 1

        # 6. cleanup: remove bp, let ping run out, detach
        pump_task.cancel()
        try:
            await c.debug_continue()
        except RuntimeError:
            # target may already have hit another event or exited
            pass
        await asyncio.sleep(1.5)
        await c.debug_detach(True)

        if rip_hits:
            print("\nBREAKPOINT TEST PASSED (sw int3 set, hit, regs read, cleaned up)")
            return 0
        print("\nBREAKPOINT TEST INCONCLUSIVE (stopped but rip far from bp)")
        return 1
    finally:
        await c.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
