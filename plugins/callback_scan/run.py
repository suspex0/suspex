from __future__ import annotations

from pathlib import Path

from suspex.sdk import Reader, SuspexError

# kernel callback globals resolvable in the public ntoskrnl PDB. Arrays are
# EX_CALLBACK_ROUTINE_BLOCK* slots (low 3 bits = rundown lock); list heads are
# LIST_ENTRY walks where the callback fn sits at node+0x00's owning struct.
CALLBACK_TARGETS = {
    "process_notify": {
        "symbols": ["PspCreateProcessNotifyRoutine", "PspCreateProcessNotifyRoutineEx"],
        "kind": "array",
        "count": 8,
    },
    "thread_notify": {
        "symbols": ["PspCreateThreadNotifyRoutine", "PspCreateThreadNotifyRoutineEx"],
        "count": 64,
        "kind": "array",
    },
    "image_notify": {
        "symbols": ["PspLoadImageNotifyRoutine"],
        "kind": "array",
        "count": 8,
    },
    "bugcheck_reason": {
        "symbols": ["KeBugCheckReasonCallbackListHead"],
        "kind": "list",
        # KBUGCHECK_REASON_CALLBACK_RECORD: { LIST_ENTRY Entry (16B);
        # PCALLBACK_FUNCTION Function (+0x10); ... }
        "member_fn_offset": 0x10,
    },
    "registry_notify": {
        "symbols": ["CmpRegisterCallbackExtraList"],
        "kind": "list",
        # node = { LIST_ENTRY Link (16B); PVOID Function (+0x10); ... }
        "member_fn_offset": 0x10,
    },
}


def _u64(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


async def _fn_from_block(r: Reader, block: int) -> int | None:
    """EX_CALLBACK_ROUTINE_BLOCK (x64): { EX_RUNDOWN_REF RundownProtect (8B);
    PVOID Function (+0x08); PVOID Context (+0x10) }. The low 3 bits of the
    slot are the rundown lock, not a pointer tag — mask them off."""
    try:
        return await r.u64(block + 0x08)
    except Exception:
        return None


async def run(sdk, params: dict) -> dict:
    binary = params.get("binary_path") or "C:\\Windows\\System32\\ntoskrnl.exe"
    if not Path(binary).exists():
        return {
            "ok": True, "status": "no_binary", "severity": "warning",
            "summary": f"callback_scan: {binary} not accessible from the orchestrator host",
        }

    want = [g.lower() for g in (params.get("include_lists") or [])]
    names = [n for grp in CALLBACK_TARGETS.values() for n in grp["symbols"]]
    try:
        rvas = sdk.symbols.resolve(binary, names)
    except Exception as exc:
        return {
            "ok": True, "status": "no_symbols", "severity": "warning",
            "summary": f"callback_scan: symbol resolution failed ({type(exc).__name__}: {exc})",
        }

    mod = await sdk.mods.find("ntoskrnl.exe", kernel=True)
    if mod is None:
        raise SuspexError("ntoskrnl.exe not found in kernel view")
    base = mod["base"]
    r = Reader(lambda addr, n: sdk.mem.read(0, addr, n, space="kernel", view="kernel"))

    kernel_mods = await sdk.mods.list(kernel=True)
    by_range = []
    for m in kernel_mods:
        try:
            mb = _u64(m.get("base", 0))
            ms = _u64(m.get("size", 0))
            nm = str(m.get("name", ""))
            if mb and ms:
                by_range.append((mb, mb + ms, nm))
        except Exception:
            continue

    def owner(addr: int) -> str:
        for lo, hi, nm in by_range:
            if lo <= addr < hi:
                return nm
        return ""

    resolved: dict[str, int] = {k: v for k, v in rvas.items()}
    entries: list[dict] = []
    notes: list[str] = []

    for group, spec in CALLBACK_TARGETS.items():
        if want and group.lower() not in want:
            continue
        for sym in spec["symbols"]:
            rva = resolved.get(sym)
            if rva is None:
                notes.append(f"{sym}: not in PDB (skipped)")
                continue
            array_va = base + rva
            if spec["kind"] == "array":
                for i in range(spec.get("count", 8)):
                    try:
                        slot = await r.u64(array_va + i * 8)
                    except Exception:
                        break
                    if not slot:
                        continue
                    block = slot & ~0x7
                    fn = _fn_from_block(r, block)
                    if fn:
                        entries.append({
                            "group": group, "symbol": sym, "index": i,
                            "callback": hex(fn), "owner": owner(fn),
                        })
            else:  # LIST_ENTRY walk
                try:
                    head = array_va
                    cur = await r.u64(head)  # Flink
                    seen = set()
                    while cur and cur != head and cur not in seen and len(seen) < 256:
                        seen.add(cur)
                        try:
                            fn = await r.u64(cur + spec.get("member_fn_offset", 0))
                        except Exception:
                            fn = 0
                        if fn:
                            entries.append({
                                "group": group, "symbol": sym, "node": hex(cur),
                                "callback": hex(fn), "owner": owner(fn),
                            })
                        cur = await r.u64(cur)
                except Exception as exc:
                    notes.append(f"{sym}: walk failed ({type(exc).__name__})")

    unknown = [e for e in entries if not e["owner"]]
    severity = "warning" if unknown else "info"
    summary = (f"callback_scan: {len(entries)} callback(s) across "
               f"{len({e['group'] for e in entries})} group(s), "
               f"{len(unknown)} not attributed to a loaded module")
    return {
        "ok": True,
        "status": "scanned",
        "nt_build": sdk.nt_build,
        "resolved_symbols": {k: hex(v + base) for k, v in resolved.items()},
        "entries": entries,
        "unattributed": len(unknown),
        "notes": notes,
        "severity": severity,
        "summary": summary,
    }
