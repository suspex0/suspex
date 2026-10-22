"""Kernel-vs-usermode memory parity harness (phase 1).

Reads sampled committed regions of one target pid through BOTH views —
the kernel agent (Memory.Read space=user, driver path) and the umagent
usermode view (ReadProcessMemory) — byte-compares the results and times
both paths. Region enumeration comes from the umagent view
(VirtualQueryEx); the kernel view only needs to answer reads.

Pure orchestration: works on any two objects exposing
``mem_read(pid, address, size, space)`` and ``debug_regions(pid)``
(real AgentClients in production, fakes in tests).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

KUSER_SHARED_DATA = 0x7FFE0000  # volatile clock data mapped into every process

MAX_MISMATCH_OFFSETS = 32


def _u64(v: Any) -> int:
    # proto3 JSON mapping turns 64-bit ints into decimal strings; accept
    # hex strings too (hand-written reports/tests)
    return int(v, 0) if isinstance(v, str) else int(v)


def _readable(protect: int) -> bool:
    return bool(protect) and protect != PAGE_NOACCESS and not (protect & PAGE_GUARD)


async def run_parity(kernel: Any, user: Any, pid: int, *, samples: int = 16,
                     read_bytes: int = 4096, seed: int = 0) -> dict[str, Any]:
    """Sample committed regions of pid and compare kernel vs usermode reads."""
    try:
        regions = await user.debug_regions(pid)
    except Exception as exc:
        # region enumeration itself denied (e.g. protected process): the
        # denial asymmetry is the finding — record it, sample nothing
        reason = f"{type(exc).__name__}: {exc}"
        return {
            "pid": pid,
            "regions_error": reason,
            "summary": {
                "pid": pid,
                "regions_total": 0,
                "regions_committed": 0,
                "samples": 0,
                "compared": 0,
                "matches": 0,
                "mismatches": 0,
                "kernel_ok_user_failed": 0,
                "user_ok_kernel_failed": 0,
                "both_failed": 0,
                "volatile_skipped": 0,
                "bytes_compared": 0,
                "kernel_ms_total": 0,
                "user_ms_total": 0,
            },
            "checks": [],
            "checks_note": f"user view could not enumerate regions: {reason}",
        }
    committed = [r for r in regions
                 if _u64(r.get("state", 0)) == MEM_COMMIT and _readable(_u64(r.get("protect", 0)))]

    picked: list[dict[str, Any]] = []
    if committed:
        step = max(1, len(committed) // max(1, samples))
        picked = committed[::step][:samples]

    checks: list[dict[str, Any]] = []
    for idx, r in enumerate(picked):
        base = _u64(r.get("base", 0))
        size = _u64(r.get("size", 0))
        n = min(read_bytes, size)
        if n <= 0:
            continue
        off = ((seed + idx * 0x9E3779B97F4A7C15) % (size - n)) if size > n else 0
        addr = base + off

        entry: dict[str, Any] = {
            "address": hex(addr),
            "bytes": n,
            "region_base": hex(base),
            "region_size": size,
            "protect": _u64(r.get("protect", 0)),
            "type": _u64(r.get("type", 0)),
            "module": r.get("module", ""),
        }

        t0 = time.perf_counter()
        kdata: bytes | None = None
        try:
            kdata = await kernel.mem_read(pid, addr, n, "user")
        except Exception as exc:
            entry["kernel_error"] = f"{type(exc).__name__}: {exc}"
        entry["kernel_ms"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        udata: bytes | None = None
        try:
            udata = await user.mem_read(pid, addr, n, "user")
        except Exception as exc:
            entry["user_error"] = f"{type(exc).__name__}: {exc}"
        entry["user_ms"] = round((time.perf_counter() - t0) * 1000, 3)

        if kdata is not None:
            entry["kernel_sha256"] = hashlib.sha256(kdata).hexdigest()
        if udata is not None:
            entry["user_sha256"] = hashlib.sha256(udata).hexdigest()
        if base == KUSER_SHARED_DATA:
            # volatile kernel-mapped clock page: reads never compare equal
            entry["note"] = "volatile KUSER_SHARED_DATA page: comparison skipped"
        elif kdata is not None and udata is not None:
            entry["match"] = kdata == udata
            if not entry["match"]:
                # live memory legitimately mutates between the two reads
                # (kernel first, then user): re-read both once and only report
                # a mismatch that is stable across consecutive observations
                k2 = u2 = None
                try:
                    k2 = await kernel.mem_read(pid, addr, n, "user")
                except Exception:
                    pass
                try:
                    u2 = await user.mem_read(pid, addr, n, "user")
                except Exception:
                    pass
                if k2 is not None and u2 is not None and k2 == u2:
                    entry["match"] = True
                    entry["note"] = "initial mismatch was transient (volatile memory)"
                else:
                    span = min(len(kdata), len(udata))
                    diffs = [i for i in range(span) if kdata[i] != udata[i]]
                    entry["mismatch_count"] = len(diffs)
                    entry["mismatch_offsets"] = [hex(i) for i in diffs[:MAX_MISMATCH_OFFSETS]]
        checks.append(entry)

    summary = {
        "pid": pid,
        "regions_total": len(regions),
        "regions_committed": len(committed),
        "samples": len(checks),
        "compared": sum(1 for c in checks if "match" in c),
        "matches": sum(1 for c in checks if c.get("match") is True),
        "mismatches": sum(1 for c in checks if c.get("match") is False),
        "kernel_ok_user_failed": sum(1 for c in checks
                                     if "kernel_error" not in c and "user_error" in c),
        "user_ok_kernel_failed": sum(1 for c in checks
                                     if "user_error" not in c and "kernel_error" in c),
        "both_failed": sum(1 for c in checks
                           if "kernel_error" in c and "user_error" in c),
        "volatile_skipped": sum(1 for c in checks if "note" in c),
        "bytes_compared": sum(c["bytes"] for c in checks if "match" in c),
        "kernel_ms_total": round(sum(c["kernel_ms"] for c in checks), 3),
        "user_ms_total": round(sum(c["user_ms"] for c in checks), 3),
    }
    return {"pid": pid, "summary": summary, "checks": checks}


def verdict(report: dict[str, Any]) -> tuple[str, str]:
    """(severity, reason) for the findings ledger."""
    s = report["summary"]
    if report.get("regions_error"):
        return "warning", f"user view cannot enumerate regions (target protected or dead): {report['regions_error']}"
    if s["mismatches"]:
        return "high", f"{s['mismatches']} byte mismatch(es) between kernel and usermode views"
    if s["samples"] == 0 or (s["compared"] == 0 and not s.get("volatile_skipped")):
        return "high", "no readable samples compared on both paths"
    if s["kernel_ok_user_failed"] or s["user_ok_kernel_failed"]:
        return ("warning",
                f"error asymmetry: kernel-only-ok {s['kernel_ok_user_failed']}, "
                f"user-only-ok {s['user_ok_kernel_failed']}")
    volatile = s.get("volatile_skipped", 0)
    suffix = f" (+{volatile} volatile skipped)" if volatile else ""
    return "info", f"parity: {s['compared']} sample(s) match byte-for-byte{suffix}"


def format_report(report: dict[str, Any]) -> str:
    s = report["summary"]
    if report.get("regions_error"):
        return (f"parity pid={s['pid']}: user view could not enumerate regions "
                f"({report['regions_error']})\n  no samples compared - error asymmetry recorded")
    lines = [
        f"parity pid={s['pid']}: regions {s['regions_total']} "
        f"({s['regions_committed']} committed), samples {s['samples']}",
        f"  compared {s['compared']} ({s['bytes_compared']} bytes): "
        f"{s['matches']} match, {s['mismatches']} MISMATCH",
        f"  volatile skipped: {s.get('volatile_skipped', 0)}",
        f"  error asymmetry: kernel-only-ok {s['kernel_ok_user_failed']}, "
        f"user-only-ok {s['user_ok_kernel_failed']}, both-failed {s['both_failed']}",
        f"  time: kernel {s['kernel_ms_total']}ms, usermode {s['user_ms_total']}ms",
    ]
    for c in report["checks"]:
        if c.get("match") is False or "kernel_error" in c or "user_error" in c:
            bits = [f"@ {c['address']} ({c['bytes']}B {c.get('module') or 'anon'})"]
            if c.get("match") is False:
                bits.append(f"MISMATCH count={c.get('mismatch_count')} "
                            f"first={c.get('mismatch_offsets', [])[:8]}")
            if "kernel_error" in c:
                bits.append(f"kernel: {c['kernel_error']}")
            if "user_error" in c:
                bits.append(f"user: {c['user_error']}")
            lines.append("  " + " | ".join(bits))
    return "\n".join(lines)
