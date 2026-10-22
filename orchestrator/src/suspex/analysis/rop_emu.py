"""Unicorn-backed gadget / chain validation for ``bin_manage``.

The ``gadget_check`` and ``chain_check`` actions execute candidate
gadgets and ROP chains on a private Unicorn CPU and report what
actually happened — control-flow continuity, register effects, rsp
movement, memory writes — instead of trusting the pattern classifier.
This is the executor half of the exploit-dev loop: build a chain from
``gadgets`` rows (real live VAs for ``source='memory'``), then validate
it here before spending it against a target.

Design:

* One-shot engine per call (``_UnicornEngine`` constructed directly —
  no session-registry bookkeeping). The image's sections are mapped at
  their real VAs (protections from the PE flags), so kernel-VA chains
  validate exactly like userspace ones; Unicorn does not care that the
  addresses are kernel-range.
* A sentinel page of ``ret`` bytes at ``SENTINEL_VA`` is the return
  trampoline — reaching it means the chain was consumed cleanly.
* GPRs are seeded with pointers into a mapped scratch region (filled
  with sentinel qwords), so ``mov rax, [rcx]``-style gadgets read
  deterministic mapped memory and ``mov rsp, rax`` pivots land on a
  ret-sled instead of faulting immediately. ``pop`` targets land
  sentinel values — visible in the register diff.
* Hooks record every executed instruction VA (capped), memory writes
  (capped), and unmapped accesses (read/write/fetch) — the latter stop
  the emulation cleanly with a classified fault instead of a raw
  UcError.

Honest scope: this validates mechanical execution — control-flow
continuity, final register/stack state, side effects. Syscall/sysenter
instructions are NOT emulated (they fault), API effects don't exist,
and "completed" means "the CPU walked the chain to the sentinel", not
"the exploit works". Every response carries that note.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Any

from ..codegen import _load_unicorn
from .engine import ImageView

# Synthetic regions — page-aligned, well clear of user module bases
# (0x140000000+), the engine's stack (0x7fff00000000-), and kernel
# module VAs (0xfffff8…).
SENTINEL_VA = 0x0000_DEAD_0000
SCRATCH_VA = 0x0000_BEEF_0000
SCRATCH_SIZE = 0x2000

_STACK_HEADROOM = 0x8000       # move rsp down this far before filling
_SENTINEL_FILL_QWORDS = 64     # qwords of sentinel after rsp / the chain
_MAX_TRACE = 4096              # executed-insn VA cap per run
_MAX_TRACE_ROWS = 256          # chain-entry trace rows in the response
_MAX_WRITES = 64
_MASK64 = (1 << 64) - 1

# Unicorn 2.1.x only *executes* guest VAs up to 52 bits — TCG masks every
# guest access (fetch and data alike) to 52 bits, while the memory API
# and the register file keep full 64-bit values. Kernel VAs (0xFFFFF8…)
# therefore have to be mapped masked; code, RIP-relative and absolute
# references stay mutually consistent because the CPU masks them all the
# same way. Verified on unicorn 2.1.4/Windows: a region mapped at
# `va & mask` executes with a full 64-bit RIP, absolute 64-bit data
# references resolve, code hooks report full VAs, write/fault hooks
# report masked ones (`_unmask` maps those back for reporting).
_UC_VA_MASK = (1 << 52) - 1


def _reloc(va: int) -> int:
    """Unicorn-executable form of a VA (identity below 2^52)."""
    return va & _UC_VA_MASK

_GP_SEED_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

_NOTE = ("mechanical validation only — control-flow continuity + final "
         "state; syscall/sysenter and API effects are not emulated")


@dataclass
class _EmuCtx:
    eng: Any
    uc: Any
    view: ImageView
    code_trace: list[int] = field(default_factory=list)
    insn_count: int = 0
    writes: list[dict] = field(default_factory=list)
    unmapped: list[dict] = field(default_factory=list)
    mapped_ranges: list[tuple[int, int, str]] = field(default_factory=list)
    # (orig_start, orig_end, masked_start) for regions relocated into the
    # 52-bit executable space — used to un-mask hook-reported addresses.
    reloc_ranges: list[tuple[int, int, int]] = field(default_factory=list)
    # masked VA -> known full VA (gadget VA, chain entries) for exact
    # un-masking of fault addresses that were never mapped.
    known_vas: dict[int, int] = field(default_factory=dict)
    skipped_sections: list[str] = field(default_factory=list)


def _unmask(ctx: _EmuCtx, va: int) -> int:
    """Map a masked hook-reported VA back to its original 64-bit form:
    inside a relocated region, or equal to a known chain/gadget VA
    (identity otherwise — the low 52 bits are still exact)."""
    for orig_start, orig_end, mstart in ctx.reloc_ranges:
        if mstart <= va < mstart + (orig_end - orig_start):
            return va - mstart + orig_start
    return ctx.known_vas.get(va, va)


def _reloc_note(ctx: _EmuCtx) -> str:
    return ("; kernel VAs are mapped into unicorn's 52-bit executable "
            "space — fault addresses that match no known chain/image VA "
            "are reported masked" if ctx.reloc_ranges else "")


# ---------------------------------------------------------------------------
# Engine preparation
# ---------------------------------------------------------------------------

def _prot_of(section) -> str:
    prot = "r"
    if section.writable:
        prot += "w"
    if section.exec:
        prot += "x"
    return prot


def _map_region(ctx: _EmuCtx, va: int, data: bytes, prot: str,
                label: str) -> None:
    """Map [va, va+len) page-aligned (if not already) and write bytes.

    The region lands at ``_reloc(va)`` — identity below 2^52, masked for
    kernel VAs (see ``_UC_VA_MASK``). The memory API is not masked by
    Unicorn, so both the map and the write use the relocated address.
    """
    if not data:
        return
    mva = _reloc(va)
    start = mva & ~0xFFF
    end = (mva + len(data) + 0xFFF) & ~0xFFF
    for s, e, _l in ctx.mapped_ranges:
        if start < e and s < end:
            # Page shared with an existing mapping (sub-page section
            # alignment) — bytes still land, protection stays as first
            # mapped.
            ctx.eng.mem_write(mva, data)
            return
    try:
        ctx.eng.mem_map(start, end - start, prot, label)
    except Exception:
        ctx.skipped_sections.append(label)
        return
    ctx.mapped_ranges.append((start, end, label))
    if mva != va:
        ctx.reloc_ranges.append((va, va + len(data), mva))
    ctx.eng.mem_write(mva, data)


def _prepare_engine(view: ImageView) -> _EmuCtx:
    """Fresh engine, image sections mapped at their real VAs, sentinel +
    scratch regions, seeded GPRs, and trace/write/fault hooks."""
    from ..emulate.unicorn_engine import _UnicornEngine

    eng = _UnicornEngine("x64")
    uc = _load_unicorn()
    ctx = _EmuCtx(eng=eng, uc=uc, view=view)

    img = view.img
    base = view.base_va
    if img is None:
        # Blob source: the whole buffer is executable by definition.
        for s, e in view.exec_ranges():
            _map_region(ctx, s, view.read(s, e - s), "rwx", "blob")
    else:
        for sec in img.sections:
            span = max(sec.vsize, sec.raw_size)
            if span <= 0:
                continue
            n = sec.raw_size if img.layout == "file" else span
            va = base + sec.va
            data = view.read(va, n)
            if not data:
                continue
            _map_region(ctx, va, data,
                        _prot_of(sec), (sec.name or "").strip("\0"))

    # Sentinel return trampoline — a page of rets.
    eng.mem_map(SENTINEL_VA, 0x1000, "rx", "sentinel")
    eng.mem_write(SENTINEL_VA, b"\xC3" * 0x1000)

    # Scratch region filled with sentinel qwords: seeded register
    # pointers read as return addresses, so pivots land on a ret-sled
    # and pointer-chasing gadgets complete deterministically.
    eng.mem_map(SCRATCH_VA, SCRATCH_SIZE, "rw", "scratch")
    eng.mem_write(SCRATCH_VA,
                  struct.pack("<Q", SENTINEL_VA) * (SCRATCH_SIZE // 8))

    # Seed GPRs into the scratch region; rsp gets headroom for the
    # synthetic chain / sentinel fill.
    regs = {r: SCRATCH_VA + 0x100 + i * 0x40
            for i, r in enumerate(_GP_SEED_REGS)}
    regs["rsp"] = (eng.read_regs()["rsp"] - _STACK_HEADROOM) & _MASK64
    eng.write_regs(regs)

    # Hooks: full code trace, memory writes, unmapped-access classifier.
    def _code_cb(mu, address, size, user):
        ctx.insn_count += 1
        if len(ctx.code_trace) < _MAX_TRACE:
            ctx.code_trace.append(address)

    def _write_cb(mu, access, address, size, value, user):
        # Write hooks report the *masked* address for relocated regions.
        if len(ctx.writes) < _MAX_WRITES:
            ctx.writes.append({"va": _unmask(ctx, address), "size": size,
                               "value": value})

    # Fault hooks deliver the *detailed* access constants
    # (UC_MEM_FETCH_PROT etc.), not the base read/write/fetch trio.
    access_names: dict[int, str] = {}
    for const, label in (("UC_MEM_READ", "read"),
                         ("UC_MEM_WRITE", "write"),
                         ("UC_MEM_FETCH", "fetch"),
                         ("UC_MEM_READ_UNMAPPED", "read"),
                         ("UC_MEM_WRITE_UNMAPPED", "write"),
                         ("UC_MEM_FETCH_UNMAPPED", "fetch"),
                         ("UC_MEM_READ_PROT", "read"),
                         ("UC_MEM_WRITE_PROT", "write"),
                         ("UC_MEM_FETCH_PROT", "fetch")):
        v = getattr(uc, const, None)
        if v is not None:
            access_names[v] = label

    def _mk_fault_cb(kind: str):
        def _cb(mu, access, address, size, value, user):
            acc = access_names.get(access, str(access))
            ctx.unmapped.append({"access": acc, "kind": kind,
                                 "va": _unmask(ctx, address), "size": size})
            return False  # stop emulation cleanly instead of raising
        return _cb

    eng.uc_hook(uc.UC_HOOK_CODE, _code_cb)
    eng.uc_hook(uc.UC_HOOK_MEM_WRITE, _write_cb)
    # Both classes matter: a fetch into the mapped-but-non-exec scratch
    # region is a protection fault, an entry pointing at a hole is
    # unmapped — the response distinguishes them via `kind`.
    eng.uc_hook(uc.UC_HOOK_MEM_UNMAPPED, _mk_fault_cb("unmapped"))
    eng.uc_hook(uc.UC_HOOK_MEM_PROT, _mk_fault_cb("prot"))
    return ctx


def _disasm_at(view: ImageView, va: int, max_ins: int = 16) -> list[str]:
    """Disassemble from *va*, stopping at the first terminator."""
    from .engine import _Decoder
    from .rop import _ending_of

    dec = _Decoder()
    data = view.read(va, 15 * max_ins)
    if not data:
        return []
    out: list[str] = []
    for ins in dec.decode(data, va, max_ins):
        out.append(f"{ins.mnemonic} {ins.op_str}".strip())
        if _ending_of(ins) is not None:
            break
    return out


def _verdict(ctx: _EmuCtx, res: dict, max_ins: int,
             completed: str = "returns") -> str:
    if ctx.unmapped:
        return f"fault:{ctx.unmapped[0]['access']}"
    if res["end_ip"] == SENTINEL_VA:
        return completed
    if res["halt_reason"] != "ok":
        return "fault:exception"
    if ctx.insn_count >= max_ins:
        return "cap"
    return "diverged"


def _regs_diff(regs_in: dict, regs_out: dict) -> dict:
    out = {}
    for r, v in regs_out.items():
        if r == "rip":
            continue
        if regs_in.get(r) != v:
            out[r] = v
    return out


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_gadget(view: ImageView, va: int, *, max_ins: int = 32,
                    stack_qwords: list[int] | None = None,
                    timeout_s: float = 10.0) -> dict:
    """Execute one gadget at *va* and report what it did.

    ``stack_qwords`` optionally seeds the synthetic stack (laid at rsp,
    sentinel fill after) — e.g. for a ``pop rsp`` gadget whose new stack
    you want to control.
    """
    if not isinstance(va, int) or va <= 0:
        raise ValueError("gadget_check: target= must be a positive VA")
    if not view.is_exec(va):
        raise ValueError(
            f"gadget_check: {va:#x} is not inside an executable region "
            "of this source")

    ctx = _prepare_engine(view)
    ctx.known_vas[_reloc(va)] = va
    eng = ctx.eng
    rsp0 = eng.read_regs()["rsp"]
    fill = struct.pack("<Q", SENTINEL_VA) * _SENTINEL_FILL_QWORDS
    if stack_qwords:
        blob = b"".join(struct.pack("<Q", int(q) & _MASK64)
                        for q in stack_qwords)
        eng.mem_write(rsp0, blob)
        eng.mem_write(rsp0 + len(blob), fill)
    else:
        eng.mem_write(rsp0, fill)

    regs_in = eng.read_regs()
    eng.write_regs({"rip": va})
    t0 = time.time()
    res = eng.run(until=SENTINEL_VA, max_ins=max_ins, timeout_s=timeout_s)
    regs_out = eng.read_regs()

    out = {
        "ok": True,
        "va": va,
        "disasm": _disasm_at(view, va),
        "verdict": _verdict(ctx, res, max_ins),
        "end_ip": res["end_ip"],
        "insns_executed": ctx.insn_count,
        "regs_changed": _regs_diff(regs_in, regs_out),
        "rsp_delta": regs_out["rsp"] - regs_in["rsp"],
        "mem_writes": ctx.writes,
        "unmapped": ctx.unmapped,
        "halt_reason": res["halt_reason"],
        "duration_s": round(time.time() - t0, 6),
        "seeded": {"regs": "pointers into scratch @ "
                           f"{SCRATCH_VA:#x} (sentinel-filled)",
                   "stack": "sentinel fill"
                            + (" + caller qwords" if stack_qwords else "")},
        "note": _NOTE + _reloc_note(ctx),
    }
    if ctx.skipped_sections:
        out["skipped_sections"] = ctx.skipped_sections
    return out


def validate_chain(view: ImageView, chain: list[int], *,
                   max_ins: int = 1000, expected: dict | None = None,
                   timeout_s: float = 10.0) -> dict:
    """Execute a candidate chain — raw qwords (gadget VAs and data
    values interleaved) laid on a synthetic stack, exactly like the
    exploit script would place them. ``rip`` starts at ``chain[0]``."""
    if not chain:
        raise ValueError("chain_check: chain= is empty")

    ctx = _prepare_engine(view)
    eng = ctx.eng
    for q in chain:
        q &= _MASK64
        ctx.known_vas.setdefault(_reloc(q), q)
    rsp0 = eng.read_regs()["rsp"]
    blob = b"".join(struct.pack("<Q", int(q) & _MASK64) for q in chain)
    eng.mem_write(rsp0, blob)
    eng.mem_write(rsp0 + len(blob),
                  struct.pack("<Q", SENTINEL_VA) * _SENTINEL_FILL_QWORDS)

    exec_entries: dict[int, int] = {}
    for i, q in enumerate(chain):
        q &= _MASK64
        if view.is_exec(q):
            exec_entries.setdefault(q, i)
    non_exec_entries = [
        {"index": i, "va": q & _MASK64}
        for i, q in enumerate(chain)
        if not view.mapped(q & _MASK64)]

    eng.write_regs({"rip": chain[0] & _MASK64, "rsp": rsp0 + 8})
    regs_in = eng.read_regs()
    t0 = time.time()
    res = eng.run(until=SENTINEL_VA, max_ins=max_ins, timeout_s=timeout_s)
    regs_out = eng.read_regs()

    # Trace: which chain entries actually executed, in order. `index` is
    # the chain position of the FIRST qword equal to that VA — when the
    # same gadget appears twice, both hits carry the same index and the
    # VA order is the honest signal.
    trace: list[dict] = []
    for addr in ctx.code_trace:
        idx = exec_entries.get(addr)
        if idx is not None and len(trace) < _MAX_TRACE_ROWS:
            trace.append({"va": addr, "index": idx})

    chain_end = rsp0 + len(blob)
    rsp_final = regs_out["rsp"]
    if rsp0 <= rsp_final <= chain_end + 8:
        consumed = min((rsp_final - rsp0) // 8, len(chain))
    else:
        consumed = None

    mismatch: list[dict] = []
    if expected:
        for r, v in (expected.get("regs") or {}).items():
            got = regs_out.get(r)
            if got is None:
                mismatch.append({"reg": r, "expected": v, "actual": None,
                                 "note": "unknown register"})
            elif got != v:
                mismatch.append({"reg": r, "expected": v, "actual": got})
        if "rsp_delta" in expected:
            d = rsp_final - regs_in["rsp"]
            if d != expected["rsp_delta"]:
                mismatch.append({"field": "rsp_delta",
                                 "expected": expected["rsp_delta"],
                                 "actual": d})

    out: dict[str, Any] = {
        "ok": True,
        "verdict": _verdict(ctx, res, max_ins, completed="completed"),
        "chain_len": len(chain),
        "consumed": consumed,
        "trace": trace,
        "trace_truncated": len(trace) >= _MAX_TRACE_ROWS,
        "end_ip": res["end_ip"],
        "insns_executed": ctx.insn_count,
        "final_regs": _regs_diff(regs_in, regs_out),
        "rsp_delta": rsp_final - regs_in["rsp"],
        "mem_writes": ctx.writes,
        "unmapped": ctx.unmapped,
        "halt_reason": res["halt_reason"],
        "duration_s": round(time.time() - t0, 6),
        "note": _NOTE + _reloc_note(ctx),
    }
    if non_exec_entries:
        # Informational; the warning only fires when one of them was
        # actually fetched as code — data qwords are normal in a chain.
        out["non_exec_entries"] = non_exec_entries
        faulted = {u["va"] for u in ctx.unmapped}
        if any(e["va"] in faulted for e in non_exec_entries):
            out.setdefault("warnings", []).append(
                "chain entries at unmapped VAs were fetched as code — "
                "that is where execution faulted")
    if mismatch:
        out["expected_mismatch"] = mismatch
    if ctx.skipped_sections:
        out["skipped_sections"] = ctx.skipped_sections
    return out
