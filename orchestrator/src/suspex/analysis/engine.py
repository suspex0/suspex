"""Recursive-descent x64 analysis engine — the knife-derived core.

Given a byte image (a :class:`pe.PeImage` or a raw code blob wrapped by
:func:`wrap_blob`) this recovers functions by flow analysis rather than
linear sweeps: entry point + exports + .pdata starts seed a worklist;
each function's basic blocks, call edges, jump-table targets, and
typed xrefs are recovered by walking control flow.

Design contract (carried from knife):

* Bounded work: ``budget`` instructions total, ``MAX_JT_ENTRIES`` per
  switch, block walk dies at unmapped/non-exec bytes. ``truncated`` on
  the result distinguishes "no more code" from "ran out of budget".
* Never invent edges: constant tracking is limited to ``lea reg,[rip+x]``
  and ``mov reg,imm``; anything else invalidates the slot. A jmp reg that
  doesn't match a known table shape is an unresolved indirect, not a
  guess.
* IAT resolution: ``call/jmp [rip+x]`` and ``jmp [abs]`` whose slot is a
  known import thunk resolve to ``dll!name`` edges instead of anonymous
  addresses.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

ANALYSIS_BUDGET = 2_000_000
MAX_JT_ENTRIES = 4096
MAX_BLOCKS_PER_FUNC = 8192
MAX_CALLERS_PER_PATHS = 512

# Normalized operand kinds the engine uses internally.
REG, IMM, MEM = "reg", "imm", "mem"


class AnalysisError(Exception):
    """Engine-level failure; carries a ``kind`` for the envelope."""

    def __init__(self, kind: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint


def _capstone():
    """Load capstone through the codegen soft-import (named error on miss)."""
    from ..codegen import _load_capstone
    return _load_capstone()


# ---------------------------------------------------------------------------
# Image views — normalize "a buffer + address space" for the engine.
# ---------------------------------------------------------------------------

class ImageView:
    """Byte image with VA↔offset mapping, exec flags, and a name table."""

    def __init__(self, img=None, *, data: bytes | None = None,
                 base_va: int = 0) -> None:
        self.img = img
        if img is not None:
            # `base_va` overrides the header's preferred ImageBase — the
            # live case (`source="memory"` parses a KASLR-rebased image
            # whose header still carries the linker base). Defaults to
            # the header base, keeping every existing caller identical.
            self.base_va = base_va or img.image_base
            self._data = img.data
        else:
            self.base_va = base_va
            self._data = data or b""
        self.names: dict[int, str] = {}     # va -> human name
        self.iat_slots: dict[int, str] = {}  # thunk-slot VA -> dll!name
        self.pdata_starts: list[int] = []
        if img is not None:
            # Parser-emitted VAs (exports, pdata) are preferred-base
            # relative; shift them onto this view's base.
            delta = self.base_va - img.image_base
            for d in img.imports:
                for e in d["entries"]:
                    nm = e["name"] or f"ord{e['ordinal']}"
                    slot_va = self.base_va + e["thunk_rva"]
                    self.iat_slots[slot_va] = f"{d['dll']}!{nm}"
            for e in img.exports:
                self.names[e["va"] + delta] = e["name"] or f"ord_{e['ordinal']}"
            for p in img.pdata:
                self.pdata_starts.append(p["begin_va"] + delta)
            if img.entry_rva:
                self.names.setdefault(self.base_va + img.entry_rva,
                                      "entry")

    # -- byte access ---------------------------------------------------------
    def off_of(self, va: int) -> int | None:
        if self.img is not None:
            return self.img.rva_to_off(va - self.base_va)
        off = va - self.base_va
        return off if 0 <= off < len(self._data) else None

    def read(self, va: int, size: int) -> bytes:
        off = self.off_of(va)
        if off is None:
            return b""
        return self._data[off:off + size]

    def mapped(self, va: int) -> bool:
        return self.off_of(va) is not None

    def is_exec(self, va: int) -> bool:
        if self.img is None:
            return self.mapped(va)  # blob: everything readable is exec
        rva = va - self.base_va
        return self.img.is_exec_rva(rva)

    def exec_ranges(self) -> list[tuple[int, int]]:
        if self.img is None:
            return [(self.base_va, self.base_va + len(self._data))]
        out = []
        for s in self.img.sections:
            if s.exec:
                out.append((self.base_va + s.va,
                            self.base_va + s.va + max(s.vsize, s.raw_size)))
        return out

    def name_for(self, va: int) -> str:
        return self.names.get(va) or self.iat_slots.get(va) or ""


# ---------------------------------------------------------------------------
# Instruction normalization.
# ---------------------------------------------------------------------------

@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    ops: list[dict] = field(default_factory=list)
    groups: set = field(default_factory=set)

    @property
    def end(self) -> int:
        return self.addr + self.size

    def imm(self) -> int | None:
        for o in self.ops:
            if o["kind"] == IMM:
                return o["imm"]
        return None

    def mem(self) -> dict | None:
        for o in self.ops:
            if o["kind"] == MEM:
                return o
        return None


class _Decoder:
    """Capstone → :class:`Insn`. detail=True gives real operand fields."""

    def __init__(self) -> None:
        cs = _capstone()
        self._cs = cs
        self._eng = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self._eng.detail = True
        self._riprel = cs.x86.X86_REG_RIP

    def decode(self, data: bytes, addr: int, count: int) -> list[Insn]:
        cs = self._cs
        out: list[Insn] = []
        for i, ins in enumerate(self._eng.disasm(data, addr)):
            if i >= count:
                break
            ops: list[dict] = []
            for op in ins.operands:
                if op.type == cs.x86.X86_OP_REG:
                    ops.append({"kind": REG,
                                "reg": ins.reg_name(op.reg)})
                elif op.type == cs.x86.X86_OP_IMM:
                    ops.append({"kind": IMM, "imm": op.imm})
                elif op.type == cs.x86.X86_OP_MEM:
                    ops.append({
                        "kind": MEM,
                        "base": ins.reg_name(op.mem.base) or None,
                        "index": ins.reg_name(op.mem.index) or None,
                        "scale": op.mem.scale,
                        "disp": op.mem.disp,
                    })
            groups = set()
            for g in ins.groups:
                try:
                    groups.add(ins.group_name(g))
                except Exception:
                    pass
            out.append(Insn(addr=ins.address, size=ins.size,
                            mnemonic=ins.mnemonic, op_str=ins.op_str,
                            ops=ops, groups=groups))
        return out


# ---------------------------------------------------------------------------
# Analysis result.
# ---------------------------------------------------------------------------

@dataclass
class Block:
    start: int
    end: int = 0
    insns: list[Insn] = field(default_factory=list)
    # edge kinds: fallthrough|jump|call|tail_call|call_indirect|data
    edges: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class Function:
    start: int
    name: str
    blocks: dict[int, Block] = field(default_factory=dict)
    calls: set = field(default_factory=set)       # direct callee VAs/names
    xrefs_in: set = field(default_factory=set)    # caller site VAs

    @property
    def end(self) -> int:
        return max((b.end for b in self.blocks.values()), default=self.start)

    @property
    def size(self) -> int:
        return sum(b.end - b.start for b in self.blocks.values())

    def insns(self) -> Iterable[Insn]:
        for b in sorted(self.blocks.values(), key=lambda x: x.start):
            yield from b.insns


class Analysis:
    def __init__(self, view: ImageView) -> None:
        self.view = view
        self.functions: dict[int, Function] = {}
        self.xrefs_to: dict[Any, list[dict]] = {}
        self.xrefs_from: dict[int, list[dict]] = {}
        self.indirect_calls: list[int] = []
        self.data_refs: list[dict] = []
        self.truncated = False
        self.insns_decoded = 0

    # -- xref bookkeeping ----------------------------------------------------
    def add_xref(self, dst: Any, src: int, kind: str) -> None:
        self.xrefs_to.setdefault(dst, []).append({"from": src, "kind": kind})
        self.xrefs_from.setdefault(src, []).append(
            {"to": dst, "kind": kind})

    # -- queries --------------------------------------------------------------
    def function_at(self, va: int) -> Function | None:
        for f in self.functions.values():
            for b in f.blocks.values():
                if b.start <= va < b.end:
                    return f
        return None

    def paths_to(self, target: int, *, max_paths: int = 8,
                 max_depth: int = 12) -> list[list[int]]:
        """Backward BFS: shortest call chains from roots (entry/exports/
        orphan functions) down to *target*. Honest about indirect edges —
        a chain that only exists through an indirect call still returns,
        marked by the caller via edge kinds if desired."""
        roots = {f.start for f in self.functions.values()}
        # caller map: callee_va -> [caller function start]
        callers: dict[int, set[int]] = {}
        for f in self.functions.values():
            for callee in f.calls:
                if isinstance(callee, int):
                    callers.setdefault(callee, set()).add(f.start)
        if not callers.get(target) and target not in roots:
            return []
        paths: list[list[int]] = []
        # BFS from target back to a root.
        q: deque[list[int]] = deque([[target]])
        seen_depth: dict[int, int] = {target: 0}
        while q and len(paths) < max_paths:
            chain = q.popleft()
            head = chain[0]
            if head in roots and len(chain) > 1 or len(chain) >= max_depth:
                if head in roots and len(chain) > 1:
                    paths.append(list(reversed(chain)))
                continue
            ups = callers.get(head)
            if not ups:
                if len(chain) > 1 and head in roots:
                    paths.append(list(reversed(chain)))
                continue
            for up in sorted(ups):
                if up in chain:
                    continue
                q.append([up] + chain)
        return paths


# ---------------------------------------------------------------------------
# The engine.
# ---------------------------------------------------------------------------

_TERMINATORS = {"ret", "retn", "retf", "iret", "iretq", "int3", "ud2",
                "jmp", "ljmp"}
_JCC = {"je", "jz", "jne", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge",
        "jl", "jle", "jo", "jno", "js", "jns", "jp", "jpe", "jnp", "jpo",
        "jc", "jnc", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}


class Engine:
    def __init__(self, view: ImageView, *, budget: int = ANALYSIS_BUDGET):
        self.view = view
        self.dec = _Decoder()
        self.budget = budget
        self.result = Analysis(view)

    # -- public driver ---------------------------------------------------------
    def analyze(self, seeds: Iterable[int] | None = None) -> Analysis:
        r = self.result
        seed_list = list(seeds or [])
        seed_list += [v for v in self.view.pdata_starts]
        entry = self._entry_va()
        if entry:
            seed_list.append(entry)
        for va in self.view.names:
            if self.view.is_exec(va):
                seed_list.append(va)
        # Dedup preserving order; only exec seeds.
        seen: set[int] = set()
        for s in seed_list:
            if s in seen or not isinstance(s, int) or not self.view.is_exec(s):
                continue
            seen.add(s)
            if s in r.functions:
                continue
            self._recover(s)
            if r.insns_decoded >= self.budget:
                r.truncated = True
                break
        self._reclassify_tail_jumps()
        return r

    def _entry_va(self) -> int:
        img = self.view.img
        if img is not None and img.entry_rva:
            return img.image_base + img.entry_rva
        return 0

    # -- per-function recovery ---------------------------------------------------
    def _recover(self, start: int) -> None:
        r = self.result
        fn = Function(start=start,
                      name=self.view.name_for(start)
                      or f"sub_{start:X}")
        r.functions[start] = fn
        worklist = [start]
        visited: set[int] = set()
        while worklist:
            if r.insns_decoded >= self.budget:
                r.truncated = True
                return
            if len(fn.blocks) >= MAX_BLOCKS_PER_FUNC:
                r.truncated = True
                return
            bstart = worklist.pop()
            if bstart in visited or not self.view.is_exec(bstart):
                continue
            if bstart in r.functions and bstart != start:
                # Reached another recovered function — it's a tail call,
                # not a block of this one.
                continue
            visited.add(bstart)
            block = self._decode_block(bstart, fn, worklist, visited)
            if block is not None:
                fn.blocks[bstart] = block

    def _decode_block(self, start: int, fn: Function,
                      worklist: list[int], visited: set[int]) -> Block | None:
        r = self.result
        view = self.view
        block = Block(start=start)
        consts: dict[str, int] = {}
        va = start
        chunk = 0x400
        budget_left = self.budget - r.insns_decoded
        while True:
            data = view.read(va, chunk)
            if not data:
                block.end = va
                break
            insns = self.dec.decode(data, va, 4096)
            if not insns:
                block.end = va
                break
            stop = False
            for ins in insns:
                if not self.view.is_exec(ins.addr):
                    stop = True
                    break
                block.insns.append(ins)
                r.insns_decoded += 1
                self._track_const(ins, consts)
                self._collect_dataref(ins)
                m = ins.mnemonic
                if m == "call":
                    self._handle_call(ins, fn, block)
                    va = ins.end
                    continue
                if m == "jmp":
                    self._handle_jmp(ins, fn, block, worklist, visited,
                                     consts)
                    va = ins.end
                    stop = True
                    break
                if m in _JCC:
                    tgt = ins.imm()
                    if tgt is not None:
                        block.edges.append((tgt, "jump"))
                        if tgt not in visited:
                            worklist.append(tgt)
                    block.edges.append((ins.end, "fallthrough"))
                    if ins.end not in visited:
                        worklist.append(ins.end)
                    va = ins.end
                    stop = True
                    break
                if m in _TERMINATORS - {"jmp"}:
                    va = ins.end
                    stop = True
                    break
                va = ins.end
            if stop:
                block.end = va
                break
            if len(insns) == 0:
                block.end = va
                break
        return block

    # -- instruction handlers ----------------------------------------------------
    def _track_const(self, ins: Insn, consts: dict[str, int]) -> None:
        """Conservative constant tracking: lea reg,[rip+x] and mov reg,imm
        only; any other write invalidates the slot."""
        writes = [o for o in ins.ops if o["kind"] == REG]
        dest = writes[0]["reg"] if writes else None
        if ins.mnemonic == "lea" and dest:
            mem = ins.mem()
            if mem and mem["base"] == "rip" and not mem["index"]:
                consts[dest] = ins.end + mem["disp"]
                return
        if ins.mnemonic == "mov" and dest:
            iv = ins.imm()
            if iv is not None:
                consts[dest] = iv
                return
        if dest:
            consts.pop(dest, None)

    def _collect_dataref(self, ins: Insn) -> None:
        mem = ins.mem()
        if not mem:
            return
        if mem["base"] == "rip" and not mem["index"]:
            target = ins.end + mem["disp"]
            if self.view.mapped(target) and not self.view.is_exec(target):
                self.result.data_refs.append(
                    {"from": ins.addr, "to": target})
                self.result.add_xref(target, ins.addr, "data")
        elif not mem["base"] and not mem["index"] and mem["disp"]:
            target = mem["disp"] & 0xFFFFFFFFFFFFFFFF
            if self.view.mapped(target) and not self.view.is_exec(target):
                self.result.data_refs.append(
                    {"from": ins.addr, "to": target})
                self.result.add_xref(target, ins.addr, "data")

    def _handle_call(self, ins: Insn, fn: Function,
                     block: Block) -> None:
        r = self.result
        iv = ins.imm()
        mem = ins.mem()
        if iv is not None:
            tgt = iv & 0xFFFFFFFFFFFFFFFF
            block.edges.append((tgt, "call"))
            fn.calls.add(tgt)
            r.add_xref(tgt, ins.addr, "call")
            block.edges.append((ins.end, "fallthrough"))
        elif mem is not None:
            slot = None
            if mem["base"] == "rip" and not mem["index"]:
                slot = ins.end + mem["disp"]
            elif not mem["base"] and not mem["index"]:
                slot = mem["disp"] & 0xFFFFFFFFFFFFFFFF
            nm = self.view.iat_slots.get(slot) if slot is not None else None
            if nm:
                block.edges.append((nm, "call"))
                fn.calls.add(nm)
                r.add_xref(nm, ins.addr, "call")
            else:
                block.edges.append((f"indirect@{ins.addr:X}",
                                    "call_indirect"))
                fn.calls.add(f"indirect@{ins.addr:X}")
                r.indirect_calls.append(ins.addr)
            block.edges.append((ins.end, "fallthrough"))
        else:
            block.edges.append((f"indirect@{ins.addr:X}", "call_indirect"))
            fn.calls.add(f"indirect@{ins.addr:X}")
            r.indirect_calls.append(ins.addr)
            block.edges.append((ins.end, "fallthrough"))

    def _handle_jmp(self, ins: Insn, fn: Function, block: Block,
                    worklist: list[int], visited: set[int],
                    consts: dict[str, int]) -> None:
        r = self.result
        iv = ins.imm()
        mem = ins.mem()
        if iv is not None:
            tgt = iv & 0xFFFFFFFFFFFFFFFF
            # Same-function loop/branch vs tail call: resolved post-pass;
            # optimistically treat as a block edge.
            block.edges.append((tgt, "jump"))
            if tgt not in visited:
                worklist.append(tgt)
            return
        if mem is not None:
            slot = None
            if mem["base"] == "rip" and not mem["index"]:
                slot = ins.end + mem["disp"]
            elif not mem["base"] and not mem["index"]:
                slot = mem["disp"] & 0xFFFFFFFFFFFFFFFF
            nm = self.view.iat_slots.get(slot) if slot is not None else None
            if nm:
                # import thunk: jmp qword [IAT] — a tail call into the dll
                block.edges.append((nm, "tail_call"))
                fn.calls.add(nm)
                r.add_xref(nm, ins.addr, "call")
            else:
                block.edges.append((f"indirect@{ins.addr:X}",
                                    "jump_indirect"))
            return
        # jmp reg — try jump-table recovery before giving up.
        targets = self._recover_jump_table(ins, fn, block, consts)
        if targets:
            for t in targets:
                block.edges.append((t, "jump"))
                if t not in visited:
                    worklist.append(t)
        else:
            block.edges.append((f"indirect@{ins.addr:X}",
                                "jump_indirect"))

    # -- jump-table recovery -------------------------------------------------------
    def _recover_jump_table(self, ins: Insn, fn: Function,
                            block: Block, consts: dict[str, int]) -> list[int]:
        """Recognize the two canonical x64 switch shapes:

        absolute:  jmp qword [base_reg + index*8]  (table of VAs)
        offset:    mov r32, [table + index*4]; add/sub; jmp reg
                   (table of signed offsets applied to a base)

        Constants come from the block-local lea/mov tracker; anything we
        can't prove stays unresolved — never a guessed edge.
        """
        jreg = None
        for o in ins.ops:
            if o["kind"] == REG:
                jreg = o["reg"]
        if not jreg:
            return []
        insns = block.insns
        pos = insns.index(ins)
        # Shape A — absolute table: jmp [base + idx*8 + disp]
        mem = ins.mem()
        if mem and mem["index"]:
            base_va = consts.get(mem["base"]) if mem["base"] else None
            if mem["base"] == "rip":
                base_va = ins.end + mem["disp"]
                count = self._bound_before(insns, pos, mem["index"])
                if base_va and count:
                    return self._read_abs_table(base_va, count, 8)
            elif base_va:
                count = self._bound_before(insns, pos, mem["index"])
                if count:
                    return self._read_abs_table(base_va + mem["disp"],
                                                count, mem["scale"])
        # Shape B — offset table: look back for
        #   mov/movsxd r32,[base + idx*4 + disp]; ...; jmp reg
        for back in range(pos - 1, max(pos - 24, -1), -1):
            p = insns[back]
            pm = p.mem()
            if p.mnemonic in ("mov", "movsxd") and pm and pm["index"] \
                    and pm["scale"] in (1, 2, 4, 8):
                tbase = consts.get(pm["base"]) if pm["base"] else None
                if pm["base"] == "rip":
                    tbase = p.end + pm["disp"]
                elif tbase is not None:
                    tbase += pm["disp"]
                if not tbase:
                    continue
                count = self._bound_before(insns, back, pm["index"])
                if not count:
                    continue
                # Find the runtime base the offsets are added to:
                # nearest lea/mov const on the jmp register before the jump.
                rt_base = consts.get(jreg)
                if rt_base is None:
                    # common idiom: add reg, base_reg — the OTHER reg is base
                    for f in range(pos - 1, back, -1):
                        q = insns[f]
                        if q.mnemonic in ("add", "sub") and q.ops \
                                and q.ops[0].get("reg") == jreg:
                            other = [o for o in q.ops
                                     if o["kind"] == REG
                                     and o["reg"] != jreg]
                            if other:
                                rt_base = consts.get(other[0]["reg"])
                            else:
                                iv = q.imm()
                                if iv is not None and q.mnemonic == "sub":
                                    rt_base = (consts.get(jreg) or 0) - iv
                            break
                if rt_base is None:
                    continue
                return self._read_off_table(tbase, count, pm["scale"],
                                            rt_base)
        return []

    def _bound_before(self, insns: list[Insn], pos: int,
                      index_reg: str | None) -> int:
        """Find the case-count bound: nearest ``cmp <idx>, imm`` guarded by
        ja/jbe before the table load."""
        if not index_reg:
            return 0
        for back in range(pos - 1, max(pos - 32, -1), -1):
            p = insns[back]
            if p.mnemonic == "cmp" and p.ops \
                    and p.ops[0].get("kind") == REG \
                    and p.ops[0]["reg"] == index_reg:
                iv = p.imm()
                if iv is None:
                    continue
                # bounded compare: count = imm+1 for ja/jbe style guards
                return min(iv + 1, MAX_JT_ENTRIES)
        return 0

    def _read_abs_table(self, base_va: int, count: int,
                        stride: int) -> list[int]:
        out = []
        import struct as _st
        for i in range(min(count, MAX_JT_ENTRIES)):
            b = self.view.read(base_va + i * stride, stride)
            if len(b) < stride:
                break
            if stride == 8:
                va = _st.unpack_from("<Q", b)[0]
            else:
                va = _st.unpack_from("<I", b)[0]
            if not self.view.is_exec(va):
                break
            out.append(va)
        return out

    def _read_off_table(self, base_va: int, count: int, stride: int,
                        rt_base: int) -> list[int]:
        out = []
        import struct as _st
        for i in range(min(count, MAX_JT_ENTRIES)):
            b = self.view.read(base_va + i * stride, stride)
            if len(b) < stride:
                break
            if stride == 4:
                off = _st.unpack_from("<i", b)[0]
            elif stride == 8:
                off = _st.unpack_from("<q", b)[0]
            elif stride == 2:
                off = _st.unpack_from("<h", b)[0]
            else:
                off = b[0] if b[0] < 128 else b[0] - 256
            va = (rt_base + off) & 0xFFFFFFFFFFFFFFFF
            if not self.view.is_exec(va):
                break
            out.append(va)
        return out

    # -- post-pass ------------------------------------------------------------------
    def _reclassify_tail_jumps(self) -> None:
        """A 'jump' edge whose target is another function's start is a tail
        call — fix the edge kind and record the call xref."""
        r = self.result
        starts = set(r.functions)
        for f in r.functions.values():
            for b in f.blocks.values():
                for i, (dst, kind) in enumerate(b.edges):
                    if kind == "jump" and isinstance(dst, int) \
                            and dst in starts and dst != f.start:
                        b.edges[i] = (dst, "tail_call")
                        f.calls.add(dst)
                        r.add_xref(dst, b.insns[-1].addr if b.insns
                                   else b.start, "call")


# ---------------------------------------------------------------------------
# Public helpers used by bin_manage / plugins.
# ---------------------------------------------------------------------------

def analyze_image(view: ImageView, *, seeds: Iterable[int] | None = None,
                  budget: int = ANALYSIS_BUDGET) -> Analysis:
    """One-shot: build an Engine on *view* and run recovery."""
    return Engine(view, budget=budget).analyze(seeds)


def wrap_blob(data: bytes, base_va: int = 0) -> ImageView:
    """Wrap a raw code blob (shellcode dump, in-memory region) as an
    ImageView so non-PE buffers analyze identically."""
    return ImageView(None, data=data, base_va=base_va)


def body_hash(fn: Function) -> str:
    """Normalized per-function fingerprint: mnemonic + operand *shape*
    (kind/width), immediates and displacements masked — a hot-patched
    function changes hash while a relocated copy doesn't."""
    import hashlib
    h = hashlib.sha256()
    for ins in fn.insns():
        h.update(ins.mnemonic.encode())
        for o in ins.ops:
            if o["kind"] == REG:
                h.update(f"r:{o['reg']}".encode())
            elif o["kind"] == IMM:
                h.update(b"i:*")
            else:
                h.update(f"m:{o.get('scale', 0)}:"
                         f"{1 if o.get('index') else 0}:"
                         f"{1 if o.get('base') else 0}".encode())
    return h.hexdigest()
