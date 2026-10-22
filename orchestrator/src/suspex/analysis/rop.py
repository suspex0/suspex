"""rp++-style gadget scanning over an :class:`~.engine.ImageView`.

The ``bin_manage(action='gadgets')`` substrate. Gadgets live at unaligned
offsets mid-instruction, so this deliberately does NOT reuse the
recursive-descent engine: it walks every executable region, finds
terminator byte candidates (``ret``/``retn``/``retf``/``jmp r/m``/
``call r/m``/``syscall``/``sysenter``/``int 2e``), then backward-decodes
candidate start offsets and keeps the decodings that land exactly on the
terminator with no control flow in between (the rp++ algorithm).

Bounded work: ``budget`` caps capstone decode attempts; ``truncated`` on
the result distinguishes "no more code" from "ran out of budget" — same
honesty convention as ``mem_rw pattern_scan``.

Categories (a gadget carries a set — one instruction can imply several):

* ``trivial``     — a lone terminator (bare ``ret``, ``syscall``, …)
* ``load``        — ``pop r64``
* ``push`` / ``push_ret`` — ``push X`` / ``push X; ret``
* ``mov`` / ``mov_imm`` — reg←reg / reg←imm
* ``xchg`` / ``mem_xchg``
* ``arith``       — add/sub/xor/and/or/inc/dec/neg/not/cmp/test/…
* ``shift``       — shl/shr/sar/rol/ror/…
* ``mem_load``    — ``mov r, [mem]`` (also movsx/movzx forms)
* ``mem_store``   — ``mov [mem], r``
* ``string``      — movs/stos/lods/scas/cmps forms
* ``stack_pivot`` — rsp ← attacker-controlled value: ``xchg/mov/lea rsp``,
  ``pop rsp``, ``leave`` — the tag kernel work cares about most
* ``stack_adjust``— rsp ← rsp ± imm (``add rsp, 0x20``, ``and rsp, ~0xF``)
* ``privileged``  — hlt/in/out/rdmsr/wrmsr/cpuid/swapgs/mov cr|dr/…
* ``syscall`` / ``sysenter`` / ``int`` / ``jmp_reg`` / ``jmp_mem`` /
  ``call_reg`` / ``call_mem`` — mirror of the ending kind

``stack_delta`` on a gadget is the net rsp change where every
rsp-affecting instruction is understood (pops + ret imm16 + add/sub rsp),
else ``None`` — never a guess.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .engine import IMM, MEM, REG, ImageView, Insn, _Decoder

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

DEFAULT_MAX_INSNS = 8      # instructions per gadget
DEFAULT_MAX_BYTES = 24     # backward window (bytes) per terminator
DEFAULT_BUDGET = 4_000_000  # capstone decode attempts per index build

_CHUNK = 1 << 20           # terminator-scan chunk
_CACHE_CAP = 1_000_000     # per-offset decode memo cap

# Terminator lead bytes: c2/c3 ret, ca/cb retf, cd int, ff jmp/call r/m,
# 0f syscall/sysenter.
_TERM_LEAD = re.compile(rb"[\xc2\xc3\xca\xcb\xcd\xff\x0f]")

_ENDINGS_ALL = frozenset({
    "ret", "ret_imm", "retf", "jmp_reg", "jmp_mem", "call_reg",
    "call_mem", "syscall", "sysenter", "int",
})

# Ending selectors: "ret" matches ret|ret_imm, "jmp" matches both forms, …
_ENDING_ALIASES: dict[str, frozenset[str]] = {
    "ret": frozenset({"ret", "ret_imm"}),
    "jmp": frozenset({"jmp_reg", "jmp_mem"}),
    "call": frozenset({"call_reg", "call_mem"}),
}

_ARITH = {"add", "sub", "adc", "sbb", "and", "or", "xor", "inc", "dec",
          "neg", "not", "cmp", "test"}
_SHIFT = {"shl", "shr", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"}
_STRING = {"movsb", "movsw", "movsd", "movsq", "stosb", "stosw", "stosd",
           "stosq", "lodsb", "lodsw", "lodsd", "lodsq", "scasb", "scasw",
           "scasd", "scasq", "cmpsb", "cmpsw", "cmpsd", "cmpsq"}
_PRIV = {"hlt", "in", "out", "cli", "sti", "rdmsr", "wrmsr", "rdpmc",
         "cpuid", "invlpg", "invpcid", "swapgs", "lgdt", "lidt", "lldt",
         "ltr", "clts", "wbinvd", "invd", "sysret", "sysretq", "iret",
         "iretq", "iretd"}

# Mnemonics that may not appear mid-gadget: an earlier terminator or
# branch means the decode from this start offset never "reaches" the
# terminator we are building around.
_CF_MNEMONICS = {"ret", "retn", "retf", "iret", "iretq", "iretd", "jmp",
                 "ljmp", "call", "lcall", "syscall", "sysenter", "sysret",
                 "sysretq", "int", "int3", "int1", "ud0", "ud1", "ud2",
                 "hlt"}

_SP_NAMES = ("rsp", "esp")


def _is_sp(op: dict | None) -> bool:
    return bool(op and op["kind"] == REG and op["reg"] in _SP_NAMES)


def _is_control_flow(ins: Insn) -> bool:
    """True for terminators/branches — invalid mid-gadget."""
    m = ins.mnemonic
    if m in _CF_MNEMONICS:
        return True
    if m.startswith("j") and m != "jmp":
        return True  # jcc / jcxz / jecxz / jrcxz
    if m.startswith("loop"):
        return True
    return False


def _ending_of(ins: Insn) -> str | None:
    """Classify a terminating instruction, or None when it isn't one."""
    m = ins.mnemonic
    if m in ("ret", "retn"):
        return "ret_imm" if ins.imm() is not None else "ret"
    if m == "retf":
        return "retf"
    if m == "syscall":
        return "syscall"
    if m == "sysenter":
        return "sysenter"
    if m == "int":
        return "int"
    if m == "jmp":
        if any(o["kind"] == REG for o in ins.ops):
            return "jmp_reg"
        if ins.mem() is not None:
            return "jmp_mem"
        return None  # relative jmp — a branch, not a gadget ending
    if m == "call":
        if any(o["kind"] == REG for o in ins.ops):
            return "call_reg"
        if ins.mem() is not None:
            return "call_mem"
        return None
    return None


def ending_selector(spec: Any) -> frozenset[str] | None:
    """Normalize an ending filter: ``""``/``"all"``/None → None (all);
    ``"ret"``/``"jmp"``/``"call"`` expand to their variants; a csv or
    iterable of exact ending names is intersected with the known set.

    Raises ValueError on an unknown ending name (tool layer → bad_arg).
    """
    if spec is None or spec == "" or spec == "all":
        return None
    if isinstance(spec, str):
        parts = [p.strip().lower() for p in spec.split(",") if p.strip()]
    else:
        parts = [str(p).strip().lower() for p in spec if str(p).strip()]
    out: set[str] = set()
    for p in parts:
        if p in ("all", "*"):
            return None
        if p in _ENDING_ALIASES:
            out |= _ENDING_ALIASES[p]
        elif p in _ENDINGS_ALL:
            out.add(p)
        else:
            raise ValueError(
                f"unknown ending {p!r}; expected one of: "
                + ", ".join(sorted(_ENDINGS_ALL | set(_ENDING_ALIASES)
                                   | {"all"})))
    return frozenset(out)


# ---------------------------------------------------------------------------
# Gadget model
# ---------------------------------------------------------------------------

@dataclass
class Gadget:
    va: int
    raw: bytes
    insns: list[Insn]
    ending: str
    categories: frozenset[str]
    regs: frozenset[str]
    stack_delta: int | None
    ret_imm: int = 0

    @property
    def text(self) -> str:
        return "; ".join(f"{i.mnemonic} {i.op_str}".strip()
                         for i in self.insns)


def classify(insns: list[Insn], ending: str) -> frozenset[str]:
    """Pattern tags over the normalized instruction list (see module doc)."""
    tags: set[str] = set()
    if len(insns) == 1:
        tags.add("trivial")
    if ending in ("jmp_reg", "jmp_mem", "call_reg", "call_mem",
                  "syscall", "sysenter", "int"):
        tags.add(ending)
    for ins in insns:
        m = ins.mnemonic
        ops = ins.ops
        dst = ops[0] if ops else None
        tail = m.split()[-1]  # "rep movsb" → "movsb"
        if m == "pop":
            tags.add("load")
            if _is_sp(dst):
                tags.add("stack_pivot")
        elif m == "push":
            tags.add("push")
        elif m.startswith("mov") and m not in _STRING and tail not in _STRING:
            if dst and dst["kind"] == REG:
                if _is_sp(dst):
                    tags.add("stack_pivot")
                src = ops[1] if len(ops) > 1 else None
                if src:
                    if src["kind"] == MEM:
                        tags.add("mem_load")
                    elif src["kind"] == IMM:
                        tags.add("mov_imm")
                    elif src["kind"] == REG:
                        tags.add("mov")
            elif dst and dst["kind"] == MEM:
                tags.add("mem_store")
        elif m == "lea":
            if _is_sp(dst):
                tags.add("stack_pivot")
        elif m == "xchg":
            tags.add("xchg")
            if any(_is_sp(o) for o in ops):
                tags.add("stack_pivot")
            if any(o["kind"] == MEM for o in ops):
                tags.add("mem_xchg")
        elif m == "leave":
            tags.add("stack_pivot")
        elif m in _ARITH:
            tags.add("arith")
        elif m in _SHIFT:
            tags.add("shift")
        elif tail in _STRING:
            tags.add("string")
        elif m in _PRIV or "privilege" in ins.groups:
            tags.add("privileged")
        if (m in ("add", "sub", "and", "or") and _is_sp(dst)
                and len(ops) > 1 and ops[1]["kind"] == IMM):
            tags.add("stack_adjust")
    if (insns[-1].mnemonic in ("ret", "retn", "retf")
            and any(i.mnemonic == "push" for i in insns[:-1])):
        tags.add("push_ret")
    return frozenset(tags)


def stack_delta(insns: list[Insn]) -> int | None:
    """Net rsp change, or None when any rsp effect is not understood."""
    d = 0
    for ins in insns:
        m = ins.mnemonic
        ops = ins.ops
        dst = ops[0] if ops else None
        if m == "pop":
            if _is_sp(dst):
                return None
            d += 8
        elif m == "push":
            d -= 8
        elif m in ("add", "sub") and _is_sp(dst):
            src = ops[1] if len(ops) > 1 else None
            if not (src and src["kind"] == IMM):
                return None
            d += src["imm"] if m == "add" else -src["imm"]
        elif m in ("ret", "retn"):
            d += 8
            iv = ins.imm()
            if iv:
                d += iv
        elif m in ("nop", "pause", "endbr64"):
            pass
        elif _is_sp(dst):
            return None  # mov/lea/xchg/and/or/… into rsp — not modelled
        elif m == "xchg" and any(_is_sp(o) for o in ops):
            return None
    return d


def _make_gadget(va: int, raw: bytes, insns: list[Insn],
                 ending: str) -> Gadget:
    regs = frozenset(o["reg"] for i in insns for o in i.ops
                     if o["kind"] == REG)
    ret_imm = 0
    if ending == "ret_imm":
        ret_imm = insns[-1].imm() or 0
    return Gadget(va=va, raw=raw, insns=insns, ending=ending,
                  categories=classify(insns, ending), regs=regs,
                  stack_delta=stack_delta(insns), ret_imm=ret_imm)


def gadget_row(g: Gadget) -> dict:
    """JSON row for one gadget (paging/projection applied by the caller)."""
    return {
        "va": g.va,
        "bytes": g.raw.hex(),
        "text": g.text,
        "insns": [f"{i.mnemonic} {i.op_str}".strip() for i in g.insns],
        "ending": g.ending,
        "categories": sorted(g.categories),
        "regs": sorted(g.regs),
        "n_insns": len(g.insns),
        "ret_imm": g.ret_imm,
        "stack_delta": g.stack_delta,
    }


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def scan_ranges(view: ImageView) -> list[tuple[int, int, str]]:
    """(start_va, end_va, label) executable regions for this view.

    PE sources use section exec flags — with the file-layout clamp to
    ``raw_size`` (bytes past raw data are zero-fill at load; decoding
    neighbouring file bytes would invent gadgets). Blobs scan whole.
    """
    img = view.img
    if img is None:
        return [(s, e, "blob") for s, e in view.exec_ranges()]
    out: list[tuple[int, int, str]] = []
    base = view.base_va
    for s in img.sections:
        if not s.exec:
            continue
        span = s.raw_size if img.layout == "file" \
            else max(s.vsize, s.raw_size)
        if span <= 0:
            continue
        out.append((base + s.va, base + s.va + span,
                    (s.name or "").strip("\0")))
    return out


def _find_terminators(view: ImageView, start: int,
                      end: int) -> Iterable[tuple[int, str]]:
    """Yield (va, kind_hint) for byte-level terminator candidates."""
    pos = start
    while pos < end:
        want = min(_CHUNK, end - pos)
        chunk = view.read(pos, want + 16)  # overlap for 2-byte patterns
        if not chunk:
            pos = (pos + 0x1000) & ~0xFFF  # unmapped hole — next page
            continue
        limit = min(len(chunk), want)
        for m in _TERM_LEAD.finditer(chunk):
            i = m.start()
            if i >= limit:
                break  # tail of chunk — next iteration re-reads it
            b = chunk[i]
            if b == 0xC3:
                yield pos + i, "ret"
            elif b == 0xC2 and i + 2 < len(chunk):
                yield pos + i, "ret_imm"
            elif b in (0xCA, 0xCB):
                yield pos + i, "retf"
            elif b == 0xFF and i + 1 < len(chunk):
                regf = (chunk[i + 1] >> 3) & 7
                if regf == 4:
                    yield pos + i, "jmp"
                elif regf == 2:
                    yield pos + i, "call"
            elif b == 0x0F and i + 1 < len(chunk):
                nb = chunk[i + 1]
                if nb == 0x05:
                    yield pos + i, "syscall"
                elif nb == 0x34:
                    yield pos + i, "sysenter"
            elif b == 0xCD and i + 1 < len(chunk) and chunk[i + 1] == 0x2E:
                yield pos + i, "int"
        pos += limit if limit > 0 else 0x1000


def _walk_to(insns: list[Insn], target: int, max_insns: int) \
        -> list[Insn] | None:
    """Walk a decode from some start offset; return the instruction list
    that lands exactly on *target* (terminator included), else None."""
    out: list[Insn] = []
    for ins in insns:
        if ins.addr == target:
            return out + [ins]
        if ins.addr > target:
            return None  # straddled the target — not a clean boundary
        if len(out) >= max_insns - 1:
            return None  # too long
        if _is_control_flow(ins):
            return None  # earlier terminator/branch
        out.append(ins)
    return None


def _scan_range(dec: _Decoder, view: ImageView, start: int, end: int, *,
                max_insns: int, max_bytes: int,
                want: frozenset[str] | None,
                budget: int) -> tuple[list[Gadget], int, int, bool]:
    """Scan one exec range. Returns (gadgets, attempts, terminators,
    truncated)."""
    found: list[Gadget] = []
    attempts = 0
    terms = 0
    cache: dict[int, list[Insn]] = {}
    span = max_bytes + 16
    for T, _hint in _find_terminators(view, start, end):
        terms += 1
        lo = max(start, T - max_bytes)
        # s == T yields the bare terminator (a lone `ret` is a gadget too).
        for s in range(T, lo - 1, -1):
            insns = cache.get(s)
            if insns is None:
                if attempts >= budget:
                    return found, attempts, terms, True
                attempts += 1
                data = view.read(s, span)
                insns = dec.decode(data, s, max_insns + 1) if data else []
                if len(cache) < _CACHE_CAP:
                    cache[s] = insns
            g = _walk_to(insns, T, max_insns)
            if g is None:
                continue
            ending = _ending_of(g[-1])
            if ending is None or (want is not None and ending not in want):
                continue
            raw = view.read(s, sum(i.size for i in g))
            found.append(_make_gadget(s, raw, g, ending))
    return found, attempts, terms, False


@dataclass
class GadgetIndex:
    """One built index — raw gadgets, filterable at query time."""

    gadgets: list[Gadget] = field(default_factory=list)
    base_va: int = 0
    truncated: bool = False
    bytes_scanned: int = 0
    terminators: int = 0
    decode_attempts: int = 0
    scan_s: float = 0.0
    ranges: list[tuple[int, int, str]] = field(default_factory=list)


def build_index(view: ImageView, *, endings: Any = None,
                max_insns: int = DEFAULT_MAX_INSNS,
                max_bytes: int = DEFAULT_MAX_BYTES,
                budget: int = DEFAULT_BUDGET) -> GadgetIndex:
    """Scan every executable region and return the gadget index.

    Raises ``CodegenUnavailable`` when capstone is missing (the tool
    layer maps that to the ``codegen_extra_missing`` envelope).
    """
    want = ending_selector(endings)
    dec = _Decoder()
    t0 = time.time()
    idx = GadgetIndex(base_va=view.base_va)
    idx.ranges = scan_ranges(view)
    for start, end, _label in idx.ranges:
        if start >= end:
            continue
        idx.bytes_scanned += end - start
        # Remaining budget is shared across ranges — the cap is per
        # index build, not per section.
        found, attempts, terms, trunc = _scan_range(
            dec, view, start, end, max_insns=max_insns,
            max_bytes=max_bytes, want=want,
            budget=budget - idx.decode_attempts)
        idx.gadgets.extend(found)
        idx.decode_attempts += attempts
        idx.terminators += terms
        if trunc:
            idx.truncated = True
            break
    idx.gadgets.sort(key=lambda g: g.va)
    idx.scan_s = round(time.time() - t0, 3)
    return idx


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def parse_bad_bytes(spec: str) -> frozenset[int]:
    """Parse ``"00 0a"`` / ``"00,0a"`` / ``"000a"`` → byte values.

    Raises ValueError on malformed input (tool layer → bad_arg).
    """
    if not spec:
        return frozenset()
    cleaned = re.sub(r"[\s,;]+", "", spec.strip())
    cleaned = cleaned.replace("0x", "")
    if not cleaned or len(cleaned) % 2 or \
            not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError(
            f"bad_bytes {spec!r}: expected hex pairs like '00 0a' "
            "or '000a'")
    return frozenset(int(cleaned[i:i + 2], 16)
                     for i in range(0, len(cleaned), 2))


def _va_has_bad_bytes(va: int, bad: frozenset[int]) -> bool:
    packed = va.to_bytes(8, "little")
    return any(b in packed for b in bad)


def _selector_set(spec: Any) -> frozenset[str]:
    if not spec:
        return frozenset()
    if isinstance(spec, str):
        return frozenset(p.strip().lower()
                         for p in spec.split(",") if p.strip())
    return frozenset(str(p).strip().lower() for p in spec if str(p).strip())


def query(index: GadgetIndex, *, ending: Any = "", category: Any = "",
          reg: Any = "", bad_bytes: frozenset[int] = frozenset(),
          max_len: int = 0, unique: bool = False) -> list[dict]:
    """Filter the index into rows (paging is the caller's job)."""
    want_endings = ending_selector(ending)
    want_cats = _selector_set(category)
    want_regs = _selector_set(reg)
    out: list[dict] = []
    seen: dict[str, dict] = {}
    for g in index.gadgets:
        if want_endings is not None and g.ending not in want_endings:
            continue
        if want_cats and not (want_cats & g.categories):
            continue
        if want_regs and not (want_regs & g.regs):
            continue
        if max_len and len(g.insns) > max_len:
            continue
        if bad_bytes and _va_has_bad_bytes(g.va, bad_bytes):
            continue
        if unique:
            row = seen.get(g.text)
            if row is not None:
                row["aliases"] += 1
                continue
            row = gadget_row(g)
            row["aliases"] = 1
            seen[g.text] = row
            out.append(row)
        else:
            out.append(gadget_row(g))
    return out
