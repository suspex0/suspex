"""v1-lite pseudocode lifter — flattened per-function pseudo listing.

Deliberately NOT a Hex-Rays replacement: this pass renders each basic
block as C-ish statements with per-block constant propagation (lea/mov),
call-argument resolution from the Win64 arg registers, string-literal
labels for rip-relative loads into mapped data, and loc_ labels for
intra-function edges. Structured control-flow reconstruction (if/while/
switch trees) is the deferred v2 — the output stays honest about it.
"""

from __future__ import annotations

from .engine import Analysis, Function, ImageView

ARG_REGS = ["rcx", "rdx", "r8", "r9"]

_W32 = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx",
        "esp": "rsp", "ebp": "rbp", "esi": "rsi", "edi": "rdi",
        "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
        "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15"}
# legacy e?? regs drop the 'e' (eax->ax, esp->sp); r8d..r15d swap the
# 'd' suffix for 'w' (r8d->r8w, r10d->r10w)
_W16 = {(k[:-1] + "w" if k[0] == "r" else k[1:]): v for k, v in
        _W32.items()}
_W8 = {"al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx",
       "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
       "r8b": "r8", "r9b": "r9", "r10b": "r10", "r11b": "r11",
       "r12b": "r12", "r13b": "r13", "r14b": "r14", "r15b": "r15"}


def _canon(reg: str | None) -> str | None:
    if reg is None:
        return None
    return _W32.get(reg) or _W16.get(reg) or _W8.get(reg) or reg


def _fmt_operand(view: ImageView, ins, op: dict, consts: dict) -> str:
    kind = op["kind"]
    if kind == "reg":
        c = _canon(op["reg"])
        if c in consts:
            return f"{c} /*0x{consts[c]:X}*/"
        return c or op["reg"]
    if kind == "imm":
        v = op["imm"] & 0xFFFFFFFFFFFFFFFF
        return f"0x{v:X}"
    # mem
    base = op.get("base")
    if base == "rip":
        tgt = ins.end + op["disp"]
        nm = view.name_for(tgt)
        if nm:
            return f"&{nm}"
        s = view.read(tgt, 64)
        if s and all(0x20 <= b < 0x7F or b == 0 for b in s[:16]):
            lit = s.split(b"\0", 1)[0].decode("ascii", "replace")
            if len(lit) >= 4:
                return f'&"{lit[:48]}"'
        return f"*(0x{tgt:X})"
    parts = []
    if base:
        parts.append(_canon(base))
    if op.get("index"):
        parts.append(f"{_canon(op['index'])}*{op['scale']}")
    if op.get("disp"):
        parts.append(f"0x{op['disp'] & 0xFFFFFFFFFFFFFFFF:X}")
    return "*(" + " + ".join(p for p in parts if p) + ")"


def pseudo(view: ImageView, analysis: Analysis, fn: Function) -> dict:
    """Lift *fn* to a flat pseudo listing."""
    labels = {}
    for b in fn.blocks.values():
        for dst, kind in b.edges:
            if isinstance(dst, int) and dst in fn.blocks \
                    and kind in ("jump", "fallthrough"):
                labels.setdefault(dst, f"loc_{dst:X}")
    lines: list[str] = []
    for bstart in sorted(fn.blocks):
        b = fn.blocks[bstart]
        if bstart in labels:
            lines.append(f"{labels[bstart]}:")
        consts: dict[str, int] = {}
        for ins in b.insns:
            m = ins.mnemonic
            ops = ins.ops
            rendered = None
            if m == "mov" and len(ops) >= 2:
                dst = ops[0]
                if dst["kind"] == "reg":
                    d = _canon(dst["reg"])
                    rendered = f"{d} = {_fmt_operand(view, ins, ops[1], consts)};"
                    iv = ins.imm()
                    if iv is not None:
                        consts[d] = iv & 0xFFFFFFFFFFFFFFFF
                    elif ops[1]["kind"] == "reg" \
                            and _canon(ops[1]["reg"]) in consts:
                        consts[d] = consts[_canon(ops[1]["reg"])]
                    else:
                        consts.pop(d, None)
                else:
                    rendered = f"{_fmt_operand(view, ins, ops[0], consts)} = {_fmt_operand(view, ins, ops[1], consts)};"
            elif m == "lea" and len(ops) >= 2 and ops[0]["kind"] == "reg":
                d = _canon(ops[0]["reg"])
                mem = ins.mem()
                # lea computes the address, not the load — render &x.
                if mem and mem.get("base") == "rip" \
                        and not mem.get("index"):
                    tgt = ins.end + mem["disp"]
                    nm = view.name_for(tgt)
                    rendered = f"{d} = &{nm or ('0x%X' % tgt)};"
                else:
                    rendered = (f"{d} = &{_fmt_operand(view, ins, mem or ops[1], consts)};")
                if mem and mem.get("base") == "rip" and not mem.get("index"):
                    consts[d] = ins.end + mem["disp"]
                else:
                    consts.pop(d, None)
            elif m in ("add", "sub", "xor", "and", "or", "shl", "shr",
                       "sar") and len(ops) >= 2:
                op_sym = {"add": "+=", "sub": "-=", "xor": "^=",
                          "and": "&=", "or": "|=", "shl": "<<=",
                          "shr": ">>=", "sar": ">>="}[m]
                dst = ops[0]
                if dst["kind"] == "reg":
                    d = _canon(dst["reg"])
                    consts.pop(d, None)
                    rendered = f"{d} {op_sym} {_fmt_operand(view, ins, ops[1], consts)};"
                else:
                    rendered = f"{_fmt_operand(view, ins, dst, consts)} {op_sym} {_fmt_operand(view, ins, ops[1], consts)};"
            elif m == "call":
                tgt = ins.imm()
                mem = ins.mem()
                if tgt is not None:
                    nm = view.name_for(tgt) or f"sub_{tgt:X}"
                elif mem and mem.get("base") == "rip":
                    slot = ins.end + mem["disp"]
                    nm = view.iat_slots.get(slot) or f"*0x{slot:X}"
                else:
                    nm = f"(*{_fmt_operand(view, ins, ops[0], consts)})"
                args = []
                for ar in ARG_REGS:
                    if ar in consts:
                        args.append(f"0x{consts[ar]:X}")
                    else:
                        args.append(ar)
                rendered = f"{nm}({', '.join(args)});"
            elif m == "cmp" or m == "test":
                rendered = (f"flags = {m}({_fmt_operand(view, ins, ops[0], consts)}, "
                            f"{_fmt_operand(view, ins, ops[1], consts) if len(ops) > 1 else ''});")
            elif m in _JCC_MNEMONICS:
                iv = ins.imm()
                lbl = labels.get(iv, f"0x{iv:X}" if isinstance(iv, int) else "?")
                rendered = f"if ({_cc_name(m)}) goto {lbl};"
            elif m == "jmp":
                iv = ins.imm()
                if iv is not None:
                    lbl = labels.get(iv)
                    if lbl:
                        rendered = f"goto {lbl};"
                    else:
                        nm = view.name_for(iv)
                        rendered = f"return {nm or f'sub_{iv:X}'}();  /* tail */"
                else:
                    rendered = "/* indirect jump */"
            elif m.startswith("ret"):
                rendered = "return rax;"
            if rendered:
                lines.append(f"  {rendered}   /* {ins.addr:X} */")
            else:
                lines.append(f"  /* {ins.mnemonic} {ins.op_str} */")
    return {
        "function": fn.name, "start": fn.start, "end": fn.end,
        "version": "v1-lite",
        "note": ("flat listing — no structured control flow; constants "
                 "propagated per block only; call args are best-effort "
                 "register tracking"),
        "lines": lines,
    }


_JCC_MNEMONICS = {"je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge",
                  "jl", "jle", "jz", "jnz", "js", "jns", "jo", "jno",
                  "jp", "jnp", "jc", "jnc"}


def _cc_name(m: str) -> str:
    return {
        "je": "== 0", "jz": "== 0", "jne": "!= 0", "jnz": "!= 0",
        "ja": "u>", "jae": "u>=", "jb": "u<", "jbe": "u<=",
        "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
        "js": "sign", "jns": "!sign", "jo": "of", "jno": "!of",
        "jp": "parity", "jnp": "!parity", "jc": "carry", "jnc": "!carry",
    }.get(m, m)
