"""Sink audit — backward argument-provenance over dangerous call sites.

Ported from knife's ``audit`` pass: for each catalogued dangerous-API call
site, walk backward over the instructions that fed the *interesting*
argument (the copy length, the allocation size, the format string) and
classify where the value came from. Only sites whose provenance matches a
bug pattern become findings — a ``memcpy`` with a constant length is not
a lead, a ``memcpy`` whose length is a subtraction of two dynamic values
is.

x64 Win64 ABI only (rcx/rdx/r8/r9 arg registers + spill slots). Bounded:
the walk gives up after ``MAX_STEPS`` instructions or ``MAX_DEPTH`` hops
of register chasing — provenance beyond that is reported ``unknown``,
not guessed.
"""

from __future__ import annotations

from .engine import Analysis, ImageView, Insn
from .reachability import Reachability

MAX_STEPS = 64
MAX_DEPTH = 8

# Win64 integer arg registers, in order.
ARG_REGS = ["rcx", "rdx", "r8", "r9"]

# Sink catalog: api → {class, arg_index (the interesting arg), note,
# severity}. arg_index is 0-based position in ARG_REGS.
SINKS: dict[str, dict] = {
    # unbounded copies — arg 2 = length
    "memcpy": {"cls": "copy", "arg": 2, "sev": 3,
               "note": "dst/src/len — len provenance decides exploitability"},
    "memmove": {"cls": "copy", "arg": 2, "sev": 3,
                "note": "same as memcpy"},
    "strcpy": {"cls": "copy", "arg": 1, "sev": 3,
               "note": "unbounded by definition — src provenance only"},
    "strncpy": {"cls": "copy", "arg": 2, "sev": 2,
                "note": "bounded copy — check the bound's provenance"},
    "strcat": {"cls": "copy", "arg": 1, "sev": 3,
               "note": "appends unbounded"},
    "sprintf": {"cls": "format", "arg": 1, "sev": 3,
                "note": "format arg + unbounded write"},
    "snprintf": {"cls": "format", "arg": 2, "sev": 2,
                 "note": "format arg provenance"},
    "printf": {"cls": "format", "arg": 0, "sev": 2,
               "note": "non-constant format string"},
    "sscanf": {"cls": "format", "arg": 1, "sev": 2,
               "note": "format-driven input parse"},
    "lstrcpy": {"cls": "copy", "arg": 1, "sev": 3, "note": ""},
    "lstrcpyn": {"cls": "copy", "arg": 2, "sev": 2, "note": ""},
    "rtlcopymemory": {"cls": "copy", "arg": 2, "sev": 3, "note": ""},
    "rtlmovememory": {"cls": "copy", "arg": 2, "sev": 3, "note": ""},
    "memcpy_s": {"cls": "copy", "arg": 3, "sev": 2, "note": ""},
    "bcopy": {"cls": "copy", "arg": 2, "sev": 2, "note": ""},
    "memset": {"cls": "fill", "arg": 2, "sev": 1, "note": ""},
    # exec — arg 0 = command/image
    "system": {"cls": "exec", "arg": 0, "sev": 3, "note": "shell command"},
    "popen": {"cls": "exec", "arg": 0, "sev": 3, "note": ""},
    "winexec": {"cls": "exec", "arg": 0, "sev": 3, "note": ""},
    "createprocessa": {"cls": "exec", "arg": 1, "sev": 3,
                       "note": "lpCommandLine"},
    "createprocessw": {"cls": "exec", "arg": 1, "sev": 3,
                       "note": "lpCommandLine"},
    "shellexecutea": {"cls": "exec", "arg": 3, "sev": 2, "note": ""},
    "shellexecutew": {"cls": "exec", "arg": 3, "sev": 2, "note": ""},
    "dlopen": {"cls": "exec", "arg": 0, "sev": 2, "note": "module path"},
    "loadlibrarya": {"cls": "exec", "arg": 0, "sev": 2, "note": ""},
    "loadlibraryw": {"cls": "exec", "arg": 0, "sev": 2, "note": ""},
    # allocation size — arg 0 (malloc/HeapAlloc size is rdx arg1? HeapAlloc
    # is (heap, flags, size) → arg 2; ExAllocatePool* → arg1/2 depending on
    # flavor; treat size arg position per-api)
    "malloc": {"cls": "alloc", "arg": 0, "sev": 2, "note": "size arg"},
    "calloc": {"cls": "alloc", "arg": 1, "sev": 2, "note": "count*size"},
    "realloc": {"cls": "alloc", "arg": 1, "sev": 2, "note": ""},
    "heapalloc": {"cls": "alloc", "arg": 2, "sev": 2, "note": ""},
    "virtualalloc": {"cls": "alloc", "arg": 1, "sev": 2, "note": ""},
    "exallocatepool": {"cls": "alloc", "arg": 1, "sev": 2, "note": ""},
    "exallocatepoolwithtag": {"cls": "alloc", "arg": 1, "sev": 2, "note": ""},
    "exallocatepool2": {"cls": "alloc", "arg": 1, "sev": 2, "note": ""},
    "alloca": {"cls": "alloc", "arg": 0, "sev": 3,
               "note": "input-sized stack allocation — stack clash"},
    "_alloca_probe": {"cls": "alloc", "arg": 0, "sev": 3, "note": ""},
    # input sources — mark their outputs external
    "recv": {"cls": "source", "arg": 1, "sev": 1, "note": "network input"},
    "read": {"cls": "source", "arg": 1, "sev": 1, "note": ""},
    "fgets": {"cls": "source", "arg": 0, "sev": 1, "note": ""},
    "getenv": {"cls": "source", "arg": 0, "sev": 1, "note": ""},
    "getcommandlinea": {"cls": "source", "arg": 0, "sev": 1, "note": ""},
    "getcommandlinew": {"cls": "source", "arg": 0, "sev": 1, "note": ""},
}

# Bug-pattern verdicts: (sink class, origin set) → (finding_class, severity)
def _verdict(cls: str, origins: set[str], bounded: bool) -> tuple[str, int]:
    if cls == "copy":
        if "subtract" in origins or "multiply" in origins:
            return ("copy-underflow", 3)
        if not bounded and ("dynamic" in origins or "external" in origins
                            or "argument" in origins):
            return ("unbounded-copy", 2)
        return ("copy-constant", 1)
    if cls == "format":
        if origins - {"constant"}:
            return ("format-string", 3)
        return ("format-constant", 1)
    if cls == "alloc":
        if "multiply" in origins:
            return ("alloc-overflow", 3)
        if "subtract" in origins:
            return ("alloc-underflow", 3)
        if origins - {"constant"}:
            return ("alloc-dynamic", 2)
        return ("alloc-constant", 1)
    if cls == "exec":
        if "external" in origins or "dynamic" in origins:
            return ("exec-injection", 3)
        return ("exec-fixed", 1)
    if cls == "source":
        return ("external-input", 1)
    return ("observed", 1)


def _trace_reg(fn, start: Insn, reg: str, *,
               view: ImageView) -> tuple[set[str], bool, list[str]]:
    """Backward walk: what fed *reg* before *start*?

    Walks the containing block's instructions before the call site, then
    predecessor blocks' tails, tracking reg copies and arithmetic. Returns
    (origins, bounded, trail) — origins ⊆ {constant, argument, external,
    dynamic, stack, multiply, subtract, unknown}; bounded=True when an
    and/mask/clamp was seen in the trail.
    """
    origins: set[str] = set()
    trail: list[str] = []
    bounded = False
    queue: list[tuple[str, int]] = [(reg, 0)]  # (regname, depth)
    seen: set[str] = set()
    steps = 0
    # Flatten function insns ≤ the call site, block-ordered.
    insns: list[Insn] = []
    for b in sorted(fn.blocks.values(), key=lambda x: x.start):
        for i in b.insns:
            insns.append(i)
            if i.addr == start.addr:
                break
    # index of the call site
    try:
        end_i = next(i for i, x in enumerate(insns)
                     if x.addr == start.addr)
    except StopIteration:
        return {"unknown"}, False, []
    cursor = end_i - 1
    while queue and steps < MAX_STEPS:
        cur, depth = queue.pop()
        if cur in seen or depth > MAX_DEPTH:
            continue
        seen.add(cur)
        # walk backward from cursor through the flattened stream
        found = False
        for i in range(cursor, max(0, cursor - MAX_STEPS), -1):
            steps += 1
            ins = insns[i]
            ops = ins.ops
            if len(ops) < 1 or ops[0].get("kind") != "reg" \
                    or ops[0]["reg"] != cur:
                continue
            found = True
            src = ops[1] if len(ops) > 1 else None
            m = ins.mnemonic
            trail.append(f"{ins.mnemonic} {ins.op_str}".strip())
            if m == "mov" or m == "lea":
                if src and src["kind"] == "imm":
                    origins.add("constant")
                elif src and src["kind"] == "reg":
                    queue.append((src["reg"], depth + 1))
                    cursor = i - 1
                    break
                elif src and src["kind"] == "mem":
                    if src.get("base") in ("rbp", "rsp") or \
                            (src.get("base") == "rip"):
                        origins.add("stack" if src.get("base") != "rip"
                                    else "fixed")
                    else:
                        origins.add("external")
                continue
            if m in ("add", "sub", "imul", "mul", "xor", "and", "or",
                     "shl", "shr", "sar", "neg", "not", "inc", "dec"):
                if m in ("sub",):
                    origins.add("subtract")
                if m in ("imul", "mul"):
                    origins.add("multiply")
                if m == "and":
                    bounded = True  # mask/clamp seen
                origins.add("dynamic")
                if src and src["kind"] == "reg":
                    queue.append((src["reg"], depth + 1))
                if src and src["kind"] == "imm" and m == "and":
                    bounded = True
                continue
            if m == "call":
                origins.add("external")
                continue
            if m == "movzx" or m == "movsxd":
                if src and src["kind"] == "reg":
                    queue.append((src["reg"], depth + 1))
                    cursor = i - 1
                    break
                origins.add("dynamic")
                continue
            origins.add("dynamic")
            continue
        if not found:
            # Function argument — reg never written before the call.
            if cur in ARG_REGS:
                origins.add("argument")
            else:
                origins.add("unknown")
            break
        cursor -= 1
    if not origins:
        origins.add("unknown")
    return origins, bounded, trail


def audit(analysis: Analysis, view: ImageView, *,
          reachable_only: bool = False) -> dict:
    """Run the sink audit over the recovered call graph."""
    findings: list[dict] = []
    roots = set()
    if view.img is not None and view.img.entry_rva:
        roots.add(view.img.image_base + view.img.entry_rva)
    roots |= set(view.names)

    for key, refs in analysis.xrefs_to.items():
        if not isinstance(key, str) or "!" not in key:
            continue
        api = key.split("!")[-1].lower()
        meta = SINKS.get(api)
        if not meta:
            continue
        for ref in refs:
            site = ref["from"]
            fn = analysis.function_at(site)
            if fn is None:
                continue
            # the call instruction at the site
            call_ins = None
            for b in fn.blocks.values():
                for ins in b.insns:
                    if ins.addr == site and ins.mnemonic == "call":
                        call_ins = ins
                        break
            if call_ins is None:
                continue
            arg_reg = ARG_REGS[meta["arg"]] \
                if meta["arg"] < len(ARG_REGS) else ARG_REGS[-1]
            origins, bounded, trail = _trace_reg(fn, call_ins, arg_reg,
                                                 view=view)
            cls_name, sev = _verdict(meta["cls"], origins, bounded)
            if sev < 2:
                continue  # constant/benign sites are not findings
            reach = (Reachability.CONFIRMED_DIRECT.value
                     if fn.start in roots or fn.xrefs_in
                     else Reachability.UNRESOLVED.value)
            findings.append({
                "sink": api,
                "sink_class": meta["cls"],
                "finding_class": cls_name,
                "severity": sev,
                "site_va": site,
                "function": fn.name,
                "function_va": fn.start,
                "arg_register": arg_reg,
                "origins": sorted(origins),
                "bounded": bounded,
                "reachability": reach,
                "trail": trail[:16],
                "note": meta["note"],
            })
    findings.sort(key=lambda r: (-r["severity"], r["site_va"]))
    return {
        "findings": findings,
        "count": len(findings),
        "sinks_matched": len({f["sink"] for f in findings}),
        "note": ("provenance is a bounded backward walk — 'unknown' means "
                 "the walk couldn't prove an origin, not that the site is "
                 "safe"),
    }
