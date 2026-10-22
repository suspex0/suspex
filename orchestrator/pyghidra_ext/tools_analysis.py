"""Read/analysis tool bodies — decompile, disasm, functions, symbols,
strings, imports/exports, xrefs, callgraph, bytes, scans, pcode.

Every function takes the resolved ``binary_name`` as its first arg (the
shim injects it from the session map); arg spellings follow
pyghidra-mcp where they exist and ida-pro-mcp analogues otherwise, so
``ghidra_manage`` is a drop-in for ``ida_manage`` habits.
"""
from __future__ import annotations

import re
from typing import Any

from .helpers import (_addr_str, _decompile, _err, _iter_functions,
                      _match, _page, _resolve_target)
from .state import STATE, _j


# ------------------------------------------------------------ metadata ----

def get_metadata(binary_name: str) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    fm = p.getFunctionManager()
    return _j({
        "binary_name": binary_name,
        "path": st.get("path", ""),
        "image_base": _addr_str(p.getImageBase()),
        "min_address": _addr_str(p.getMinAddress()),
        "max_address": _addr_str(p.getMaxAddress()),
        "language": str(p.getLanguageID()),
        "compiler_spec": STATE._safe(
            lambda: str(p.getCompilerSpec().getCompilerSpecID())),
        "executable_format": STATE._safe(
            lambda: str(p.getExecutableFormat())),
        "executable_path": STATE._safe(
            lambda: str(p.getExecutablePath())),
        "function_count": int(fm.getFunctionCount()),
        "analyzing": STATE.is_analyzing(binary_name),
    })


# ------------------------------------------------------------ functions ----

def list_functions(binary_name: str, query: str = "", offset: int = 0,
                   limit: int = 200) -> str:
    st = STATE.get(binary_name)
    rows = []
    for f in _iter_functions(st["program"]):
        nm = f.getName()
        if _match(query, nm):
            rows.append({"name": nm,
                         "entry": _addr_str(f.getEntryPoint()),
                         "size": int(f.getBody().getNumAddresses())})
    return _j(_page(rows, offset, limit))


def get_function_by_name(binary_name: str, name: str) -> str:
    st = STATE.get(binary_name)
    f = STATE.get_function(st["program"], name)
    if f is None:
        return _j(_err("not_found", f"function {name!r} not found"))
    return _j({"name": f.getName(), "entry": _addr_str(f.getEntryPoint()),
               "size": int(f.getBody().getNumAddresses()),
               "signature": str(f.getSignature()),
               "calling_convention": str(f.getCallingConventionName())})


def get_function_by_address(binary_name: str, address: str) -> str:
    st = STATE.get(binary_name)
    f = STATE.get_function(st["program"], address)
    if f is None:
        return _j(_err("not_found",
                       f"no function at/containing {address}"))
    return _j({"name": f.getName(), "entry": _addr_str(f.getEntryPoint()),
               "size": int(f.getBody().getNumAddresses())})


def search_symbols_by_name(binary_name: str, query: str,
                           functions_only: bool = False,
                           offset: int = 0, limit: int = 25) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    if functions_only:
        for f in _iter_functions(p):
            if _match(query, f.getName()):
                rows.append({"name": f.getName(), "type": "function",
                             "address": _addr_str(f.getEntryPoint())})
    else:
        sym_it = p.getSymbolTable().getAllSymbols(True)
        while sym_it.hasNext():
            s = sym_it.next()
            nm = s.getName()
            if _match(query, nm):
                rows.append({"name": nm,
                             "type": str(s.getSymbolType()),
                             "address": _addr_str(s.getAddress())})
    return _j(_page(rows, offset, limit))


# ------------------------------------------------------------ decompile ----

def decompile_function(binary_name: str, name_or_address: Any = None,
                       include_callees: bool = False,
                       include_strings: bool = False,
                       include_xrefs: bool = False,
                       timeout_sec: int = 30,
                       # aliases for ida-manage muscle memory
                       address: Any = None, func: Any = None) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    target = name_or_address if name_or_address is not None \
        else (address if address is not None else func)
    if target is None:
        return _j(_err("bad_arg",
                       "name_or_address (or address) is required"))
    targets = target if isinstance(target, list) else [target]
    out = []
    for t in targets:
        f = _resolve_target(p, t)
        if isinstance(f, list):
            f = f[0] if f else None
        if f is None:
            out.append({"name": str(t), "code": "",
                        "error": f"function or symbol {t!r} not found"})
            continue
        res = _decompile(p, f, timeout_sec)
        entry = {"name": f.getName(),
                 "entry": _addr_str(f.getEntryPoint())}
        if res is None:
            entry["code"] = ""
            entry["error"] = "decompile failed (no result / timeout)"
        else:
            df = res.getDecompiledFunction()
            entry["code"] = df.getC() if df is not None else ""
        if include_callees:
            callees = set()
            try:
                for c in f.getCalledFunctions(STATE.monitor()):
                    callees.add(c.getName())
            except Exception:  # noqa: BLE001
                pass
            entry["callees"] = sorted(callees)
        if include_strings:
            entry["strings"] = _function_strings(p, f)
        if include_xrefs:
            entry["xrefs"] = _xrefs_to(p, f.getEntryPoint(), 25)
        out.append(entry)
    return _j(out[0] if len(out) == 1 else out)


def _function_strings(program: Any, func: Any) -> list[dict]:
    """Strings referenced from inside ``func``'s body (via xrefs to data)."""
    out = []
    rm = program.getReferenceManager()
    listing = program.getListing()
    body = func.getBody()
    addr_it = body.getAddresses(True)
    count = 0
    while addr_it.hasNext() and count < 64:
        a = addr_it.next()
        for ref in rm.getReferencesFrom(a):
            to = ref.getToAddress()
            data = listing.getDataAt(to)
            if data is not None and data.hasStringValue():
                val = data.getValue()
                if isinstance(val, str) and val:
                    out.append({"address": _addr_str(to), "value": val})
                    count += 1
    return out[:64]


# --------------------------------------------------------------- disasm ----

def disassemble_function(binary_name: str, address: Any = None,
                         name_or_address: Any = None) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    target = address if address is not None else name_or_address
    f = STATE.get_function(p, target)
    if f is None:
        return _j(_err("not_found", f"no function at/containing {target}"))
    listing = p.getListing()
    body = f.getBody()
    it = listing.getInstructions(body, True)
    lines = []
    while it.hasNext():
        ins = it.next()
        lines.append(f"{_addr_str(ins.getAddress())}  {ins.toString()}")
    return _j({"name": f.getName(), "entry": _addr_str(f.getEntryPoint()),
               "text": "\n".join(lines), "instruction_count": len(lines)})


def get_pcode(binary_name: str, name_or_address: Any = None,
              address: Any = None, high: bool = True) -> str:
    """P-code IR for a function — ``high=true`` emits the decompiler's
    lifted ops; ``high=false`` raw per-instruction pcode."""
    st = STATE.get(binary_name)
    p = st["program"]
    f = STATE.get_function(p, name_or_address if name_or_address is not None
                           else address)
    if f is None:
        return _j(_err("not_found", "no function resolved"))
    if high:
        res = _decompile(p, f)
        if res is None:
            return _j(_err("decompile_failed",
                           "decompile required for high pcode"))
        hf = res.getHighFunction()
        ops = []
        if hf is not None:
            it = hf.getPcodeOps()
            while it.hasNext():
                ops.append(str(it.next()))
        return _j({"name": f.getName(),
                   "entry": _addr_str(f.getEntryPoint()),
                   "pcode": ops})
    listing = p.getListing()
    it = listing.getInstructions(f.getBody(), True)
    ops = []
    while it.hasNext():
        ins = it.next()
        for op in ins.getPcode():
            ops.append(f"{_addr_str(ins.getAddress())}: {op.toString()}")
    return _j({"name": f.getName(),
               "entry": _addr_str(f.getEntryPoint()),
               "pcode": ops})


# --------------------------------------------------------------- xrefs ----

def _xrefs_to(program: Any, addr: Any, limit: int) -> list[dict]:
    rm = program.getReferenceManager()
    fm = program.getFunctionManager()
    rows = []
    it = rm.getReferencesTo(addr)
    while it.hasNext() and len(rows) < int(limit or 50):
        r = it.next()
        from_a = r.getFromAddress()
        in_f = fm.getFunctionContaining(from_a)
        rows.append({
            "from": _addr_str(from_a),
            "to": _addr_str(r.getToAddress()),
            "type": str(r.getReferenceType()),
            "in_function": (in_f.getName() if in_f is not None else ""),
            "in_function_entry": (_addr_str(in_f.getEntryPoint())
                                   if in_f is not None else ""),
        })
    return rows


def list_xrefs(binary_name: str, name_or_address: Any = None,
               address: Any = None, limit: int = 50) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    target = name_or_address if name_or_address is not None else address
    targets = target if isinstance(target, list) else [target]
    out = []
    for t in targets:
        addr = _resolve_symbol_or_addr(p, t)
        if addr is None:
            out.append({"name": str(t), "xrefs": [],
                        "error": f"{t!r} not found"})
            continue
        rows = _xrefs_to(p, addr, limit)
        f = STATE.get_function(p, addr)
        out.append({"name": (f.getName() if f is not None else str(t)),
                    "address": _addr_str(addr), "xrefs": rows})
    return _j(out[0] if len(out) == 1 else out)


def _resolve_symbol_or_addr(program: Any, value: Any):
    """Like to_addr but also resolves plain symbol names."""
    try:
        return STATE.to_addr(program, value)
    except Exception:  # noqa: BLE001
        pass
    st = program.getSymbolTable()
    try:
        for s in st.getGlobalSymbols(str(value)):
            return s.getAddress()
    except Exception:  # noqa: BLE001
        pass
    f = STATE.get_function(program, value)
    return f.getEntryPoint() if f is not None else None


def gen_callgraph(binary_name: str, function_name: str,
                  direction: str = "calling", depth: int = 2,
                  max_nodes: int = 60) -> str:
    """Mermaid flowchart of the call neighborhood — direction 'calling'
    (edges to callees) or 'called' (edges from callers)."""
    st = STATE.get(binary_name)
    p = st["program"]
    root = STATE.get_function(p, function_name)
    if root is None:
        return _j(_err("not_found", f"function {function_name!r} not found"))
    mon = STATE.monitor()
    nodes: dict[str, str] = {}
    edges: set[tuple[str, str]] = set()
    seen: set[str] = set()
    frontier = [(root, 0)]
    while frontier and len(nodes) < max_nodes:
        f, d = frontier.pop(0)
        fname = f.getName()
        if fname in seen and d >= depth:
            continue
        seen.add(fname)
        nodes[fname] = fname
        if d >= depth:
            continue
        try:
            nbrs = (f.getCalledFunctions(mon) if direction != "called"
                    else f.getCallingFunctions(mon))
            for g in nbrs:
                gname = g.getName()
                if direction != "called":
                    edges.add((fname, gname))
                else:
                    edges.add((gname, fname))
                if gname not in seen:
                    frontier.append((g, d + 1))
        except Exception:  # noqa: BLE001
            continue
    lines = ["flowchart TD"]
    ids = {n: f"n{i}" for i, n in enumerate(sorted(nodes))}
    for nm, nid in ids.items():
        safe = nm.replace('"', "'")
        lines.append(f'  {nid}["{safe}"]')
    for a, b in sorted(edges):
        if a in ids and b in ids:
            lines.append(f"  {ids[a]} --> {ids[b]}")
    return _j({"root": root.getName(), "direction": direction,
               "depth": depth, "nodes": len(nodes), "edges": len(edges),
               "mermaid": "\n".join(lines)})


# ------------------------------------------------------------ imports ----

def list_imports(binary_name: str, query: str = ".*", offset: int = 0,
                 limit: int = 25) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    try:
        em = p.getExternalManager()
        libs = list(em.getExternalLibraryNames())
        for lib in libs:
            el = em.getExternalLibrary(lib)
            if el is None:
                continue
            it = el.getSymbols()
            while it.hasNext():
                s = it.next()
                nm = s.getName()
                if _match(query, nm):
                    rows.append({"name": nm, "library": lib,
                                 "address": _addr_str(s.getAddress())
                                 if s.getAddress() else ""})
    except Exception:  # noqa: BLE001 - fall back to symbol-table scan
        sym_it = p.getSymbolTable().getExternalSymbols()
        while sym_it.hasNext():
            s = sym_it.next()
            if _match(query, s.getName()):
                rows.append({"name": s.getName(),
                             "library": STATE._safe(
                                 lambda: str(s.getParentNamespace()
                                             .getName())),
                             "address": ""})
    return _j(_page(rows, offset, limit))


def list_exports(binary_name: str, query: str = ".*", offset: int = 0,
                 limit: int = 25) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    st_tab = p.getSymbolTable()
    it = st_tab.getExternalEntryPointIterator()
    while it.hasNext():
        a = it.next()
        s = st_tab.getPrimarySymbol(a)
        if s is not None and _match(query, s.getName()):
            rows.append({"name": s.getName(), "address": _addr_str(a)})
    return _j(_page(rows, offset, limit))


def get_entry_points(binary_name: str) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    st_tab = p.getSymbolTable()
    it = st_tab.getExternalEntryPointIterator()
    while it.hasNext():
        a = it.next()
        s = st_tab.getPrimarySymbol(a)
        rows.append({"name": s.getName() if s is not None else "",
                     "address": _addr_str(a)})
    return _j({"count": len(rows), "entry_points": rows})


# ------------------------------------------------------------ segments ----

def list_segments(binary_name: str) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    for b in p.getMemory().getBlocks():
        rows.append({"name": b.getName(),
                     "start": _addr_str(b.getStart()),
                     "end": _addr_str(b.getEnd()),
                     "size": int(b.getSize()),
                     "read": bool(b.isRead()),
                     "write": bool(b.isWrite()),
                     "execute": bool(b.isExecute()),
                     "type": str(b.getType())})
    return _j({"count": len(rows), "segments": rows})


# --------------------------------------------------------------- bytes ----

def read_bytes(binary_name: str, address: str, size: int = 32) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    addr = STATE.to_addr(p, address)
    n = min(int(size or 32), 4096)
    try:
        from jpype import JByte, JArray  # noqa: F401
    except ImportError:
        JByte = JArray = None
    buf = bytearray(n)
    got = p.getMemory().getBytes(addr, buf)
    if got < 0:
        return _j(_err("read_failed",
                       f"getBytes returned {got} at {address}"))
    data = bytes(buf[:got])
    return _j({"address": _addr_str(addr), "size": got,
               "hex": data.hex(" "), 
               "ascii": "".join(chr(b) if 32 <= b < 127 else "."
                                for b in data)})


# --------------------------------------------------------------- strings ----

def search_strings(binary_name: str, query: str, limit: int = 100) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    rows = []
    it = p.getListing().getDefinedData(True)
    while it.hasNext() and len(rows) < int(limit or 100):
        d = it.next()
        if not d.hasStringValue():
            continue
        val = d.getValue()
        if isinstance(val, str) and _match(query, val):
            rows.append({"address": _addr_str(d.getAddress()),
                         "value": val[:512],
                         "length": int(d.getLength())})
    return _j({"count": len(rows), "truncated": len(rows) >= limit,
               "strings": rows})


# --------------------------------------------------------------- create ----

def create_function(binary_name: str, address: str,
                    name: str = "") -> str:
    """Force-carve a function at ``address`` (auto-analysis missed it)."""
    st = STATE.get(binary_name)
    p = st["program"]
    flat = st["flat"]
    addr = STATE.to_addr(p, address)
    fm = p.getFunctionManager()
    existing = fm.getFunctionAt(addr)
    if existing is not None:
        return _j({"ok": True, "created": False, "existed": True,
                   "name": existing.getName(),
                   "entry": _addr_str(addr)})
    with STATE.lock:
        f = flat.createFunction(addr, name or None)
    if f is None:
        return _j(_err("create_failed",
                       f"createFunction returned null at {address}"))
    return _j({"ok": True, "created": True, "name": f.getName(),
               "entry": _addr_str(f.getEntryPoint())})


# ------------------------------------------------------------- searches ----

def _block_bytes(mem: Any, start: Any, length: int) -> bytes:
    buf = bytearray(length)
    got = mem.getBytes(start, buf)
    return bytes(buf[:max(got, 0)])


def pattern_scan(binary_name: str, hex_pattern: str = "",
                 hex: str = "", seg: str = "",
                 max_results: int = 64) -> str:
    """Masked byte scan ('4C 8D ?? 48') over each executable block (or a
    named segment), implemented shim-side over raw block bytes so the
    wildcard semantics match mem_rw pattern_scan."""
    st = STATE.get(binary_name)
    p = st["program"]
    pat = (hex_pattern or hex or "").strip()
    toks = pat.split()
    if not toks:
        return _j(_err("bad_arg", "hex pattern required"))
    mask: list[int | None] = []
    for t in toks:
        if t in ("??", "?"):
            mask.append(None)
            continue
        # nibble wildcards: '4?' / '?D'
        if "?" in t and len(t) == 2:
            try:
                mask.append(int(t.replace("?", "0"), 16))
            except ValueError:
                return _j(_err("bad_arg", f"bad pattern token {t!r}"))
            continue
        try:
            mask.append(int(t, 16))
        except ValueError:
            return _j(_err("bad_arg", f"bad pattern token {t!r}"))
    hits = []
    mem = p.getMemory()
    for b in mem.getBlocks():
        if seg and b.getName() != seg:
            continue
        if not seg and not b.isExecute():
            continue
        data = _block_bytes(mem, b.getStart(), int(b.getSize()))
        plen = len(mask)
        base_off = int(b.getStart().getOffset())
        for i in range(0, max(0, len(data) - plen + 1)):
            ok = True
            for j, m in enumerate(mask):
                if m is None:
                    continue
                tok = toks[j]
                if "?" in tok and len(tok) == 2:
                    byte = data[i + j]
                    if tok[0] == "?" and (byte & 0x0F) != (m & 0x0F):
                        ok = False; break
                    if tok[1] == "?" and (byte & 0xF0) != (m & 0xF0):
                        ok = False; break
                    continue
                if data[i + j] != m:
                    ok = False; break
            if ok:
                hits.append({"address": f"0x{(base_off + i) & 0xFFFFFFFFFFFFFFFF:x}"})
                if len(hits) >= max_results:
                    return _j({"count": len(hits), "truncated": True,
                               "hits": hits})
    return _j({"count": len(hits), "truncated": False, "hits": hits})


def qword_value_scan(binary_name: str, value: str = "", seg: str = "",
                     max_results: int = 64) -> str:
    """Locate a u64 constant (little-endian) in memory blocks."""
    st = STATE.get(binary_name)
    p = st["program"]
    try:
        v = int(str(value), 0)
    except ValueError:
        return _j(_err("bad_arg", f"bad u64 value {value!r}"))
    needle = v.to_bytes(8, "little")
    hits = []
    mem = p.getMemory()
    for b in mem.getBlocks():
        if seg and b.getName() != seg:
            continue
        data = _block_bytes(mem, b.getStart(), int(b.getSize()))
        base_off = int(b.getStart().getOffset())
        idx = 0
        while True:
            i = data.find(needle, idx)
            if i < 0:
                break
            hits.append({"address": f"0x{(base_off + i) & 0xFFFFFFFFFFFFFFFF:x}"})
            if len(hits) >= max_results:
                return _j({"count": len(hits), "truncated": True,
                           "hits": hits})
            idx = i + 1
    return _j({"count": len(hits), "truncated": False, "hits": hits})


def search_code(binary_name: str, query: str, limit: int = 5,
                offset: int = 0, search_mode: str = "literal",
                max_functions: int = 4000) -> str:
    """Literal/regex search over decompiled function bodies.

    ``search_mode='semantic'`` is accepted for pyghidra-mcp arg parity
    but maps to literal — embeddings are not part of this backend."""
    st = STATE.get(binary_name)
    p = st["program"]
    try:
        rx = re.compile(query) if search_mode in ("literal", "regex",
                                                  "semantic") else None
    except re.error:
        rx = None
    hits = []
    scanned = 0
    for f in _iter_functions(p):
        scanned += 1
        if scanned > max_functions:
            break
        res = _decompile(p, f, 15)
        if res is None:
            continue
        df = res.getDecompiledFunction()
        code = df.getC() if df is not None else ""
        if not code:
            continue
        if rx is not None:
            m = rx.search(code)
        else:
            m = None
            if query.lower() in code.lower():
                m = True
        if m:
            snippet = ""
            if rx is not None:
                s0 = max(0, m.start() - 80)
                snippet = code[s0:m.end() + 80]
            hits.append({"name": f.getName(),
                         "entry": _addr_str(f.getEntryPoint()),
                         "score": None,
                         "snippet": snippet})
            if len(hits) >= offset + limit:
                break
    return _j({"count": len(hits[offset:]),
               "scanned_functions": scanned,
               "search_mode": "literal",
               "note": ("semantic mode maps to literal in this backend"
                        if search_mode == "semantic" else ""),
               "results": hits[offset:offset + limit]})


def analysis_status(binary_name: str) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    fm = p.getFunctionManager()
    return _j({"binary_name": binary_name,
               "analyzing": STATE.is_analyzing(binary_name),
               "function_count": int(fm.getFunctionCount()),
               "analyzed": STATE.is_analyzed(binary_name)})


def ghidra_query_context(binary_name: str, address: str = "") -> str:
    """One-shot context probe for an address: in-program, containing
    function, block — the disambiguator nearest_function feeds on."""
    st = STATE.get(binary_name)
    p = st["program"]
    out = {"ok": True, "binary_name": binary_name}
    if not address:
        return _j(out)
    try:
        addr = STATE.to_addr(p, address)
    except Exception:  # noqa: BLE001
        return _j({"ok": False, "kind": "bad_address",
                   "addr_in_project": False, "in_function": False})
    out["address"] = _addr_str(addr)
    mem = p.getMemory()
    block = mem.getBlock(addr)
    out["addr_in_project"] = block is not None
    if block is not None:
        out["block"] = block.getName()
    fm = p.getFunctionManager()
    f = fm.getFunctionContaining(addr)
    out["in_function"] = f is not None
    if f is not None:
        out["function_start"] = _addr_str(f.getEntryPoint())
        out["function_name"] = f.getName()
        out["function_end"] = _addr_str(f.getBody().getMaxAddress())
    return _j(out)


def ghidra_status(binary_name: str) -> str:
    """Snapshot analogous to ida_status: analysis + symbol health in one
    envelope so open_status can classify symbols/named_functions."""
    st = STATE.get(binary_name)
    p = st["program"]
    fm = p.getFunctionManager()
    named = 0
    it = fm.getFunctions(True)
    n = 0
    while it.hasNext() and n < 100000:
        f = it.next()
        n += 1
        if not f.getName().startswith("FUN_"):
            named += 1
    total = int(fm.getFunctionCount())
    return _j({
        "binary_name": binary_name,
        "analysis_state": ("running" if STATE.is_analyzing(binary_name)
                            else "idle"),
        "functions_count": total,
        "named_functions": named,
        "pdb": "unknown",
        "image_base": _addr_str(p.getImageBase()),
        "executable_format": STATE._safe(
            lambda: str(p.getExecutableFormat())),
    })
