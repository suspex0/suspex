"""Engine-backed ``bin_manage`` actions — function recovery, CFG, xrefs,
call paths, driver-surface passes, audit, diff, pseudo.

Split from ``bin.py`` so the parse-only actions stay dependency-free and
this module can demand the codegen extra (capstone) on first use.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from typing import Any

from .common import (  # noqa: F401 — shared helpers the dispatcher uses
    _j, _list_envelope, _codegen_extra_err, _unknown_action,
)


def _jh(data):
    """Same extended-key hexify as bin.py — kept local so this module
    stays importable on its own."""
    from .._hex_addresses import HEX_ADDRESS_KEYS, HEX_SIZE_KEYS, \
        hexify_dict
    from .bin import _BIN_ADDR_KEYS, _BIN_SIZE_KEYS
    return _j(hexify_dict(
        data,
        addr_keys=HEX_ADDRESS_KEYS | _BIN_ADDR_KEYS,
        size_keys=HEX_SIZE_KEYS | _BIN_SIZE_KEYS,
        add_int_mirror=True))


def _engine_view(_an, data: bytes, img, img_base: int):
    """Build the ImageView for engine work: PE image when parseable,
    blob wrapper otherwise.

    `img_base` is the *live* base for `source="memory"` (the parsed
    header keeps the linker's preferred base under KASLR) — passing it
    through makes every VA this view produces directly usable.
    """
    from ...analysis import engine as _eng
    if img is not None:
        return _eng.ImageView(img, base_va=img_base or 0)
    base = img_base or 0
    return _eng.wrap_blob(data, base_va=base)


_ROP_ACTIONS = frozenset({"gadgets", "gadget_check", "chain_check"})

# Gadget indexes are expensive to build (full exec-region decode sweep)
# and cheap to keep — cache per (image sha256, base VA) with a small FIFO
# cap. `refresh=true` rebuilds. Keyed on base VA because bad_bytes /
# VA-bearing rows differ per boot for source="memory".
_GADGET_CACHE: "OrderedDict[tuple[str, int], Any]" = OrderedDict()
_GADGET_CACHE_CAP = 8

# The same goes for the engine's whole-image analysis (function inventory
# + xref graph): every engine action needs it and rebuilding per call is
# tens of seconds on a multi-MB driver. Cached per (sha256, base_va,
# budget); `refresh=true` bypasses. The dispatch now runs in a worker
# thread, so both caches share one lock.
_ANALYSIS_CACHE: "OrderedDict[tuple[str, int, int], Any]" = OrderedDict()
_ANALYSIS_CACHE_CAP = 4
_CACHE_LOCK = threading.Lock()


def _cached_analysis(data: bytes, view, budget: int,
                     refresh: bool = False):
    """analyze_image() behind the sha/base/budget-keyed cache.
    Returns (analysis, from_cache). Callers MUST NOT mutate the result —
    it is shared across calls."""
    from ...analysis import engine as _eng
    sha = hashlib.sha256(data).hexdigest()
    key = (sha, view.base_va, int(budget))
    if not refresh:
        with _CACHE_LOCK:
            hit = _ANALYSIS_CACHE.get(key)
            if hit is not None:
                _ANALYSIS_CACHE.move_to_end(key)
                return hit, True
    analysis = _eng.analyze_image(view, budget=budget)
    with _CACHE_LOCK:
        _ANALYSIS_CACHE[key] = analysis
        _ANALYSIS_CACHE.move_to_end(key)
        while len(_ANALYSIS_CACHE) > _ANALYSIS_CACHE_CAP:
            _ANALYSIS_CACHE.popitem(last=False)
    return analysis, False


# ---------------------------------------------------------------------------
# Analysis jobs — background function-inventory builds (mem_rw scan_jobs
# shape). On a multi-MB image a cold analysis outlives client-side MCP
# timeouts even though to_thread keeps the loop alive, so big-engine
# actions auto-kick a job instead of blocking: the caller polls
# analyze_status, then re-issues and hits the warm cache.
# ---------------------------------------------------------------------------

ENGINE_ACTIONS = frozenset({
    "funcs", "disasm_func", "xrefs", "paths", "callgraph", "cfg",
    "irp_surface", "ioctl_surface", "audit", "diff", "pseudo"})

_ENGINE_SYNC_MAX = 512 * 1024   # exec bytes — bigger → background job

_AJOBS: "OrderedDict[str, dict]" = OrderedDict()
_AJOB_SEQ = [0]
_AJOB_CAP = 32


def _ajob_progress(job: dict) -> dict:
    eng = job.get("engine")
    r = getattr(eng, "result", None)
    return {"insns_decoded": getattr(r, "insns_decoded", 0)
                            or job.get("insns_decoded", 0),
            "functions": (len(r.functions) if r is not None
                          else job.get("functions", 0)),
            "budget": getattr(eng, "budget", 0),
            "elapsed_s": round(time.time() - job["started_ts"], 1)}


def start_or_join_analysis(data: bytes, view, budget: int,
                           origin: str, owner: str, *,
                           refresh: bool = False) -> dict:
    """Start (or attach to) a background analyze_image() for this image.
    Returns the job record; {"status": "ready", "cached": True} when the
    analysis cache is already warm."""
    sha = hashlib.sha256(data).hexdigest()
    key = (sha, view.base_va, int(budget))
    if not refresh:
        with _CACHE_LOCK:
            if key in _ANALYSIS_CACHE:
                return {"status": "ready", "cached": True}
    for job in _AJOBS.values():
        if job["key"] == key and job["status"] == "running":
            return job
    _AJOB_SEQ[0] += 1
    jid = f"a{_AJOB_SEQ[0]:04d}"
    job: dict[str, Any] = {
        "analyze_id": jid, "key": key, "kind": "engine",
        "status": "running", "origin": origin, "owner": owner,
        "started_ts": time.time(), "finished_ts": None,
        "error": "", "task": None, "engine": None}

    async def _run() -> None:
        from ...analysis import engine as _eng
        try:
            eng = _eng.Engine(view, budget=budget)
            job["engine"] = eng          # live progress handle
            analysis = await asyncio.to_thread(eng.analyze)
            with _CACHE_LOCK:
                _ANALYSIS_CACHE[key] = analysis
                _ANALYSIS_CACHE.move_to_end(key)
                while len(_ANALYSIS_CACHE) > _ANALYSIS_CACHE_CAP:
                    _ANALYSIS_CACHE.popitem(last=False)
            job["status"] = "ready"
            job["functions"] = len(analysis.functions)
            job["insns_decoded"] = analysis.insns_decoded
            job["truncated"] = analysis.truncated
        except Exception as exc:  # noqa: BLE001 — surfaced via status
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            job["finished_ts"] = time.time()
            job["engine"] = None
            while len(_AJOBS) > _AJOB_CAP:
                _AJOBS.popitem(last=False)

    _AJOBS[jid] = job
    job["task"] = asyncio.create_task(_run(), name=f"suspex-an-{jid}")
    return job


def maybe_start_job(action: str, data: bytes, img, img_base: int,
                    budget: int, origin: str, owner: str,
                    refresh: bool = False) -> dict | None:
    """Gate for engine actions: ``None`` → run inline (small image or
    warm cache); a dict envelope → job kicked, caller returns it."""
    view = _engine_view(None, data, img, img_base)
    exec_bytes = sum(e - s for s, e in view.exec_ranges())
    if exec_bytes <= _ENGINE_SYNC_MAX and not refresh:
        return None
    sha = hashlib.sha256(data).hexdigest()
    key = (sha, view.base_va, int(budget))
    if not refresh:
        with _CACHE_LOCK:
            if key in _ANALYSIS_CACHE:
                return None      # warm — the inline call is instant
    job = start_or_join_analysis(data, view, budget, origin, owner,
                                 refresh=refresh)
    if job.get("status") == "ready":
        return None
    return {"ok": True, "kind": "analysis_running",
            "analyze_id": job["analyze_id"], "status": job["status"],
            "action": action, "exec_bytes": exec_bytes,
            "origin": origin,
            "progress": _ajob_progress(job),
            "hint": ("function inventory is building in the background — "
                     "poll bin_manage(action='analyze_status', job_id="
                     f"'{job['analyze_id']}'), then re-issue this call; "
                     "it will hit the warm cache and return instantly")}


def ajob_status(job_id: str, current: str) -> dict:
    job = _AJOBS.get(job_id)
    if job is None:
        return {"ok": False, "kind": "unknown_job",
                "error": f"analyze_id {job_id!r} not found",
                "hint": "bin_manage(action='analyze_list') to see jobs"}
    return {"ok": True, "analyze_id": job_id, "status": job["status"],
            "progress": _ajob_progress(job),
            "origin": job["origin"], "owner": job["owner"],
            "foreign": job["owner"] != current,
            "started_ts": job["started_ts"],
            "finished_ts": job.get("finished_ts"),
            "functions": job.get("functions"),
            "insns_decoded": job.get("insns_decoded"),
            "truncated": job.get("truncated"),
            "error": job.get("error") or ""}


def ajob_list(current: str) -> dict:
    return {"ok": True, "jobs": [
        {"analyze_id": jid, "status": j["status"], "kind": j["kind"],
         "origin": j["origin"], "owner": j["owner"],
         "foreign": j["owner"] != current,
         "progress": _ajob_progress(j), "error": j.get("error") or ""}
        for jid, j in _AJOBS.items()]}


def dispatch(ctx: Any, _an, action: str, data: bytes, img,
             img_base: int, *, target: Any, func: Any,
             compare_path: str, reachability: str, max_functions: int,
             max_instructions: int, limit: int, offset: int,
             fields: Any, filter: Any, summary: bool,
             verbosity: str, ending: str = "", category: str = "",
             reg: str = "", bad_bytes: str = "", max_len: int = 0,
             max_gadget_bytes: int = 0, scan_budget: int = 0,
             unique: bool = False, refresh: bool = False,
             chain: Any = "", expected_json: str = "",
             salvage: Any = None) -> str:
    from ...analysis import engine as _eng

    list_kw = dict(tool="bin_manage", action=action, limit=limit,
                   offset=offset, fields=fields or (), filter=filter,
                   summary=summary,
                   global_cap=ctx.cfg.mcp_max_items())

    view = _engine_view(_an, data, img, img_base)

    # Gadget passes need only the ImageView — running the recursive-
    # descent recovery first would burn the instruction budget for
    # nothing (and gadget rows come from unaligned decodes the engine
    # never visits).
    if action in _ROP_ACTIONS:
        return _rop_dispatch(
            ctx, view, action, data, img_base, list_kw=list_kw,
            target=target, chain=chain, expected_json=expected_json,
            ending=ending, category=category, reg=reg,
            bad_bytes=bad_bytes, max_len=max_len,
            max_gadget_bytes=max_gadget_bytes, scan_budget=scan_budget,
            unique=unique, refresh=refresh, salvage=salvage)

    try:
        analysis, analysis_cached = _cached_analysis(
            data, view,
            max_instructions or _eng.ANALYSIS_BUDGET,
            refresh=refresh)
    except _eng.AnalysisError as exc:
        return _j({"ok": False, "kind": exc.kind, "error": str(exc),
                   "hint": exc.hint})
    except Exception as exc:
        return _codegen_extra_err(exc)

    if action == "funcs":
        inv = sorted(analysis.functions.values(), key=lambda x: x.start)
        capped = inv[:max_functions] if max_functions > 0 else inv
        rows = [{
            "va": f.start, "name": f.name, "size": f.size,
            "blocks": len(f.blocks), "calls": len(f.calls),
            "xrefs_in": len(f.xrefs_in),
        } for f in capped]
        extras = {"truncated": analysis.truncated,
                  "insns_decoded": analysis.insns_decoded,
                  "functions": len(inv), "cached": analysis_cached}
        if salvage:
            extras["salvage"] = salvage
        return _jh(_list_envelope(rows, kind="funcs", extras=extras,
                                  **list_kw))

    if action == "disasm_func":
        fn = _resolve_func(analysis, view, func)
        if fn is None:
            return _j({"ok": False, "kind": "func_not_found",
                       "error": f"disasm_func: no function for {func!r}",
                       "hint": "bin_manage(action='funcs') to list"})
        return _jh(_render_function(analysis, view, fn))

    if action == "cfg":
        fn = _resolve_func(analysis, view, func)
        if fn is None:
            return _j({"ok": False, "kind": "func_not_found",
                       "error": f"cfg: no function for {func!r}"})
        nodes = [f"0x{a:X}" for a in sorted(fn.blocks)]
        edges = []
        for b in fn.blocks.values():
            for dst, kind in b.edges:
                if isinstance(dst, int) and dst in fn.blocks:
                    edges.append({"from": b.start, "to": dst,
                                  "kind": kind})
        return _jh({"function": fn.name, "start": fn.start,
                   "nodes": nodes, "edges": edges})

    if action == "xrefs":
        t = _resolve_target(analysis, view, target)
        if t is None:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "xrefs: target= required (va, '0x…', "
                                "function name, or dll!api)"})
        rows = analysis.xrefs_to.get(t, [])
        return _jh(_list_envelope(rows, kind="xrefs",
                                 extras={"target": t}, **list_kw))

    if action == "paths":
        t = _resolve_target(analysis, view, target)
        if not isinstance(t, int):
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "paths: target must resolve to a function "
                                "address (name or va)"})
        chains = analysis.paths_to(t)
        rows = [{"chain": [f"0x{a:X}" for a in c],
                 "chain_named": [_label(view, analysis, a) for a in c],
                 "depth": len(c)} for c in chains]
        return _jh(_list_envelope(
            rows, kind="paths",
            extras={"target": t,
                    "target_name": _label(view, analysis, t),
                    "note": "indirect dispatch is outside this graph — "
                            "empty does not mean unreachable"},
            **list_kw))

    if action == "callgraph":
        rows = []
        for f in analysis.functions.values():
            callees = sorted(
                c if isinstance(c, str) else f"0x{c:X}"
                for c in f.calls)
            rows.append({"va": f.start, "name": f.name,
                         "callees": callees,
                         "callee_count": len(callees)})
        return _jh(_list_envelope(rows, kind="callgraph", **list_kw))

    if action == "irp_surface":
        from ...analysis import driver as _drv
        return _jh(_drv.driver_surface(view, analysis))

    if action == "ioctl_surface":
        from ...analysis import driver as _drv
        return _jh(_drv.ioctl_surface(view, analysis))

    if action == "audit":
        from ...analysis import audit as _audit
        return _jh(_audit.audit(analysis, view,
                               reachable_only=(reachability
                                               == "confirmed")))

    if action == "diff":
        return _diff(ctx, _an, data, img, compare_path,
                     list_kw=list_kw)

    if action == "pseudo":
        from ...analysis import pseudo as _ps
        fn = _resolve_func(analysis, view, func)
        if fn is None:
            return _j({"ok": False, "kind": "func_not_found",
                       "error": f"pseudo: no function for {func!r}"})
        return _jh(_ps.pseudo(view, analysis, fn))

    return _unknown_action("bin_manage", action,
                           ["funcs", "disasm_func", "cfg", "xrefs",
                            "paths", "callgraph", "irp_surface",
                            "ioctl_surface", "audit", "diff", "pseudo"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _label(view, analysis, va: int) -> str:
    nm = view.name_for(va)
    if nm:
        return nm
    fn = analysis.functions.get(va)
    return fn.name if fn else f"sub_{va:X}"


def _resolve_target(analysis, view, target: Any):
    """Resolve a target selector: int va, '0x…' str, function name, or
    'dll!api' import name → int va or the name string."""
    if target is None or target == "":
        return None
    if isinstance(target, int):
        return target
    t = str(target).strip()
    try:
        return int(t, 0)
    except ValueError:
        pass
    # name → function start, or an import-slot name used as xref key
    for va, nm in view.names.items():
        if nm == t:
            return va
    for f in analysis.functions.values():
        if f.name == t:
            return f.start
    for slot, nm in view.iat_slots.items():
        if nm == t or nm.split("!", 1)[-1] == t:
            return nm
    return t


def _resolve_func(analysis, view, func: Any):
    if func is None or func == "":
        return None
    if isinstance(func, int):
        va = func
    else:
        s = str(func).strip()
        try:
            va = int(s, 0)
        except ValueError:
            va = 0
            for st, nm in view.names.items():
                if nm == s:
                    va = st
                    break
            if not va:
                for f in analysis.functions.values():
                    if f.name == s:
                        return f
    if not va:
        return None
    fn = analysis.functions.get(va)
    if fn is not None:
        return fn
    return analysis.function_at(va)


def _render_function(analysis, view, fn) -> dict:
    """Function-bounded labeled listing — the `disasm_func` output shape."""
    lines = []
    labels = {}
    for b in fn.blocks.values():
        for dst, kind in b.edges:
            if kind in ("jump", "fallthrough") and isinstance(dst, int) \
                    and dst in fn.blocks:
                labels[dst] = f"loc_{dst:X}"
    for bstart in sorted(fn.blocks):
        b = fn.blocks[bstart]
        if bstart in labels:
            lines.append({"label": labels[bstart], "va": bstart})
        for ins in b.insns:
            row = {"va": ins.addr, "bytes": "", "text": f"{ins.mnemonic} {ins.op_str}".strip()}
            tgt = ins.imm()
            if tgt is not None and ins.mnemonic in ("call", "jmp") \
                    or ins.mnemonic.startswith("j"):
                if isinstance(tgt, int) and tgt in labels:
                    row["text"] = f"{ins.mnemonic} {labels[tgt]}"
                elif isinstance(tgt, int):
                    nm = view.name_for(tgt)
                    if nm:
                        row["text"] = f"{ins.mnemonic} {nm}"
                    elif tgt in analysis.functions:
                        row["text"] = f"{ins.mnemonic} {analysis.functions[tgt].name}"
            xr = analysis.xrefs_to.get(ins.addr)
            if xr:
                row["xrefs"] = xr
            lines.append(row)
    return {"function": fn.name, "start": fn.start, "end": fn.end,
            "size": fn.size, "blocks": len(fn.blocks),
            "lines": lines}


def _diff(ctx, _an, data: bytes, img, compare_path: str, *,
          list_kw: dict) -> str:
    """Function-level diff vs compare_path via normalized body hashes."""
    from ...analysis import engine as _eng
    from ...analysis import pe as _pe

    if not compare_path:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "diff: compare_path= required",
                   "hint": "path to the reference binary under artifacts/"})
    from .._artifacts import resolve_artifact_path
    p = resolve_artifact_path(ctx.cfg, compare_path)
    if p is None:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "diff: compare_path outside artifacts_dir"})
    try:
        other_data = p.read_bytes()
    except OSError as exc:
        return _j({"ok": False, "kind": "file_not_found",
                   "error": f"diff: {exc}"})
    other_img = _maybe_parse(_pe, other_data)
    rows = []
    if img is None or other_img is None:
        return _j({"ok": False, "kind": "bad_magic",
                   "error": "diff: both inputs must parse as PE"})
    a, _ = _cached_analysis(data, _eng.ImageView(img),
                            _eng.ANALYSIS_BUDGET)
    b, _ = _cached_analysis(other_data, _eng.ImageView(other_img),
                            _eng.ANALYSIS_BUDGET)
    a_hashes = {}
    for va, f in a.functions.items():
        a_hashes.setdefault(_eng.body_hash(f), []).append(f.start - img.image_base)
    b_hashes = {}
    for va, f in b.functions.items():
        b_hashes.setdefault(_eng.body_hash(f), []).append(
            f.start - other_img.image_base)
    for h, starts in a_hashes.items():
        if h not in b_hashes:
            for s in starts:
                rows.append({"side": "only_in_left", "rva": s,
                             "body_hash": h[:16]})
    for h, starts in b_hashes.items():
        if h not in a_hashes:
            for s in starts:
                rows.append({"side": "only_in_right", "rva": s,
                             "body_hash": h[:16]})
    common = len(set(a_hashes) & set(b_hashes))
    return _jh(_list_envelope(
        rows, kind="diff",
        extras={"identical_functions": common,
                "changed_functions": len(rows),
                "left_functions": len(a.functions),
                "right_functions": len(b.functions)},
        **list_kw))


def _maybe_parse(_pe, data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    for lay in ("file", "image"):
        try:
            return _pe.parse(data, layout=lay)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Gadget actions — rp++-style scan + Unicorn validation.
# ---------------------------------------------------------------------------

def _coerce_va(value: Any, what: str = "target") -> int:
    """int / '0x…' hex string → VA. Raises ValueError otherwise."""
    if isinstance(value, bool) or value is None or value == "":
        raise ValueError(f"{what}: expected a VA (int or '0x…' hex)")
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except ValueError as exc:
        raise ValueError(
            f"{what}: {value!r} is not an int or '0x…' hex VA "
            "(module+offset is not supported here — pass the full VA)"
        ) from exc


def _parse_chain(chain: Any) -> list[int]:
    """chain= accepts a JSON list string, a Python list, or csv/space
    separated hex. Entries are raw stack qwords (gadget VAs and data
    values interleaved)."""
    if chain is None or chain == "":
        raise ValueError("chain_check: chain= is required "
                         "(e.g. '[\"0x…\", 0x4141, \"0x…\"]')")
    if isinstance(chain, str):
        s = chain.strip()
        items: list = []
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    items = parsed
            except ValueError:
                pass  # JSON with bare 0x… literals — token fallback
        if not items:
            # Tolerant tokenization: strip brackets/quotes, split on
            # commas/whitespace. Handles csv, "0x… 0x…", and
            # `[0x140001000, "0x4141"]` (not valid JSON).
            body = s[1:-1] if s.startswith("[") and s.endswith("]") else s
            items = [p.strip().strip('"').strip("'")
                     for p in re.split(r"[,\s]+", body)]
            items = [p for p in items if p]
    elif isinstance(chain, (list, tuple)):
        items = list(chain)
    else:
        raise ValueError(f"chain_check: chain= has unsupported type "
                         f"{type(chain).__name__}")
    out: list[int] = []
    for it in items:
        if isinstance(it, bool):
            raise ValueError("chain_check: bool is not a chain entry")
        if isinstance(it, int):
            out.append(it)
            continue
        t = str(it).strip()
        try:
            out.append(int(t, 16) if t.lower().startswith("0x")
                       else int(t, 0))
        except ValueError as exc:
            raise ValueError(
                f"chain_check: {it!r} is not an int/hex qword") from exc
    if not out:
        raise ValueError("chain_check: chain= resolved to zero entries")
    return out


def _parse_expected(spec: str) -> dict | None:
    """expected_json: {"regs": {"rax": "0x…"}, "rsp_delta": N}."""
    if not spec:
        return None
    try:
        obj = json.loads(spec)
    except ValueError as exc:
        raise ValueError(f"expected_json: not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("expected_json: expected a JSON object")
    out: dict[str, Any] = {}
    regs = obj.get("regs")
    if regs is not None:
        if not isinstance(regs, dict):
            raise ValueError('expected_json: "regs" must be an object')
        parsed_regs: dict[str, int] = {}
        for k, v in regs.items():
            try:
                parsed_regs[str(k).strip().lower()] = (
                    int(v, 0) if isinstance(v, str) else int(v))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"expected_json: regs.{k} = {v!r} is not an "
                    "int/hex value") from exc
        out["regs"] = parsed_regs
    if "rsp_delta" in obj:
        try:
            out["rsp_delta"] = int(obj["rsp_delta"])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "expected_json: rsp_delta must be an integer") from exc
    return out or None


def _rop_dispatch(ctx: Any, view, action: str, data: bytes,
                  img_base: int, *, list_kw: dict, target: Any,
                  chain: Any, expected_json: str, ending: str,
                  category: str, reg: str, bad_bytes: str, max_len: int,
                  max_gadget_bytes: int, scan_budget: int, unique: bool,
                  refresh: bool, salvage: Any = None) -> str:
    from ...analysis import rop as _rop

    if action == "gadgets":
        try:
            bad = _rop.parse_bad_bytes(bad_bytes)
            _rop.ending_selector(ending)  # validate before the scan
        except ValueError as exc:
            return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
        sha = hashlib.sha256(data).hexdigest()
        key = (sha, view.base_va)
        with _CACHE_LOCK:
            idx = None if refresh else _GADGET_CACHE.get(key)
        cached = idx is not None
        if idx is None:
            try:
                # Always build the full index — it is cached and shared,
                # so an ending-restricted build would poison later
                # queries. Filtering happens at query time.
                idx = _rop.build_index(
                    view,
                    max_bytes=max_gadget_bytes or _rop.DEFAULT_MAX_BYTES,
                    budget=scan_budget or _rop.DEFAULT_BUDGET)
            except Exception as exc:
                return _codegen_extra_err(exc)
            with _CACHE_LOCK:
                _GADGET_CACHE[key] = idx
                while len(_GADGET_CACHE) > _GADGET_CACHE_CAP:
                    _GADGET_CACHE.popitem(last=False)
        try:
            rows = _rop.query(idx, ending=ending, category=category,
                              reg=reg, bad_bytes=bad, max_len=max_len,
                              unique=unique)
        except ValueError as exc:
            return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
        extras: dict[str, Any] = {
            "image_sha256": sha,
            "base_va": view.base_va,
            "ranges": [{"label": lbl, "start": s, "end": e}
                       for s, e, lbl in idx.ranges],
            "bytes_scanned": idx.bytes_scanned,
            "terminators": idx.terminators,
            "decode_attempts": idx.decode_attempts,
            "scan_s": idx.scan_s,
            "gadgets_indexed": len(idx.gadgets),
            "truncated": idx.truncated,
            "cached": cached,
        }
        if idx.truncated:
            extras["hint"] = ("scan budget exhausted — raise scan_budget "
                              "or narrow the source (module= / "
                              "address=+size=)")
        if salvage:
            extras["salvage"] = salvage
        return _jh(_list_envelope(rows, kind="gadgets", extras=extras,
                                  default_limit=100, **list_kw))

    # gadget_check / chain_check — private Unicorn validation.
    from ...analysis import rop_emu as _remu

    try:
        if action == "gadget_check":
            va = _coerce_va(target)
            out = _remu.validate_gadget(view, va)
        else:
            qwords = _parse_chain(chain)
            expected = _parse_expected(expected_json)
            out = _remu.validate_chain(view, qwords, expected=expected)
    except ValueError as exc:
        return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
    except Exception as exc:
        return _codegen_extra_err(exc)
    return _jh(out)
