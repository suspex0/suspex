"""Byte-pattern + qword scans across IDB segments.

``_parse_hex_pattern`` / ``_scan_masked`` are the pure helpers pulled out
so pytest can exercise them without a live IDA. ``pattern_scan`` /
``qword_value_scan`` reach into ``ida_bytes`` / ``ida_funcs`` /
``ida_segment`` at call time.
"""
from __future__ import annotations

from typing import Annotated

from .funcs import _to_ea, hex_ea


def _parse_hex_pattern(spec: str) -> tuple[bytes, bytes]:
    """Split a hex pattern into (pattern_bytes, mask_bytes).

    Accepts space- or comma-separated tokens; ``??`` / ``?`` are
    wildcards (mask byte 0x00). Every other token must be a 1-byte
    hex value.

        '4C 8D 05 ?? ?? ?? ?? 48 89'
            -> (b'\\x4c\\x8d\\x05\\x00\\x00\\x00\\x00\\x48\\x89',
                b'\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\xff\\xff')

    Returns ``(b"", b"")`` on any parse failure so callers can emit
    one uniform ``invalid_parameter`` error.
    """
    tokens = spec.replace(",", " ").split()
    if not tokens:
        return b"", b""
    pat = bytearray()
    mask = bytearray()
    for tok in tokens:
        t = tok.strip()
        if t in ("??", "?"):
            pat.append(0)
            mask.append(0)
            continue
        # Accept a bare hex byte (``4C``) or the ``0x`` variant.
        if t.lower().startswith("0x"):
            t = t[2:]
        if len(t) != 2:
            return b"", b""
        try:
            pat.append(int(t, 16))
            mask.append(0xFF)
        except ValueError:
            return b"", b""
    return bytes(pat), bytes(mask)


def _scan_masked(hay: bytes, pat: bytes, mask: bytes, cap: int):
    """Yield match offsets within ``hay`` for the (pat, mask) tuple.

    Naive masked search — O(n*k) — which is fine for the 6-16 byte
    signatures the analyst pipeline typically hunts and remains
    survivable on a 100 MB .text (~1-3 s in CPython).
    """
    if not pat:
        return
    n, k = len(hay), len(pat)
    if k > n:
        return
    yielded = 0
    for i in range(n - k + 1):
        ok = True
        for j in range(k):
            if mask[j] and hay[i + j] != pat[j]:
                ok = False
                break
        if ok:
            yield i
            yielded += 1
            if yielded >= cap:
                return


def pattern_scan(
    hex: Annotated[str, "Byte pattern; '??' bytes are wildcards. Example: '4C 8D 05 ?? ?? ?? ?? 48 89'"],
    seg: Annotated[str, "Segment name to search ('.text', '.rdata'). Empty = every segment."] = "",
    limit: Annotated[int, "Stop after N matches. 0 or negative = 128 (safety cap)."] = 128,
    start_ea: Annotated[str, "Optional start ea (hex '0x...' or int); overrides seg when both are given."] = "",
    end_ea: Annotated[str, "Optional end ea; required alongside start_ea."] = "",
) -> dict:
    """Byte-pattern scan across a segment (or the whole IDB).

    Returns ``{ok, count, truncated, matches:[{ea, function, function_name}]}``.
    Wildcards use ``??`` per byte. Uses a hand-rolled masked search
    instead of ``ida_bytes.bin_search`` so it isn't wobbled by the
    SWIG overload TypeError seen on IDA >= 9.0. Skips unloaded
    regions silently (``get_bytes`` returns ``None`` there).
    """
    import ida_bytes
    import ida_funcs
    import ida_segment

    pat, mask = _parse_hex_pattern(hex)
    if not pat:
        return {
            "ok": False,
            "kind": "invalid_parameter",
            "error": f"bad pattern {hex!r}",
            "hint": "space-separated 1-byte hex tokens; '??' for wildcards",
        }

    ranges: list[tuple[int, int]] = []
    if start_ea and end_ea:
        try:
            lo = _to_ea(start_ea)
            hi = _to_ea(end_ea)
        except ValueError as exc:
            return {"ok": False, "kind": "invalid_parameter",
                    "error": f"bad ea: {exc}"}
        if hi <= lo:
            return {"ok": False, "kind": "invalid_parameter",
                    "error": f"end_ea {end_ea!r} must be > start_ea {start_ea!r}"}
        ranges.append((lo, hi))
    elif seg:
        s = ida_segment.get_segm_by_name(seg)
        if not s:
            return {"ok": False, "kind": "invalid_parameter",
                    "error": f"segment {seg!r} not found in the IDB",
                    "hint": "call get_segments to enumerate loaded segments"}
        ranges.append((s.start_ea, s.end_ea))
    else:
        # Whole IDB — every loaded segment. ``get_segm_qty`` +
        # ``getnseg(i)`` is stable across IDA 7/8/9.
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if s is not None:
                ranges.append((s.start_ea, s.end_ea))

    cap = int(limit) if int(limit) > 0 else 128
    hits: list[dict] = []
    truncated = False
    for lo, hi in ranges:
        if len(hits) >= cap:
            truncated = True
            break
        buf = ida_bytes.get_bytes(lo, hi - lo)
        # ``get_bytes`` returns None (or an empty bytes) across unmapped
        # ranges — skip so a single bad segment does not tank the scan.
        if not buf:
            continue
        for m in _scan_masked(buf, pat, mask, cap - len(hits)):
            ea = lo + m
            fn = ida_funcs.get_func(ea)
            hits.append({
                "ea": hex_ea(ea),
                "function": hex_ea(fn.start_ea) if fn else None,
                "function_name": (ida_funcs.get_func_name(fn.start_ea)
                                  if fn else ""),
            })
            if len(hits) >= cap:
                truncated = True
                break
    return {
        "ok": True,
        "count": len(hits),
        "truncated": truncated,
        "pattern_bytes": len(pat),
        "matches": hits,
    }


def qword_value_scan(
    value: Annotated[str, "u64 to search for (hex '0x...' or decimal). Encoded little-endian."],
    seg: Annotated[str, "Segment name to search; empty = every segment."] = "",
    limit: Annotated[int, "Max hits (default 128)."] = 128,
) -> dict:
    """Scan the IDB for QWORDs whose little-endian value equals ``value``.

    Convenience wrapper over ``pattern_scan`` — turns a raw u64 into
    an 8-byte hex pattern and reuses the same scan machinery. Useful
    for locating vtable slots, encoded pointers, and constant tables
    that reference a known kernel address.
    """
    try:
        v = _to_ea(value)
    except ValueError as exc:
        return {"ok": False, "kind": "invalid_parameter",
                "error": f"bad value: {exc}"}
    if v < 0 or v > 0xFFFFFFFFFFFFFFFF:
        return {"ok": False, "kind": "invalid_parameter",
                "error": f"value {value!r} does not fit in a u64"}
    hex_str = " ".join(f"{(v >> (8 * i)) & 0xFF:02X}" for i in range(8))
    return pattern_scan(hex_str, seg=seg, limit=limit)
