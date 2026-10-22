"""Pattern-scan primitives: byte search with mask, chunked range scanner
that salvages partial-page reads, and the IDA-style mask parser."""

from __future__ import annotations

from .reader import SuspexError


# ------------------------------------------------------------ coverage map ----
# v0.22 Phase 3: a physical/kernel sweep needs to say *which* ranges were
# read vs skipped, not just how many bytes. The scanner records the raw
# (start, end) interval of every read/skip; _coverage_map coalesces them
# and computes the unscanned complement inside the caller's range.

_COVERAGE_CAP = 512


def _coalesce(ranges: list[tuple[int, int]]) -> list[list[int]]:
    """Merge overlapping/adjacent (start, end) pairs into sorted spans."""
    out: list[list[int]] = []
    for s, e in sorted(ranges):
        if e <= s:
            continue
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def _coverage_map(scanned: list[tuple[int, int]],
                  skipped: list[tuple[int, int]],
                  lo: int, hi: int,
                  cap: int = _COVERAGE_CAP) -> dict:
    """Coverage envelope: merged scanned/skipped spans plus the
    ``unscanned`` complement inside [lo, hi).

    The union of the three lists partitions the caller's range — a hole
    that never produced a read OR a skip (e.g. the tail past a
    max_results early-stop) lands in ``unscanned`` so callers can tell
    'unreadable' apart from 'never reached'.
    """
    sc = _coalesce(scanned)
    sk = _coalesce(skipped)
    covered = _coalesce([tuple(r) for r in sc] + [tuple(r) for r in sk])
    unscanned: list[list[int]] = []
    cur = lo
    for s, e in covered:
        if s > cur:
            unscanned.append([cur, min(s, hi)])
        cur = max(cur, e)
    if cur < hi:
        unscanned.append([cur, hi])

    def _fmt(rs: list[list[int]]) -> list[dict]:
        return [{"start": hex(s), "end": hex(e)} for s, e in rs[:cap]]

    return {
        "scanned": _fmt(sc),
        "skipped": _fmt(sk),
        "unscanned": _fmt(unscanned),
        "scanned_ranges": len(sc),
        "skipped_ranges": len(sk),
        "unscanned_ranges": len(unscanned),
        "truncated": max(len(sc), len(sk), len(unscanned)) > cap,
    }


def merge_coverage(dicts: list[dict]) -> dict:
    """Merge several ``_coverage_map`` outputs (multi-span scans).

    ``unscanned`` is dropped — the gaps between caller-requested spans
    aren't 'unscanned', they're out of scope; callers needing it read the
    per-span maps instead."""
    scanned: list[tuple[int, int]] = []
    skipped: list[tuple[int, int]] = []
    truncated = False
    for d in dicts:
        if not isinstance(d, dict):
            continue
        for r in d.get("scanned") or []:
            scanned.append((int(str(r["start"]), 16),
                            int(str(r["end"]), 16)))
        for r in d.get("skipped") or []:
            skipped.append((int(str(r["start"]), 16),
                            int(str(r["end"]), 16)))
        truncated = truncated or bool(d.get("truncated"))
    sc = _coalesce(scanned)
    sk = _coalesce(skipped)

    def _fmt(rs: list[list[int]]) -> list[dict]:
        return [{"start": hex(s), "end": hex(e)} for s, e in rs[:_COVERAGE_CAP]]

    return {
        "scanned": _fmt(sc), "skipped": _fmt(sk),
        "scanned_ranges": len(sc), "skipped_ranges": len(sk),
        "truncated": truncated or max(len(sc), len(sk)) > _COVERAGE_CAP,
        "merged_spans": len(dicts),
    }


# ----------------------------------------------------------- pattern scan ----

async def _scan_range_impl(view, pid: int, address: int, size: int,
                           pattern: bytes | str, mask: str, space: str,
                           chunk: int, max_results: int):
    """Chunked pattern scan across a VA range.

    Skips unreadable chunks (unmapped/PTE-gap) so a hole doesn't abort
    the sweep, but counts them so callers can distinguish
    'nothing was readable' from 'no hits'.

    Returns (hits, telemetry) where telemetry is
    {start, end, chunk_size, chunks_read, chunks_skipped, bytes_scanned,
    bytes_skipped, truncated}.
    """
    if isinstance(pattern, str):
        pattern = bytes.fromhex(pattern)
    hits: list[int] = []
    end = address + size
    overlap = max(0, len(pattern) - 1)
    cursor = address
    scanned_to = address
    chunks_read = 0
    chunks_skipped = 0
    bytes_scanned = 0
    bytes_skipped = 0
    truncated = False
    partial_chunks = 0
    partial_bytes = 0
    scanned_ranges: list[tuple[int, int]] = []
    skipped_ranges: list[tuple[int, int]] = []
    while cursor < end and len(hits) < max_results:
        n = min(chunk, end - cursor)
        data = None
        try:
            data = await view.read(pid, cursor, n, space)
        except Exception:
            # v0.9 per-page salvage: MmCopyMemory refuses the WHOLE
            # chunk on the first unmapped page (STATUS_INVALID_ADDRESS),
            # which used to leak the valid prefix into chunks_skipped.
            # Retry a page at a time; consume the valid prefix; stop at
            # the first bad page and let the outer loop step over the
            # unmapped region. Net win on nonpaged-pool sweeps: seconds
            # per GiB instead of minutes.
            prefix = bytearray()
            page = cursor
            page_end = cursor + n
            while page < page_end:
                take = min(0x1000 - (page & 0xFFF), page_end - page)
                try:
                    p = await view.read(pid, page, take, space)
                except Exception:
                    break
                if not p:
                    break
                prefix += p
                page += len(p)
                if len(p) < take:
                    break  # short read: driver ran out of readable bytes
            if prefix:
                data = bytes(prefix)
                partial_chunks += 1
                partial_bytes += len(data)
            else:
                # entire chunk unreadable — advance one page and record
                next_page = (cursor + 0xFFF) & ~0xFFF
                adv = (next_page - cursor) if next_page > cursor else 0x1000
                chunks_skipped += 1
                bytes_skipped += adv
                skipped_ranges.append((cursor, min(cursor + adv, end)))
                cursor += adv
                scanned_to = min(cursor, end)
                continue
        if not data:
            break
        chunks_read += 1
        bytes_scanned += len(data)
        scanned_ranges.append((cursor, min(cursor + len(data), end)))
        for off in pattern_scan(data, pattern, mask):
            addr = cursor + off
            if addr >= scanned_to:
                hits.append(addr)
                if len(hits) >= max_results:
                    truncated = True
                    break
        # Advance by however many bytes we actually got — if it was a
        # partial read, the "hole" starts at cursor+len(data), and the
        # next outer-loop iteration will hit the same failing page and
        # take the per-page-skip branch.
        got = len(data)
        scanned_to = cursor + got
        if cursor + got >= end:
            break
        cursor = cursor + got - overlap if got > overlap else cursor + got
        if got < n and got == (n - overlap if got > overlap else got):
            # A partial that stopped exactly at the caller's chunk edge:
            # progress-normally.
            pass
    telem = {
        "start": hex(address), "end": hex(end),
        "chunk_size": chunk, "chunks_read": chunks_read,
        "chunks_skipped": chunks_skipped, "bytes_scanned": bytes_scanned,
        "bytes_skipped": bytes_skipped,
        # New: per-chunk salvage counters. `partial_chunks` counts chunks
        # where the initial full-chunk read failed but the per-page
        # retry salvaged some bytes; `partial_bytes` is the total
        # rescued that would otherwise have been dropped.
        "partial_chunks": partial_chunks,
        "partial_bytes": partial_bytes,
        "truncated": truncated,
        # v0.22 Phase 3: scanned-vs-skipped-vs-unscanned span map.
        "coverage": _coverage_map(scanned_ranges, skipped_ranges,
                                  address, end),
    }
    return hits, telem


async def scan_range_with_stats(client, pid: int, address: int, size: int,
                                pattern: bytes | str, mask: str, space: str,
                                chunk: int = 0x100000, max_results: int = 64):
    """Client-facing wrapper: uses an AgentClient (mem_read) as the reader.

    The MCP `pattern_scan` action calls this with the session's client so
    that skipped-chunk telemetry surfaces in the tool response.
    """
    class _AdapterView:
        async def read(self, pid, addr, n, space):
            return await client.mem_read(pid, addr, n, space)
    return await _scan_range_impl(_AdapterView(), pid, address, size,
                                  pattern, mask, space, chunk, max_results)


def pattern_scan(data: bytes, pattern: bytes, mask: str = "") -> list[int]:
    """Offsets of pattern in data. mask: one char per pattern byte —
    '?' = wildcard byte, 'H' = high nibble must match (low wild), 'L' =
    low nibble must match (high wild), anything else = exact byte.
    parse_mask emits H/L for '6?'/'?F' tokens, with the fixed nibble
    stored in the pattern byte."""
    if not pattern:
        return []
    if mask and len(mask) != len(pattern):
        raise SuspexError("mask length must equal pattern length")
    if not mask or not any(c in "?HL" for c in mask):
        hits: list[int] = []
        start = 0
        while True:
            i = data.find(pattern, start)
            if i < 0:
                return hits
            hits.append(i)
            start = i + 1
    hits = []
    span = len(data) - len(pattern) + 1
    for i in range(span):
        for j, byte in enumerate(pattern):
            m = mask[j]
            if m == "?":
                continue
            if m == "H":
                if (data[i + j] & 0xF0) != byte:
                    break
            elif m == "L":
                if (data[i + j] & 0x0F) != byte:
                    break
            elif data[i + j] != byte:
                break
        else:
            hits.append(i)
    return hits


async def agent_pattern_scan(client, pid: int, pattern: bytes,
                             mask: str, base: int, size: int,
                             max_results: int, space: str) -> list[int]:
    """Agent-side whole-space scan that honors 'H'/'L' nibble masks.

    The wire mask is byte-granular — the agent (and the driver's pool
    matcher) only knows '?' vs exact — so nibble positions are
    downgraded to '?' for the RPC and each returned candidate is
    re-read through mem_read + verified client-side. Over-fetches
    candidates (cap 4x max_results, bounded) rather than under-report:
    a nibble hit set is a strict subset of the byte-level '?' hit set.
    Works unchanged on current and older agents.
    """
    if not any(m in "HL" for m in mask):
        return await client.mem_scan(pid, pattern, mask, base, size,
                                     max_results, space)
    wire_mask = "".join("?" if m in "HL" else m for m in mask)
    cand_cap = min(max(max_results * 4, 64), 1024)
    cands = await client.mem_scan(pid, pattern, wire_mask, base, size,
                                  cand_cap, space)
    hits: list[int] = []
    for a in cands:
        try:
            buf = await client.mem_read(pid, a, len(pattern), space)
        except Exception:
            continue
        if len(buf) == len(pattern) and pattern_scan(buf, pattern, mask):
            hits.append(a)
            if len(hits) >= max_results:
                break
    return hits


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def parse_mask(pattern: str) -> tuple[bytes, str]:
    """IDA-style '4D 5A ?? 00' string -> (bytes, mask).

    Nibble wildcards too: '6?' pins the high nibble, '?F' the low — the
    pattern byte carries the fixed nibble and the mask char is 'H'/'L'
    so matchers can tell nibble-exact from byte-exact."""
    out = bytearray()
    mask = []
    for tok in pattern.split():
        if tok in ("??", "?"):
            out.append(0)
            mask.append("?")
        elif len(tok) == 2 and tok[1] == "?" and tok[0] in _HEX_DIGITS:
            out.append(int(tok[0], 16) << 4)
            mask.append("H")
        elif len(tok) == 2 and tok[0] == "?" and tok[1] in _HEX_DIGITS:
            out.append(int(tok[1], 16))
            mask.append("L")
        else:
            try:
                v = int(tok, 16)
            except ValueError:
                raise SuspexError(
                    f"bad pattern token {tok!r} — tokens are hex bytes, "
                    "'?'/'??', or nibble wildcards like '6?'/'?F'"
                ) from None
            if v > 0xFF:
                raise SuspexError(
                    f"pattern token {tok!r} is over a byte (0x{v:x}); "
                    "tokens are hex bytes separated by spaces")
            out.append(v)
            mask.append("x")
    return bytes(out), "".join(mask)
