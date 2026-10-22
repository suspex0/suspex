"""Hex-string normalization for tool responses.

Every address/size field in every *_manage tool response is rendered as a
'0x...' string plus a mirrored `_int` key for callers that want to compute.
Fixes the developer feedback pain point where `mem_rw modules` returned
`base: "18446735308801310720"` and every caller had to convert.

Applied as `_j(hexify_dict(response))` at the return point of every tool
dispatch that touches driver-side data. Pure Python; safe to call on any
JSON-serializable object.
"""
from __future__ import annotations

from typing import Any, Iterable

# Field names that MUST be rendered as hex '0x...' strings across every tool
# response. If a field name here appears in a dict, it's an address-like
# value; otherwise leave it alone.
#
# Rule of thumb: kernel addresses, VAs, PAs, register values, handles, and
# QPC-microsecond timestamps (they're conceptually addresses on the time
# axis and easier to eyeball as hex).
HEX_ADDRESS_KEYS: frozenset[str] = frozenset({
    # Memory / VA / PA
    "base", "va", "address", "addr",
    "start", "end", "start_va", "end_va", "source_va",
    "handle", "object", "handle_value",
    "pa", "physical_address",
    # Image-relative offsets (symbols_manage resolve/lookup) — v0.24:
    # bare-decimal RVAs caused a 15-min mis-read of kernel addresses.
    "rva", "symbol_rva",
    # IDA / dispatcher work
    "dispatcher_ea", "ea",
    # Watchdog timestamps (QPC-us; hex reads cleaner)
    "last_kick_us", "deadline_us", "armed_us", "now_us",
    "t_start_us", "t_end_us", "latency_us",
    "cookie",
    # Registers (context ops surface these)
    "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
    "cr0", "cr2", "cr3", "cr4",
    "fs_base", "gs_base", "gs_base_low",
    "rflags", "cs", "ss", "ds", "es",
    # BP / IOCTL
    "orig_byte", "matched_offset", "first_bad_offset",
})

# Field names representing byte-length sizes. Kept separately because size
# semantics differ (usually decimal is fine, but hex is friendlier for
# power-of-two allocations, VAD extents, and pool blocks).
HEX_SIZE_KEYS: frozenset[str] = frozenset({
    "size", "size_in_bytes", "committed", "reserved", "reserved_size",
    "commit_charge", "file_size", "region_size",
    "read_bytes", "written_bytes", "bytes_written", "bytes_returned",
    "total_size", "tail_offset", "rotated_size",
    "stdout_size", "stderr_size", "stdout_total", "stderr_total",
})

# Field names that should NEVER be hexified even if they look like ints in
# the address key list (e.g. `size` inside a nested `hint` dict).
HEX_KEY_EXCLUSIONS: frozenset[str] = frozenset({
    "hint", "note", "error", "summary", "description", "reason",
})

_ALL_HEX_KEYS: frozenset[str] = HEX_ADDRESS_KEYS | HEX_SIZE_KEYS


def hexify(v: Any) -> str:
    """Coerce an int (or already-hex string) to a canonical '0x...' string.

    * `0x1234ABCD` (any case) → `'0x1234abcd'`
    * `291`                   → `'0x123'`
    * `-1`                    → `'-0x1'`  (negative preserved; unusual but honest)
    * anything else           → returned as-is
    """
    if isinstance(v, bool):
        # Python bool is int; guard so True doesn't render as 0x1.
        return v
    if isinstance(v, int):
        return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return v
        # Accept decimal integer strings — the exact case that bit the
        # developer: mem_rw modules returned `base: "18446735308801310720"`.
        try:
            n = int(s, 0) if (s.startswith(("0x", "0X", "-0x", "-0X")) or s.isdigit()
                              or (s.startswith("-") and s[1:].isdigit())) else None
        except ValueError:
            n = None
        if n is not None:
            return f"-0x{-n:x}" if n < 0 else f"0x{n:x}"
        return v
    return v


def _looks_hex(v: Any) -> bool:
    """True if `v` is an int or a numeric-looking string we can hexify."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return False
    if s.startswith(("0x", "0X", "-0x", "-0X")):
        return True
    if s.isdigit():
        return True
    if s.startswith("-") and s[1:].isdigit():
        return True
    return False


def hexify_dict(
    obj: Any,
    addr_keys: Iterable[str] = HEX_ADDRESS_KEYS,
    size_keys: Iterable[str] = HEX_SIZE_KEYS,
    add_int_mirror: bool = True,
) -> Any:
    """Walk `obj` and hex-normalize every value whose key is in the hex key sets.

    * dicts recurse
    * lists recurse
    * scalars pass through
    * for each hexified value, if `add_int_mirror` is on, add a `<key>_int`
      sibling holding the decimal int form so callers who want to compute
      don't have to re-parse

    Fields whose key is in `HEX_KEY_EXCLUSIONS` are left alone (a nested
    `hint: "size 4096..."` string mustn't be scanned for hex values).
    """
    if isinstance(obj, dict):
        # Materialize keys first — we may add `_int` mirrors while iterating.
        items = list(obj.items())
        out: dict[str, Any] = {}
        keys = set(addr_keys) | set(size_keys)
        for k, v in items:
            if k in HEX_KEY_EXCLUSIONS:
                out[k] = v
                continue
            if k in keys and _looks_hex(v):
                hex_str = hexify(v)
                out[k] = hex_str
                if add_int_mirror:
                    try:
                        out[f"{k}_int"] = int(hex_str, 0)
                    except (ValueError, TypeError):
                        pass
            else:
                out[k] = hexify_dict(v, addr_keys, size_keys, add_int_mirror)
        return out
    if isinstance(obj, list):
        return [hexify_dict(x, addr_keys, size_keys, add_int_mirror) for x in obj]
    return obj
