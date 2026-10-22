"""Enum decoders — attach human-readable text next to raw integer fields.

Feedback pain point: `protect: "0x20"`, `vad_type: 2`, pool tags as
uint32 hexes forced the LLM to remember Win32 constant tables. This module
lets tools emit `protect: "0x20", protect_decoded: "PAGE_EXECUTE_READ"`
so the caller reads the meaning inline.

Pure Python, no I/O, safe to call from any thread. Every decoder returns
`"UNKNOWN(0x...)"` for unrecognized values rather than raising.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

# ---------------------------------------------------------------------------
# PAGE_* protection flags (winnt.h). Low byte is the base protection; upper
# bits are modifiers (guard, nocache, writecombine).
# ---------------------------------------------------------------------------

PAGE_PROTECT_BASE: dict[int, str] = {
    0x00: "PAGE_NOACCESS_ZERO",   # not a real value; VirtualAlloc default
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

PAGE_PROTECT_MODIFIERS: list[tuple[int, str]] = [
    (0x100, "PAGE_GUARD"),
    (0x200, "PAGE_NOCACHE"),
    (0x400, "PAGE_WRITECOMBINE"),
    (0x40000000, "PAGE_TARGETS_NO_UPDATE"),
    (0x80000000, "PAGE_TARGETS_INVALID"),
]


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            return int(s, 0) if s.startswith(("0x", "0X")) else int(s, 0)
        except (ValueError, TypeError):
            return None
    return None


def decode_protect(v: Any) -> str:
    """Return 'PAGE_EXECUTE_READ | PAGE_GUARD' style decoded string.

    Handles str/int input, returns 'UNKNOWN(0xN)' when the base value isn't
    in the table.
    """
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    base = PAGE_PROTECT_BASE.get(n & 0xFF)
    if base is None:
        base = f"UNKNOWN(0x{n & 0xFF:x})"
    parts = [base]
    for bit, name in PAGE_PROTECT_MODIFIERS:
        if n & bit:
            parts.append(name)
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# VAD types (from _MMVAD.VadType, mirrored in comm/suspex_abi.h)
# ---------------------------------------------------------------------------

VAD_TYPES: dict[int, str] = {
    0: "VadNone",
    1: "VadDevicePhysicalMemory",
    2: "VadImageMap",
    3: "VadAwe",
    4: "VadWriteWatch",
    5: "VadLargePages",
    6: "VadRotatePhysical",
    7: "VadLargePageSection",
}


def decode_vad_type(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    return VAD_TYPES.get(n, f"UNKNOWN({n})")


# ---------------------------------------------------------------------------
# Service Start type + Service Type (from HKLM\...\Services)
# ---------------------------------------------------------------------------

SERVICE_START: dict[int, str] = {
    0: "SERVICE_BOOT_START",
    1: "SERVICE_SYSTEM_START",
    2: "SERVICE_AUTO_START",
    3: "SERVICE_DEMAND_START",
    4: "SERVICE_DISABLED",
}

SERVICE_TYPE: dict[int, str] = {
    0x001: "SERVICE_KERNEL_DRIVER",
    0x002: "SERVICE_FILE_SYSTEM_DRIVER",
    0x008: "SERVICE_RECOGNIZER_DRIVER",
    0x010: "SERVICE_WIN32_OWN_PROCESS",
    0x020: "SERVICE_WIN32_SHARE_PROCESS",
    0x050: "SERVICE_USER_OWN_PROCESS",
    0x060: "SERVICE_USER_SHARE_PROCESS",
    0x100: "SERVICE_INTERACTIVE_PROCESS",
}


def decode_service_start(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    return SERVICE_START.get(n, f"UNKNOWN({n})")


def decode_service_type(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    base = SERVICE_TYPE.get(n & 0xFF, f"UNKNOWN(0x{n & 0xFF:x})")
    if n & 0x100:
        return f"{base} | SERVICE_INTERACTIVE_PROCESS"
    return base


# ---------------------------------------------------------------------------
# Pool tag: 32-bit tag stored little-endian. Decode to 4 printable ASCII
# chars, or fall back to hex.
# ---------------------------------------------------------------------------

def decode_pool_tag(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    chars = []
    for i in range(4):
        c = (n >> (i * 8)) & 0xFF
        if 0x20 <= c <= 0x7E:
            chars.append(chr(c))
        else:
            return f"0x{n:08x}"     # non-printable, keep hex
    return "".join(chars)


# ---------------------------------------------------------------------------
# GENERIC_ACCESS_RIGHTS + STANDARD_RIGHTS_* on handle GrantedAccess
# ---------------------------------------------------------------------------

ACCESS_MASK_BITS: list[tuple[int, str]] = [
    (0x00000001, "DELETE_MASK"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x02000000, "MAXIMUM_ALLOWED"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]


def decode_granted_access(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    parts = []
    for bit, name in ACCESS_MASK_BITS:
        if n & bit:
            parts.append(name)
    return " | ".join(parts) if parts else f"0x{n:08x}"


# ---------------------------------------------------------------------------
# Memory region State/Type (MEMORY_BASIC_INFORMATION.State / .Type)
# ---------------------------------------------------------------------------

MEM_STATE: dict[int, str] = {
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x10000: "MEM_FREE",
}

MEM_TYPE: dict[int, str] = {
    0x20000: "MEM_PRIVATE",
    0x40000: "MEM_MAPPED",
    0x1000000: "MEM_IMAGE",
}


def decode_mem_state(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    return MEM_STATE.get(n, f"UNKNOWN(0x{n:x})")


def decode_mem_type(v: Any) -> str:
    n = _as_int(v)
    if n is None:
        return f"UNKNOWN({v!r})"
    return MEM_TYPE.get(n, f"UNKNOWN(0x{n:x})")


# ---------------------------------------------------------------------------
# Convenience: attach a `_decoded` sibling to every recognized field in a
# dict tree. Called once per tool response.
# ---------------------------------------------------------------------------

DECODERS: dict[str, Callable] = {
    "protect":         decode_protect,
    "old_protect":     decode_protect,
    "vad_type":        decode_vad_type,
    "start":           decode_service_start,     # only sensible on service dicts
    "type":            decode_service_type,      # only sensible on service dicts
    "tag":             decode_pool_tag,
    "granted_access":  decode_granted_access,
    "state":           decode_mem_state,
    # `type` collision with service_type is unavoidable — caller passes the
    # explicit map when the same key means something different (e.g. VAD_type
    # doesn't overlap because we call `vad_type` there).
}


# Some field names collide with generic Python meanings ("start", "type",
# "state") and only mean the decoded thing in certain contexts. Callers pass
# a `context` hint to disambiguate.
CONTEXT_MAPS: dict[str, dict[str, Callable]] = {
    "service": {
        "start": decode_service_start,
        "type":  decode_service_type,
    },
    "vad": {
        "protect": decode_protect,
        "vad_type": decode_vad_type,
    },
    "handle": {
        "granted_access": decode_granted_access,
    },
    "pool": {
        "tag": decode_pool_tag,
    },
    "region": {
        "protect": decode_protect,
        "state":   decode_mem_state,
        "type":    decode_mem_type,
    },
    "context_regs": {
        # register context — no enum decoding; kept for future thread flag work
    },
}


def attach_decoded(obj: Any, context: str | None = None) -> Any:
    """Walk `obj`; where a key matches a known decoder, add a `<key>_decoded`
    sibling with the human-readable text.

    Prefers `CONTEXT_MAPS[context]` when a context is supplied; falls back to
    `DECODERS` otherwise. Missing keys → no change.
    """
    decoders = CONTEXT_MAPS.get(context, DECODERS) if context else DECODERS
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = attach_decoded(v, context=context)
            fn = decoders.get(k)
            if fn is not None and f"{k}_decoded" not in obj:
                try:
                    out[f"{k}_decoded"] = fn(v)
                except Exception:
                    pass
        return out
    if isinstance(obj, list):
        return [attach_decoded(x, context=context) for x in obj]
    return obj


def attach_decoded_list(entries: Iterable[dict], context: str) -> list[dict]:
    """Convenience: same as attach_decoded but forces the context on each
    dict in a list. Use for tool responses whose payload is a list of rows
    of the same shape."""
    return [attach_decoded(e, context=context) for e in entries]
