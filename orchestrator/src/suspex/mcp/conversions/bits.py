"""Bitfield decoders and error-code lookup."""

from __future__ import annotations

from typing import Any

from ..error_maps import lookup as _err_lookup
from .errors import ConversionError
from .ints import parse_int

# ---------------------------------------------------------------------------
# Bits / presets
# ---------------------------------------------------------------------------

BIT_PRESETS: dict[str, dict[int, str]] = {
    "page_protect": {
        0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
        0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE",
        0x20: "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE",
        0x80: "PAGE_EXECUTE_WRITECOPY", 0x100: "PAGE_GUARD",
        0x200: "PAGE_NOCACHE", 0x400: "PAGE_WRITECOMBINE",
        0x40000000: "PAGE_TARGETS_INVALID", 0x40000000: "PAGE_TARGETS_NO_UPDATE",
    },
    "process_access": {
        0x0001: "PROCESS_TERMINATE", 0x0002: "PROCESS_CREATE_THREAD",
        0x0004: "PROCESS_SET_SESSIONID", 0x0008: "PROCESS_VM_OPERATION",
        0x0010: "PROCESS_VM_READ", 0x0020: "PROCESS_VM_WRITE",
        0x0040: "PROCESS_DUP_HANDLE", 0x0080: "PROCESS_CREATE_PROCESS",
        0x0100: "PROCESS_SET_QUOTA", 0x0200: "PROCESS_SET_INFORMATION",
        0x0400: "PROCESS_QUERY_INFORMATION",
        0x0800: "PROCESS_SUSPEND_RESUME",
        0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
        0x2000: "PROCESS_SET_LIMITED_INFORMATION",
        0x00100000: "SYNCHRONIZE", 0x000F0000: "STANDARD_RIGHTS_REQUIRED",
        0x001FFFFF: "PROCESS_ALL_ACCESS",
    },
    "thread_access": {
        0x0001: "THREAD_TERMINATE", 0x0002: "THREAD_SUSPEND_RESUME",
        0x0008: "THREAD_GET_CONTEXT", 0x0010: "THREAD_SET_CONTEXT",
        0x0020: "THREAD_QUERY_INFORMATION", 0x0040: "THREAD_SET_INFORMATION",
        0x0080: "THREAD_SET_THREAD_TOKEN", 0x0100: "THREAD_IMPERSONATE",
        0x0200: "THREAD_DIRECT_IMPERSONATION",
        0x0400: "THREAD_SET_LIMITED_INFORMATION",
        0x0800: "THREAD_QUERY_LIMITED_INFORMATION",
        0x00100000: "SYNCHRONIZE",
    },
    "section_map": {
        0x0001: "SECTION_QUERY", 0x0002: "SECTION_MAP_WRITE",
        0x0004: "SECTION_MAP_READ", 0x0008: "SECTION_MAP_EXECUTE",
        0x0010: "SECTION_EXTEND_SIZE", 0x0020: "SECTION_MAP_EXECUTE_EXPLICIT",
    },
    "eflags": {
        1 << 0: "CF", 1 << 2: "PF", 1 << 4: "AF", 1 << 6: "ZF",
        1 << 7: "SF", 1 << 8: "TF", 1 << 9: "IF", 1 << 10: "DF",
        1 << 11: "OF", 1 << 14: "NT", 1 << 16: "RF", 1 << 17: "VM",
        1 << 18: "AC", 1 << 19: "VIF", 1 << 20: "VIP", 1 << 21: "ID",
    },
    "pe_characteristics": {
        0x0001: "RELOCS_STRIPPED", 0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMS_STRIPPED", 0x0008: "LOCAL_SYMS_STRIPPED",
        0x0010: "AGGRESSIVE_WS_TRIM", 0x0020: "LARGE_ADDRESS_AWARE",
        0x0080: "BYTES_REVERSED_LO", 0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED", 0x0400: "REMOVABLE_RUN_FROM_SWAP",
        0x0800: "NET_RUN_FROM_SWAP", 0x1000: "SYSTEM",
        0x2000: "DLL", 0x4000: "UP_SYSTEM_ONLY",
        0x8000: "BYTES_REVERSED_HI",
    },
    "pe_dll_characteristics": {
        0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE",
        0x0080: "FORCE_INTEGRITY", 0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION", 0x0400: "NO_SEH", 0x0800: "NO_BIND",
        0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE",
    },
    "pe_section_flags": {
        0x00000008: "TYPE_NO_PAD", 0x00000020: "CNT_CODE",
        0x00000040: "CNT_INITIALIZED_DATA", 0x00000080: "CNT_UNINITIALIZED_DATA",
        0x00000100: "LNK_OTHER", 0x00000200: "LNK_INFO", 0x00000800: "LNK_REMOVE",
        0x00001000: "LNK_COMDAT", 0x00008000: "GPREL",
        0x02000000: "MEM_DISCARDABLE", 0x04000000: "MEM_NOT_CACHED",
        0x08000000: "MEM_NOT_PAGED", 0x10000000: "MEM_SHARED",
        0x20000000: "MEM_EXECUTE", 0x40000000: "MEM_READ",
        0x80000000: "MEM_WRITE",
    },
    "virtual_alloc_type": {
        0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x4000: "MEM_DECOMMIT",
        0x8000: "MEM_RELEASE", 0x10000: "MEM_FREE", 0x20000: "MEM_PRIVATE",
        0x40000: "MEM_MAPPED", 0x80000: "MEM_RESET",
        0x100000: "MEM_TOP_DOWN", 0x200000: "MEM_WRITE_WATCH",
        0x400000: "MEM_PHYSICAL", 0x1000000: "MEM_LARGE_PAGES",
    },
}


def decode_bits(value: Any, preset: str = "",
                names: dict[int, str] | None = None) -> dict[str, Any]:
    iv = parse_int(value)
    if preset:
        preset_key = preset.strip().lower()
        if preset_key not in BIT_PRESETS:
            raise ConversionError(
                "unknown_type",
                f"unknown bits preset {preset!r}",
                hint="known presets: " + ", ".join(sorted(BIT_PRESETS)),
            )
        table = BIT_PRESETS[preset_key]
    elif names:
        # Coerce keys to ints (JSON came in as str keys quite possibly).
        table = {parse_int(k): str(v) for k, v in names.items()}
    else:
        raise ConversionError(
            "unparseable_value",
            "bits requires preset= or names_json=",
            hint="pass preset='page_protect' or names_json='{\"0x1\":\"FLAG_A\"}'",
        )
    set_names: list[str] = []
    clear_names: list[str] = []
    seen_mask = 0
    for mask, name in sorted(table.items()):
        if mask == 0:
            continue
        # Composite masks (multi-bit) match when ALL their bits are set.
        if (iv & mask) == mask:
            set_names.append(name)
        else:
            clear_names.append(name)
        seen_mask |= mask
    unknown = iv & ~seen_mask & 0xFFFFFFFFFFFFFFFF
    return {
        "value": iv,
        "hex": f"0x{iv:X}",
        "preset": preset or None,
        "set": set_names,
        "clear": clear_names,
        "unknown_bits_hex": f"0x{unknown:X}" if unknown else "0x0",
        "unknown_bits": unknown,
    }


def lookup_err(value: Any, space: str = "auto") -> dict[str, Any]:
    iv = parse_int(value)
    return _err_lookup(iv, space=space)
