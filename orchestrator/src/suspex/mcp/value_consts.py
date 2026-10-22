"""Named-constant registry for `value_manage`.

Windows-x64-specific values consumed by two consumers:
  * `value_manage(action="eval")` name resolution (fallback after `env`)
  * `value_manage(action="constants")` enumeration

Every entry is a plain int (Python ints are arbitrary precision, so
`MAXULONG64` fits without shenanigans). Values pinned to Windows 10/11 on
x86_64; ARM64 buckets deferred until the lab spins up an ARM64 target.
"""

from __future__ import annotations

from typing import TypedDict


class ConstEntry(TypedDict):
    name: str
    value: int
    category: str  # one of the seven CATEGORY_SLUGS below
    note: str


# Category slugs — kept in a set for O(1) validation; the tests assert
# every entry.category is one of these.
CATEGORY_SLUGS: frozenset[str] = frozenset({
    "memory", "kernel_va", "user_va", "masks", "errno", "units", "nt_status",
})


# CONST_ENTRIES: ordered for stable enumeration; grouped by category.
CONST_ENTRIES: list[ConstEntry] = [
    # -- memory ------------------------------------------------------------
    {"name": "PAGE_SIZE", "value": 0x1000, "category": "memory",
     "note": "x86_64 4 KiB base page"},
    {"name": "LARGE_PAGE_SIZE", "value": 0x200000, "category": "memory",
     "note": "x86_64 2 MiB large page"},
    {"name": "HUGE_PAGE_SIZE", "value": 0x40000000, "category": "memory",
     "note": "1 GiB huge page (PDPT entry)"},
    {"name": "PAGE_SHIFT", "value": 12, "category": "memory",
     "note": "log2(PAGE_SIZE); shift for VA -> page number"},
    {"name": "LARGE_PAGE_SHIFT", "value": 21, "category": "memory",
     "note": "log2(LARGE_PAGE_SIZE)"},
    {"name": "ALLOCATION_GRANULARITY", "value": 0x10000, "category": "memory",
     "note": "VirtualAlloc rounding (64 KiB)"},
    {"name": "CACHE_LINE", "value": 0x40, "category": "memory",
     "note": "x86_64 cache line (64 bytes)"},
    {"name": "MMU_LEVELS", "value": 4, "category": "memory",
     "note": "x86_64 4-level paging default (PML4/PDPT/PD/PT)"},
    {"name": "PTE_ENTRIES", "value": 512, "category": "memory",
     "note": "PTEs per page table (4 KiB / 8 bytes)"},
    {"name": "PTE_ENTRY_SIZE", "value": 8, "category": "memory",
     "note": "bytes per PTE on x86_64"},

    # -- kernel_va ---------------------------------------------------------
    {"name": "KUSER_SHARED_DATA_KERNEL", "value": 0xFFFFF78000000000,
     "category": "kernel_va",
     "note": "read-only shared page (kernel side)"},
    {"name": "KERNEL_HALF_START", "value": 0xFFFF800000000000,
     "category": "kernel_va",
     "note": "non-canonical -> canonical boundary (top half start)"},
    {"name": "KERNEL_LOWEST_VA", "value": 0xFFFF800000000000,
     "category": "kernel_va",
     "note": "lowest canonical kernel VA"},
    {"name": "KERNEL_HIGHEST_VA", "value": 0xFFFFFFFFFFFFFFFF,
     "category": "kernel_va",
     "note": "highest canonical kernel VA"},
    {"name": "SESSION_SPACE_START", "value": 0xFFFFF90000000000,
     "category": "kernel_va",
     "note": "session space (approximate; VA layout is randomized)"},
    {"name": "PAGED_POOL_START", "value": 0xFFFFCA0000000000,
     "category": "kernel_va",
     "note": "paged pool base (approximate; ASLR)"},
    {"name": "NONPAGED_POOL_START", "value": 0xFFFFCC0000000000,
     "category": "kernel_va",
     "note": "nonpaged pool base (approximate; ASLR)"},

    # -- user_va -----------------------------------------------------------
    {"name": "KUSER_SHARED_DATA_USER", "value": 0x7FFE0000,
     "category": "user_va",
     "note": "read-only shared page (user side)"},
    {"name": "USER_LOWEST_VA", "value": 0x10000, "category": "user_va",
     "note": "first mappable user address"},
    {"name": "USER_HIGHEST_VA", "value": 0x00007FFFFFFEFFFF,
     "category": "user_va",
     "note": "last user address (per SetProcessDEPPolicy view)"},
    {"name": "TEB_SIZE_APPROX", "value": 0x1800, "category": "user_va",
     "note": "approximate TEB size on Win10 x64 (real size varies)"},

    # -- masks -------------------------------------------------------------
    {"name": "MAXUCHAR", "value": 0xFF, "category": "masks",
     "note": "max unsigned 8-bit"},
    {"name": "MAXUSHORT", "value": 0xFFFF, "category": "masks",
     "note": "max unsigned 16-bit"},
    {"name": "MAXULONG", "value": 0xFFFFFFFF, "category": "masks",
     "note": "max unsigned 32-bit"},
    {"name": "MAXULONG64", "value": 0xFFFFFFFFFFFFFFFF, "category": "masks",
     "note": "max unsigned 64-bit"},
    {"name": "MAXCHAR", "value": 0x7F, "category": "masks",
     "note": "max signed 8-bit"},
    {"name": "MAXSHORT", "value": 0x7FFF, "category": "masks",
     "note": "max signed 16-bit"},
    {"name": "MAXLONG", "value": 0x7FFFFFFF, "category": "masks",
     "note": "max signed 32-bit"},
    {"name": "MAXLONG64", "value": 0x7FFFFFFFFFFFFFFF, "category": "masks",
     "note": "max signed 64-bit"},
    {"name": "SIGN_BIT_8", "value": 0x80, "category": "masks",
     "note": "sign bit for 8-bit signed"},
    {"name": "SIGN_BIT_16", "value": 0x8000, "category": "masks",
     "note": "sign bit for 16-bit signed"},
    {"name": "SIGN_BIT_32", "value": 0x80000000, "category": "masks",
     "note": "sign bit for 32-bit signed"},
    {"name": "SIGN_BIT_64", "value": 0x8000000000000000, "category": "masks",
     "note": "sign bit for 64-bit signed"},
    {"name": "LOW_NIBBLE", "value": 0xF, "category": "masks",
     "note": "low 4 bits of a byte"},
    {"name": "HIGH_NIBBLE", "value": 0xF0, "category": "masks",
     "note": "high 4 bits of a byte"},
    {"name": "CANONICAL_MASK", "value": 0x0000FFFFFFFFFFFF, "category": "masks",
     "note": "48-bit canonical VA mask (low 48 bits)"},
    {"name": "NONCANONICAL_HOLE_LOW", "value": 0x0000800000000000,
     "category": "masks",
     "note": "first non-canonical address after user half"},
    {"name": "NONCANONICAL_HOLE_HIGH", "value": 0xFFFF7FFFFFFFFFFF,
     "category": "masks",
     "note": "last non-canonical address before kernel half"},

    # -- errno (a load-bearing few; err_lookup handles the full table) -----
    {"name": "ERROR_SUCCESS", "value": 0, "category": "errno",
     "note": "operation succeeded"},
    {"name": "ERROR_ACCESS_DENIED", "value": 5, "category": "errno",
     "note": "access is denied"},
    {"name": "ERROR_INVALID_HANDLE", "value": 6, "category": "errno",
     "note": "the handle is invalid"},
    {"name": "ERROR_INVALID_PARAMETER", "value": 87, "category": "errno",
     "note": "the parameter is incorrect"},

    # -- units (byte / count / time multipliers) ---------------------------
    {"name": "KB", "value": 1024, "category": "units",
     "note": "kilobyte (1024 bytes; SI-ambiguous, matches KiB here)"},
    {"name": "MB", "value": 1 << 20, "category": "units",
     "note": "megabyte (2^20 bytes)"},
    {"name": "GB", "value": 1 << 30, "category": "units",
     "note": "gigabyte (2^30 bytes)"},
    {"name": "TB", "value": 1 << 40, "category": "units",
     "note": "terabyte (2^40 bytes)"},
    {"name": "KIB", "value": 1024, "category": "units",
     "note": "kibibyte (2^10 bytes)"},
    {"name": "MIB", "value": 1 << 20, "category": "units",
     "note": "mebibyte (2^20 bytes)"},
    {"name": "GIB", "value": 1 << 30, "category": "units",
     "note": "gibibyte (2^30 bytes)"},
    {"name": "TIB", "value": 1 << 40, "category": "units",
     "note": "tebibyte (2^40 bytes)"},
    {"name": "US", "value": 1, "category": "units",
     "note": "microsecond (base unit for time helpers)"},
    {"name": "MS", "value": 1000, "category": "units",
     "note": "millisecond (in microseconds)"},
    {"name": "SEC", "value": 1000000, "category": "units",
     "note": "second (in microseconds)"},
    {"name": "FILETIME_TICK_NS", "value": 100, "category": "units",
     "note": "100ns per FILETIME tick"},

    # -- nt_status (severity constants; err_lookup covers per-code lookup) -
    {"name": "STATUS_SEVERITY_SUCCESS", "value": 0x0, "category": "nt_status",
     "note": "NTSTATUS severity: success"},
    {"name": "STATUS_SEVERITY_INFORMATIONAL", "value": 0x1,
     "category": "nt_status",
     "note": "NTSTATUS severity: informational"},
    {"name": "STATUS_SEVERITY_WARNING", "value": 0x2, "category": "nt_status",
     "note": "NTSTATUS severity: warning"},
    {"name": "STATUS_SEVERITY_ERROR", "value": 0x3, "category": "nt_status",
     "note": "NTSTATUS severity: error"},
    {"name": "NT_SEVERITY_MASK", "value": 0xC0000000, "category": "nt_status",
     "note": "top nibble gating NTSTATUS severity"},
    {"name": "NT_CUSTOMER_MASK", "value": 0x20000000, "category": "nt_status",
     "note": "customer-defined bit in NTSTATUS"},
    {"name": "NT_FACILITY_MASK", "value": 0x0FFF0000, "category": "nt_status",
     "note": "facility field of NTSTATUS"},
    {"name": "NT_CODE_MASK", "value": 0x0000FFFF, "category": "nt_status",
     "note": "code field of NTSTATUS"},
]


# Derived views — module-level dicts so lookups are O(1).
CONSTANTS: dict[str, int] = {e["name"]: e["value"] for e in CONST_ENTRIES}


def _build_categories() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {slug: [] for slug in CATEGORY_SLUGS}
    for e in CONST_ENTRIES:
        out[e["category"]].append(e["name"])
    return out


CATEGORIES: dict[str, list[str]] = _build_categories()
