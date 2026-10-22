// Kernel big-pool enumeration with optional tag / paged / content filters.
//
// ZwQuerySystemInformation(SystemBigPoolInformation) returns each pool
// allocation larger than one page: {virtual address, size, tag, paged
// flag}. That's the full "big pool" surface — small pool has no
// comparable enumeration on modern Windows (segment heap opacity),
// which we document rather than pretend. The content filter reads a
// window of each entry via MmCopyMemory (kernel VA, non-fault, safe
// against unmapped pages) and pattern-scans.

#include "SuspexDriver.h"

// SystemBigPoolInformation = 0x42 (per public SDK / undocumented lists).
#define SUSPEX_SYS_BIGPOOL_INFO_CLASS 0x42

typedef struct _SUSPEX_SBP_ENTRY {
    PVOID VirtualAddress; // low bit = 1 -> non-paged
    SIZE_T SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    } u;
} SUSPEX_SBP_ENTRY;

typedef struct _SUSPEX_SBP_INFO {
    ULONG Count;
    SUSPEX_SBP_ENTRY AllocatedInfo[1];
} SUSPEX_SBP_INFO;

// Grow the query buffer until ZwQuerySystemInformation stops asking for
// more (STATUS_INFO_LENGTH_MISMATCH). 64 MB hard cap so a compromised
// build cannot balloon paged pool from a single IOCTL.
#define SUSPEX_SBP_MAX_BYTES (64u * 1024 * 1024)

static NTSTATUS SuspxSbpAcquire(_Out_ SUSPEX_SBP_INFO** OutInfo, _Out_ PULONG OutLen)
{
    ULONG len = 0x10000; // 64 KB seed
    SUSPEX_SBP_INFO* buf = NULL;

    *OutInfo = NULL;
    *OutLen = 0;
    for (;;) {
        ULONG needed = 0;
        NTSTATUS st;
        if (buf) {
            SuspxFree(buf);
        }
        buf = (SUSPEX_SBP_INFO*)SuspxAlloc(len);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(SUSPEX_SYS_BIGPOOL_INFO_CLASS, buf, len, &needed);
        if (NT_SUCCESS(st)) {
            *OutInfo = buf;
            *OutLen = len;
            return STATUS_SUCCESS;
        }
        if (st != STATUS_INFO_LENGTH_MISMATCH || needed == 0) {
            SuspxFree(buf);
            return st;
        }
        // Grow with 25% headroom; entries can churn between the size
        // probe and the real query.
        len = needed + (needed / 4) + 0x1000;
        if (len > SUSPEX_SBP_MAX_BYTES) {
            SuspxFree(buf);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
}

// Pattern match with '?' / 0 wildcards. Mask byte is either 0 (wildcard
// legacy encoding) or '?' == 0x3F; anything else means "byte must equal
// pattern byte". Zero-length patterns don't reach here (guarded by
// caller).
static BOOLEAN SuspxPatternHit(const UCHAR* Data, SIZE_T DataLen,
                               const UCHAR* Pattern, const UCHAR* Mask,
                               ULONG PatternLen, SIZE_T* HitOffset)
{
    SIZE_T span, i;
    ULONG j;

    if (DataLen < PatternLen) {
        return FALSE;
    }
    span = DataLen - PatternLen + 1;
    for (i = 0; i < span; i++) {
        BOOLEAN ok = TRUE;
        for (j = 0; j < PatternLen; j++) {
            UCHAR m = Mask[j];
            if (m == 0 || m == '?') {
                continue;
            }
            if (Data[i + j] != Pattern[j]) {
                ok = FALSE;
                break;
            }
        }
        if (ok) {
            *HitOffset = i;
            return TRUE;
        }
    }
    return FALSE;
}

// Fetch a window of the entry with MmCopyMemory(virtual). Kernel VAs are
// safe here: unresolvable pages return STATUS_INVALID_ADDRESS rather
// than bugchecking (unlike the __try/__except-around-RtlCopyMemory
// approach that the caller-facing SuspxKernelMemRead's soft-fault
// fallback used before v4 gated it behind allow_fault).
static NTSTATUS SuspxReadKernelWindow(_In_ UINT64 Va, _Out_writes_bytes_(Len) PVOID Dst,
                                      _In_ SIZE_T Len, _Out_ PSIZE_T Done)
{
    MM_COPY_ADDRESS addr;
    addr.VirtualAddress = (PVOID)(ULONG_PTR)Va;
    return MmCopyMemory(Dst, addr, Len, MM_COPY_MEMORY_VIRTUAL, Done);
}

NTSTATUS SuspxPoolScan(_In_ const SUSPEX_POOL_SCAN_IN* In,
                       _Out_writes_to_(Capacity, *Written) SUSPEX_POOL_ENTRY* Out,
                       _In_ ULONG Capacity, _Out_ PULONG Written, _Out_ PULONG Required,
                       _Out_ PULONG Considered)
{
    SUSPEX_SBP_INFO* info = NULL;
    ULONG info_len = 0;
    NTSTATUS st;
    ULONG max_out = In->MaxResults;
    ULONG pattern_len = In->PatternLen;
    ULONG span = In->ContentSpan;
    ULONG offset = In->Offset;
    ULONG want_nonpaged = (In->Flags & SUSPEX_POOL_FLAG_NONPAGED_ONLY) != 0;
    ULONG want_paged = (In->Flags & SUSPEX_POOL_FLAG_PAGED_ONLY) != 0;
    PVOID scratch = NULL;
    ULONG i, saw = 0, considered = 0, wrote = 0;

    *Written = 0;
    *Required = 0;
    *Considered = 0;

    if (max_out == 0 || max_out > Capacity) {
        max_out = Capacity;
    }
    if (max_out > SUSPEX_POOL_MAX_ENTRIES) {
        max_out = SUSPEX_POOL_MAX_ENTRIES;
    }
    if (pattern_len > SUSPEX_POOL_PATTERN_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (span > SUSPEX_POOL_CONTENT_SPAN_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    // v0.16: refuse pattern + span=0 up front. Previously the content
    // filter branch below silently skipped and every considered entry
    // was emitted with MatchedOffset=0 — indistinguishable from a real
    // hit at VA 0. The orchestrator now refuses the same shape early
    // (see mcp/tools.py pool_scan handler) but a caller that reaches
    // the driver directly (drv_exerciser, out-of-tree consumer) still
    // wants a hard NTSTATUS instead of fake matches.
    if (pattern_len > 0 && span == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pattern_len > 0 && span > 0) {
        scratch = SuspxAlloc(span);
        if (!scratch) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    st = SuspxSbpAcquire(&info, &info_len);
    if (!NT_SUCCESS(st)) {
        if (scratch) {
            SuspxFree(scratch);
        }
        return st;
    }
    saw = info->Count;

    for (i = 0; i < info->Count && wrote < max_out; i++) {
        SUSPEX_SBP_ENTRY* e = &info->AllocatedInfo[i];
        ULONG_PTR va_raw = (ULONG_PTR)e->VirtualAddress;
        BOOLEAN nonpaged = (va_raw & 1) != 0;
        UINT64 va = (UINT64)(va_raw & ~(ULONG_PTR)1);
        SIZE_T size = e->SizeInBytes;

        if (want_nonpaged && !nonpaged) {
            continue;
        }
        if (want_paged && nonpaged) {
            continue;
        }
        if (In->TagFilter && e->u.TagUlong != In->TagFilter) {
            continue;
        }
        considered++;

        UINT64 matched = 0;
        if (pattern_len > 0 && span > 0) {
            SIZE_T got = 0, wanted;
            NTSTATUS rd;
            SIZE_T hit_off = 0;
            UINT64 win_va;
            if (offset >= size) {
                continue;
            }
            wanted = span;
            if (wanted > size - offset) {
                wanted = size - offset;
            }
            win_va = va + offset;
            rd = SuspxReadKernelWindow(win_va, scratch, wanted, &got);
            if (!NT_SUCCESS(rd) || got == 0) {
                continue; // hole: silently skip (not evidence of no-match)
            }
            if (!SuspxPatternHit((const UCHAR*)scratch, got, In->Pattern,
                                 In->Mask, pattern_len, &hit_off)) {
                continue;
            }
            matched = win_va + hit_off;
        }

        Out[wrote].VirtualAddress = va;
        Out[wrote].SizeInBytes = (UINT64)size;
        Out[wrote].Tag = e->u.TagUlong;
        Out[wrote].NonPaged = nonpaged ? 1u : 0u;
        Out[wrote].MatchedOffset = matched;
        wrote++;
    }

    if (scratch) {
        SuspxFree(scratch);
    }
    SuspxFree(info);
    *Written = wrote;
    *Required = saw;
    *Considered = considered;
    return STATUS_SUCCESS;
}
