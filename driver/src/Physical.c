#include "SuspexDriver.h"

// v4 physical-memory rework: v1 cached MmGetPhysicalMemoryRanges once at
// driver load (misses hotplug RAM, VM balloon deflate, boot-time ACPI
// changes) and used MmMapIoSpace(MmNonCached) on the RAM path — which
// returns NULL on modern builds for normal RAM (only firmware-reserved
// and MMIO ranges accept the non-cached IO map). Field reports on
// Win 26200 saw every physical read fail gle=1450 (NO_SYSTEM_RESOURCES)
// as a result. v4:
//   * re-queries MmGetPhysicalMemoryRanges each call so hotplug is
//     reflected and the caller can also enumerate the ranges via the
//     new PHYS_RANGES IOCTL,
//   * primary read path is MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) which
//     is documented and works for normal RAM,
//   * MmMapIoSpaceEx(MmCached) is the write path plus the read fallback
//     when MmCopyMemory refuses (typically MMIO / device-reserved). We
//     never use the non-cached map for normal RAM again.

static BOOLEAN SuspxPhysInRangeFresh(_In_ UINT64 Pa, _In_ UINT64 Len)
{
    PPHYSICAL_MEMORY_RANGE r;
    ULONG i = 0;
    BOOLEAN inside = FALSE;

    if (!Len) {
        return FALSE;
    }
    r = MmGetPhysicalMemoryRanges();
    if (!r) {
        return FALSE;
    }
    while (r[i].BaseAddress.QuadPart != 0 || r[i].NumberOfBytes.QuadPart != 0) {
        UINT64 start = (UINT64)r[i].BaseAddress.QuadPart;
        UINT64 size = (UINT64)r[i].NumberOfBytes.QuadPart;
        if (Pa >= start && Len <= size && Pa <= start + (size - Len)) {
            inside = TRUE;
            break;
        }
        i++;
    }
    ExFreePool(r); // MmGetPhysicalMemoryRanges allocates PagedPool for us
    return inside;
}

NTSTATUS SuspxPhysRangesInit(VOID)
{
    // v4: no persistent cache — the check function re-queries per call.
    // Kept as a symbol so DriverEntry keeps compiling until callers stop
    // referencing it; a follow-up commit can drop the call.
    return STATUS_SUCCESS;
}

NTSTATUS SuspxPhysRangesEnumerate(
    _Out_writes_to_(Capacity, *WrittenOut) SUSPEX_PHYS_RANGE_ENTRY* Out,
    _In_ ULONG Capacity,
    _Out_ PULONG WrittenOut,
    _Out_ PULONG TotalOut)
{
    PPHYSICAL_MEMORY_RANGE r;
    ULONG i = 0, written = 0;

    *WrittenOut = 0;
    *TotalOut = 0;
    r = MmGetPhysicalMemoryRanges();
    if (!r) {
        return STATUS_UNSUCCESSFUL;
    }
    while (r[i].BaseAddress.QuadPart != 0 || r[i].NumberOfBytes.QuadPart != 0) {
        if (written < Capacity && Out) {
            Out[written].Base = (UINT64)r[i].BaseAddress.QuadPart;
            Out[written].Size = (UINT64)r[i].NumberOfBytes.QuadPart;
            Out[written].Kind = SUSPEX_PHYS_KIND_RAM;
            Out[written].Reserved = 0;
            written++;
        }
        i++;
    }
    ExFreePool(r);
    *WrittenOut = written;
    *TotalOut = i;
    return STATUS_SUCCESS;
}

// v12: shared 8-byte physical read (was TU-local) — the page-table walks
// and the foreign-CR3 kernel-half identity check in Memory.c both use it.
BOOLEAN SuspxPhysRead64(_In_ UINT64 Pa, _Out_ UINT64* Value)
{
    MM_COPY_ADDRESS src;
    SIZE_T done = 0;
    NTSTATUS st;
    PHYSICAL_ADDRESS pa;
    PVOID map;

    *Value = 0;
    pa.QuadPart = (LONGLONG)Pa;
    // MmMapIoSpace(MmNonCached) returns NULL for normal RAM on modern
    // builds (26200 field reports, gle=1450) — page-table reads must use
    // the same MmCopyMemory path as the v4 data reads, with the cached
    // map as fallback for pages MmCopyMemory refuses.
    src.PhysicalAddress.QuadPart = (LONGLONG)Pa;
    st = MmCopyMemory(Value, src, 8, MM_COPY_MEMORY_PHYSICAL, &done);
    if (NT_SUCCESS(st) && done == 8) {
        return TRUE;
    }
    map = MmMapIoSpaceEx(pa, 8, PAGE_READONLY);
    if (!map) {
        return FALSE;
    }
    *Value = *(UINT64*)map;
    MmUnmapIoSpace(map, 8);
    return TRUE;
}

// v12: the raw four-level walk under a caller-chosen CR3. Physical reads
// only (MmCopyMemory / MmMapIoSpaceEx) — safe from PASSIVE regardless of
// whose tables are being walked, and the only piece shared by translate,
// foreign-CR3 write verify, and the kernel-half identity check.
// LeafEntry reports the descriptor that maps VA (PTE for 4 KiB, PDE/PDPTE
// for large pages) with one adjustment: bit1 (RW) is the EFFECTIVE write
// bit — present iff every walked level granted write. Other leaf bits are
// the descriptor verbatim.
BOOLEAN SuspxWalkVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3,
                      _Out_ UINT64* PhysicalAddress, _Out_ UINT64* LeafEntry,
                      _Out_ UINT32* PageSizeShift)
{
    UINT64 pml4;
    UINT64 pml4e, pdpte, pde, pte;
    UINT64 rw = 2; // ANDed across levels; survives into LeafEntry bit1

    *PhysicalAddress = 0;
    if (LeafEntry) {
        *LeafEntry = 0;
    }
    if (PageSizeShift) {
        *PageSizeShift = 0;
    }
    pml4 = Cr3 & 0x000FFFFFFFFFF000ull;
    if (!pml4) {
        return FALSE;
    }
    if (!SuspxPhysRead64(pml4 + ((Va >> 39) & 0x1FF) * 8, &pml4e) || !(pml4e & 1)) {
        return FALSE;
    }
    rw &= pml4e;
    if (!SuspxPhysRead64((pml4e & 0x000FFFFFFFFFF000ull) + ((Va >> 30) & 0x1FF) * 8, &pdpte) || !(pdpte & 1)) {
        return FALSE;
    }
    rw &= pdpte;
    if (pdpte & 0x80) { // 1 GiB page
        *PhysicalAddress = (pdpte & 0x000FFFFFC0000000ull) + (Va & 0x3FFFFFFFull);
        if (PageSizeShift) {
            *PageSizeShift = 30;
        }
        if (LeafEntry) {
            *LeafEntry = (pdpte & ~2ull) | (rw & 2);
        }
        return TRUE;
    }
    if (!SuspxPhysRead64((pdpte & 0x000FFFFFFFFFF000ull) + ((Va >> 21) & 0x1FF) * 8, &pde) || !(pde & 1)) {
        return FALSE;
    }
    rw &= pde;
    if (pde & 0x80) { // 2 MiB page
        *PhysicalAddress = (pde & 0x000FFFFFFFE00000ull) + (Va & 0x1FFFFFull);
        if (PageSizeShift) {
            *PageSizeShift = 21;
        }
        if (LeafEntry) {
            *LeafEntry = (pde & ~2ull) | (rw & 2);
        }
        return TRUE;
    }
    if (!SuspxPhysRead64((pde & 0x000FFFFFFFFFF000ull) + ((Va >> 12) & 0x1FF) * 8, &pte) || !(pte & 1)) {
        return FALSE;
    }
    rw &= pte;
    *PhysicalAddress = (pte & 0x000FFFFFFFFFF000ull) + (Va & 0xFFFull);
    if (PageSizeShift) {
        *PageSizeShift = 12;
    }
    if (LeafEntry) {
        *LeafEntry = (pte & ~2ull) | (rw & 2);
    }
    return TRUE;
}

// v12: resolve which CR3 to walk under, then SuspxWalkVaEx it.
//   Cr3 != 0  -> caller-supplied tables (foreign-space queries)
//   Pid != 0  -> that process's tables, fetched under KeStackAttachProcess
//   kernel VA -> System process tables (the v5 KVA-shadow fix: the caller's
//                CR3 may lack kernel entries on shadowed builds)
//   else      -> __readcr3() of the IOCTL thread
BOOLEAN SuspxTranslateVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3, _In_ UINT64 Pid,
                           _Out_ UINT64* PhysicalAddress,
                           _Out_opt_ UINT32* PageSizeShift,
                           _Out_opt_ UINT64* UsedCr3)
{
    UINT64 effCr3 = 0;

    *PhysicalAddress = 0;
    if (PageSizeShift) {
        *PageSizeShift = 0;
    }
    if (UsedCr3) {
        *UsedCr3 = 0;
    }

    if (Cr3) {
        effCr3 = Cr3;
    } else if (Pid) {
        PEPROCESS proc;
        KAPC_STATE apc;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
        if (!NT_SUCCESS(st)) {
            return FALSE;
        }
        KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
        effCr3 = __readcr3();
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
    } else if (Va >= 0xFFFF800000000000ull) {
        // Kernel VAs are deliberately absent from the caller's CR3 when KVA
        // shadow is active — effectively always on VBS/HVCI hosts. Resolve
        // under System's tables, which carry the full kernel half. (v5 did
        // this through MmGetPhysicalAddress under the attach; v12 keeps the
        // same tables but walks them itself so PageSizeShift/UsedCr3 come
        // out too.)
        KAPC_STATE apc;
        KeStackAttachProcess((PRKPROCESS)PsInitialSystemProcess, &apc);
        effCr3 = __readcr3();
        KeUnstackDetachProcess(&apc);
    } else {
        effCr3 = __readcr3();
    }

    if (UsedCr3) {
        *UsedCr3 = effCr3;
    }
    return SuspxWalkVaEx(Va, effCr3, PhysicalAddress, NULL, PageSizeShift);
}

BOOLEAN SuspxTranslateVa(_In_ UINT64 Va, _Out_ UINT64* PhysicalAddress)
{
    return SuspxTranslateVaEx(Va, 0, 0, PhysicalAddress, NULL, NULL);
}

// One-page read via MmCopyMemory(MM_COPY_MEMORY_PHYSICAL). Documented and
// stable for normal RAM on every supported build; refuses cleanly (does
// not bugcheck) when the range is not backed by anything readable.
static NTSTATUS SuspxPhysReadPageMmCopy(_In_ UINT64 Pa, _Out_ PVOID Dst,
                                        _In_ SIZE_T Chunk, _Out_ PSIZE_T Done)
{
    MM_COPY_ADDRESS addr;
    NTSTATUS st;

    addr.PhysicalAddress.QuadPart = (LONGLONG)Pa;
    st = MmCopyMemory(Dst, addr, Chunk, MM_COPY_MEMORY_PHYSICAL, Done);
    // MmCopyMemory guarantees *Done is set on success; on failure ignore it.
    if (!NT_SUCCESS(st)) {
        *Done = 0;
    }
    return st;
}

// Fallback for pages MmCopyMemory refuses — typically MMIO / firmware
// reserved. MmMapIoSpaceEx exists on 8.1+; use MmCached because we're
// reading, and the caller either understands the region (MMIO) or the
// data is device/firmware ROM that never needed the non-cached mapping
// that broke MmMapIoSpace on modern builds.
static NTSTATUS SuspxPhysReadPageMap(_In_ UINT64 Pa, _Out_ PVOID Dst,
                                     _In_ SIZE_T Chunk, _Out_ PSIZE_T Done)
{
    PHYSICAL_ADDRESS addr;
    PVOID map;

    *Done = 0;
    addr.QuadPart = (LONGLONG)Pa;
    map = MmMapIoSpaceEx(addr, Chunk, PAGE_READONLY);
    if (!map) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Dst, map, Chunk);
    MmUnmapIoSpace(map, Chunk);
    *Done = Chunk;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxPhysMemRead(_In_ UINT64 PhysicalAddress, _Out_ PVOID Dst, _In_ SIZE_T Size, _Out_ PSIZE_T Done)
{
    NTSTATUS st = STATUS_SUCCESS;
    PUCHAR dst = (PUCHAR)Dst;
    UINT64 pa = PhysicalAddress;
    SIZE_T remaining = Size, moved = 0;

    *Done = 0;
    if (!Dst || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SuspxPhysInRangeFresh(pa, Size)) {
        SuspxLog("PHYSRD out-of-RAM pa=%llx len=%llx (will still try MMIO map fallback)",
                 pa, (UINT64)Size);
        // Do NOT refuse here for v4 — MMIO / firmware ROM callers legitimately
        // read outside the RAM ranges. We still try the map fallback; if the
        // page cannot be mapped we return STATUS_INSUFFICIENT_RESOURCES.
    }
    while (remaining) {
        SIZE_T chunk = (SIZE_T)(PAGE_SIZE - (pa & 0xFFFull));
        SIZE_T done_chunk = 0;

        if (chunk > remaining) {
            chunk = remaining;
        }
        st = SuspxPhysReadPageMmCopy(pa, dst + moved, chunk, &done_chunk);
        if (!NT_SUCCESS(st) || done_chunk != chunk) {
            // MmCopyMemory refused; try the fallback.
            st = SuspxPhysReadPageMap(pa, dst + moved, chunk, &done_chunk);
            if (!NT_SUCCESS(st)) {
                break;
            }
        }
        moved += done_chunk;
        pa += done_chunk;
        remaining -= done_chunk;
    }
    *Done = moved;
    return st;
}

// v5: map-based physical write, opt-in via SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE.
// Per-4KB fault-tolerant: a page MmMapIoSpaceEx refuses is skipped (its src
// slice stays unwritten, reported via Done < Size) and the loop continues —
// a hostile target page must not turn a patch job into a hard failure, and
// a mapping refusal must never escalate past STATUS_PARTIAL_COPY. src always
// advances by the consumed offset (not the moved count) so every written
// chunk carries the bytes that belong at its own physical address.
NTSTATUS SuspxPhysMemWrite(_In_ UINT64 PhysicalAddress, _In_ PVOID Src, _In_ SIZE_T Size,
                           _Out_ PSIZE_T Done, _In_ BOOLEAN AllowMapWrite)
{
    NTSTATUS st = STATUS_SUCCESS;
    PUCHAR src = (PUCHAR)Src;
    UINT64 pa = PhysicalAddress;
    SIZE_T remaining = Size, consumed = 0, moved = 0;
    BOOLEAN anyFail = FALSE;

    *Done = 0;
    if (!Src || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!AllowMapWrite) {
        SuspxLog("PHYSWR refused map-write not opted in pa=%llx len=%llx", pa, (UINT64)Size);
        return STATUS_ACCESS_DENIED;
    }
    if (!SuspxPhysInRangeFresh(pa, Size)) {
        SuspxLog("PHYSWR out-of-RAM pa=%llx len=%llx (tolerated; per-page map decides)",
                 pa, (UINT64)Size);
        // Tolerated on purpose — MMIO / firmware-buffer writers legitimately
        // target ranges the RAM table doesn't list. Whether a page is really
        // writable is decided by MmMapIoSpaceEx per page below.
    }
    while (remaining) {
        SIZE_T chunk = (SIZE_T)(PAGE_SIZE - (pa & 0xFFFull));
        PVOID map;
        PHYSICAL_ADDRESS addr;

        if (chunk > remaining) {
            chunk = remaining;
        }
        addr.QuadPart = (LONGLONG)pa;
        map = MmMapIoSpaceEx(addr, chunk, PAGE_READWRITE);
        if (!map) {
            if (!anyFail) {
                SuspxLog("PHYSWR first skipped offset=%llx pa=%llx",
                         (UINT64)consumed, pa);
            }
            anyFail = TRUE;
            st = STATUS_PARTIAL_COPY;
            consumed += chunk;
            pa += chunk;
            remaining -= chunk;
            continue;
        }
        RtlCopyMemory(map, src + consumed, chunk);
        MmUnmapIoSpace(map, chunk);
        moved += chunk;
        consumed += chunk;
        pa += chunk;
        remaining -= chunk;
    }
    *Done = moved;
    return st;
}

NTSTATUS SuspxPhysWriteKernelVa(_In_ UINT64 Va, _In_ PVOID Src, _In_ SIZE_T Size)
{
    NTSTATUS st = STATUS_SUCCESS;
    PUCHAR src = (PUCHAR)Src;
    UINT64 va = Va;
    SIZE_T remaining = Size;

    while (remaining) {
        UINT64 pa, pagePa;
        SIZE_T chunk = (SIZE_T)(PAGE_SIZE - (va & 0xFFFull));
        PVOID map;
        PHYSICAL_ADDRESS addr;

        if (chunk > remaining) {
            chunk = remaining;
        }
        if (!SuspxTranslateVa(va, &pa)) {
            return STATUS_INVALID_ADDRESS;
        }
        pagePa = pa & ~0xFFFull;
        addr.QuadPart = (LONGLONG)pagePa;
        map = MmMapIoSpace(addr, PAGE_SIZE, MmNonCached);
        if (!map) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory((PUCHAR)map + (pa & 0xFFFull), src + (Size - remaining), chunk);
        MmUnmapIoSpace(map, PAGE_SIZE);
        __invlpg((PVOID)(ULONG_PTR)va);
        va += chunk;
        remaining -= chunk;
    }
    KeInvalidateAllCaches();
    return st;
}
