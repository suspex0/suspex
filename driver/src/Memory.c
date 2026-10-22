#include "SuspexDriver.h"
#include <intrin.h>

typedef struct _SUSPEX_KALLOC_REC {
    struct _SUSPEX_KALLOC_REC* Next;
    UINT64 Address;
    UINT64 Size;
} SUSPEX_KALLOC_REC, *PSUSPEX_KALLOC_REC;

static PSUSPEX_KALLOC_REC SuspxKAllocHead;
static KSPIN_LOCK SuspxKAllocLock;
static volatile LONG SuspxKAllocReady = 0;

VOID SuspxKmemInit(VOID)
{
    KeInitializeSpinLock(&SuspxKAllocLock);
    SuspxKAllocHead = NULL;
    InterlockedExchange(&SuspxKAllocReady, 1);
}

NTSTATUS SuspxUserMemRead(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PVOID Dst,
                          _In_ SIZE_T Size, _Out_ PSIZE_T Done)
{
    NTSTATUS st;
    PEPROCESS proc;
    SIZE_T got = 0;

    *Done = 0;
    if (!Pid || !Dst || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)Address, PsGetCurrentProcess(), Dst,
                             Size, KernelMode, &got);
    ObDereferenceObject(proc);
    *Done = got;
    return st;
}

NTSTATUS SuspxUserMemWrite(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ PVOID Src,
                           _In_ SIZE_T Size, _Out_ PSIZE_T Done)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;

    *Done = 0;
    if (!Pid || !Src || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        // PreviousMode stays KernelMode after attach, so ProbeForWrite would be
        // a no-op here; the __try guard is the actual protection.
        RtlCopyMemory((PVOID)(ULONG_PTR)Address, Src, Size);
        *Done = Size;
        st = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        SuspxLog("UMWR except pid=%llu addr=%llx st=%x", Pid, Address, st);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}

NTSTATUS SuspxUserAlloc(_In_ UINT64 Pid, _In_ UINT64 Size, _In_ ULONG Protect, _Out_ UINT64* Address)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base = NULL;
    SIZE_T sz;

    *Address = 0;
    if (!Pid || !Size || Size > (1ull << 32)) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    sz = (SIZE_T)Size;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE, Protect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    if (NT_SUCCESS(st)) {
        *Address = (UINT64)(ULONG_PTR)base;
    }
    return st;
}

NTSTATUS SuspxUserFree(_In_ UINT64 Pid, _In_ UINT64 Address)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base;
    SIZE_T sz = 0;

    if (!Pid || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    base = (PVOID)(ULONG_PTR)Address;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}

NTSTATUS SuspxUserProtect(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT64 Size,
                          _In_ ULONG Protect, _Out_ ULONG* OldProtect)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base;
    SIZE_T sz;

    *OldProtect = 0;
    if (!Pid || !Address || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    base = (PVOID)(ULONG_PTR)Address;
    sz = (SIZE_T)Size;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwProtectVirtualMemory(NtCurrentProcess(), &base, &sz, Protect, OldProtect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}
NTSTATUS SuspxKernelMemRead(_In_ UINT64 Address, _Out_ PVOID Dst, _In_ SIZE_T Size,
                          _Out_ PSIZE_T Done, _In_ UINT32 Flags)
{
    MM_COPY_ADDRESS src;
    SIZE_T got = 0;
    NTSTATUS st;
    const BOOLEAN AllowFault = (Flags & SUSPEX_MEM_FLAG_ALLOW_SOFTFAULT) != 0;
    const BOOLEAN Partial = (Flags & SUSPEX_MEM_FLAG_PARTIAL) != 0;

    *Done = 0;
    if (!Address || !Dst || !Size) {
        return STATUS_INVALID_PARAMETER;
    }

    // v6 PARTIAL path: per-4KB walk, stop at the first page MmCopyMemory
    // refuses, return whatever prefix succeeded. Kills the "1 MB chunk
    // across the nonpaged pool fails atomically on one unmapped page"
    // failure mode that made pool sweeps unusable. MmCopyMemory itself
    // is fault-safe by design (documented) — no __try/__except needed.
    if (Partial) {
        PUCHAR dst = (PUCHAR)Dst;
        UINT64 addr = Address;
        SIZE_T remaining = Size, moved = 0;
        while (remaining) {
            SIZE_T page_end = (SIZE_T)(PAGE_SIZE - (addr & 0xFFFull));
            SIZE_T take = (page_end < remaining) ? page_end : remaining;
            SIZE_T page_got = 0;
            src.VirtualAddress = (PVOID)(ULONG_PTR)addr;
            st = MmCopyMemory(dst + moved, src, take, MM_COPY_MEMORY_VIRTUAL, &page_got);
            if (!NT_SUCCESS(st) || page_got == 0) {
                break;
            }
            moved += page_got;
            addr += page_got;
            remaining -= page_got;
            if (page_got < take) {
                break;
            }
        }
        *Done = moved;
        // If we got anything at all, report the prefix: the dispatcher
        // translates a non-success status with Done>0 to STATUS_SUCCESS
        // (a warning NTSTATUS would fail DeviceIoControl outright and the
        // prefix would never reach usermode). *Done < Size is the actual
        // "advance past the first bad page" signal; if literally nothing
        // came back, propagate the underlying error.
        if (moved > 0 && moved < Size) {
            return STATUS_PARTIAL_COPY;
        }
        if (moved == Size) {
            return STATUS_SUCCESS;
        }
        return NT_SUCCESS(st) ? STATUS_INVALID_ADDRESS : st;
    }

    src.VirtualAddress = (PVOID)(ULONG_PTR)Address;
    st = MmCopyMemory(Dst, src, Size, MM_COPY_MEMORY_VIRTUAL, &got);
    if (!NT_SUCCESS(st) && AllowFault && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        // MmCopyMemory refuses non-resident PAGEDATA (e.g. PiDDBCacheTable)
        // instead of faulting it in. The queue pins callbacks to PASSIVE_LEVEL
        // (Device.c), so a soft fault here is serviced normally; a truly
        // invalid address is caught by the handler below.
        __try {
            RtlCopyMemory(Dst, src.VirtualAddress, Size);
            got = Size;
            st = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            st = GetExceptionCode();
            got = 0;
        }
    }
    *Done = got;
    return st;
}

// v12 foreign-CR3 kernel write. Writes `Size` bytes to `Address` as
// resolved under `Cr3`'s page tables instead of the IOCTL thread's own.
//
// Why this is safe (the reason it can ship instead of returning
// not_implemented):
//   * The IOCTL queue pins us at PASSIVE_LEVEL. Before touching anything
//     we require the foreign PML4 kernel half (slots 256..511) to be
//     IDENTICAL to ours — every process CR3 gets its kernel-half entries
//     copied from the same tables, so equality is the normal case for a
//     legitimate foreign space and proves that every kernel VA we execute
//     or touch under the foreign tables (our code, stack, IDT/ISRs, the
//     buffered-IO source buffer) resolves to the same physical bytes.
//     A KPTI *user* CR3 or a garbage CR3 fails this check cleanly with
//     STATUS_INVALID_PARAMETER — never reaches the swap.
//   * Every destination page is pre-verified present+writable under the
//     foreign tables and canonical before the swap. The swap+copy itself
//     runs at DISPATCH_LEVEL: the thread can neither migrate nor be
//     preempted, so no cross-process switch can silently restore a
//     different CR3 mid-copy (the hole in a PASSIVE-level design — a
//     stray write in the wrong address space is worse than a bugcheck).
//   * Under foreign CR3 the only instructions executed are the
//     __readcr3/__writecr3/RtlCopyMemory body — all kernel VAs, all
//     verified identical. No kernel service is called while swapped.
//   * Residual, documented: a dst page unmapped by a concurrent actor in
//     the ~us window between its verify and its copy still faults at
//     DISPATCH -> bugcheck. The per-page interleave keeps the window at
//     interrupt-latency scale; lab tooling accepts it.
static NTSTATUS SuspxKernelMemWriteCr3(_In_ UINT64 Cr3, _In_ UINT64 Address,
                                       _In_ PVOID Src, _In_ SIZE_T Size,
                                       _Out_ PSIZE_T Done)
{
    UINT64 ownPml4, fgnPml4;
    ULONG i;
    PUCHAR src = (PUCHAR)Src;
    UINT64 va = Address;
    SIZE_T remaining = Size, moved = 0;

    *Done = 0;

    // CR3 must be a plausible PML4 frame: bits 63:52 are architecturally
    // reserved (MAXPHYADDR <= 52), and a zero base walks nowhere.
    if ((Cr3 >> 52) != 0 || !(Cr3 & 0x000FFFFFFFFFF000ull)) {
        return STATUS_INVALID_PARAMETER;
    }
    ownPml4 = __readcr3() & 0x000FFFFFFFFFF000ull;
    fgnPml4 = Cr3 & 0x000FFFFFFFFFF000ull;
    // Kernel-half identity: PML4 slots 256..511 must match ours entry for
    // entry. Equality means every kernel VA resolves identically under
    // the foreign tables — our text, stack, IDT, ISRs, and the ioctl's
    // buffered source buffer all stay correct while swapped, at any IRQL.
    for (i = 256; i < 512; i++) {
        UINT64 own = 0, fgn = 0;
        if (!SuspxPhysRead64(ownPml4 + i * 8, &own)
            || !SuspxPhysRead64(fgnPml4 + i * 8, &fgn) || own != fgn) {
            SuspxLog("KMW-CR3 refused cr3=%llx: kernel PML4[%u] mismatch own=%llx fgn=%llx",
                     Cr3, i, own, fgn);
            return STATUS_INVALID_PARAMETER;
        }
    }

    while (remaining) {
        UINT64 pa, leaf;
        UINT32 shift;
        SIZE_T chunk = (SIZE_T)(PAGE_SIZE - (va & 0xFFFull));
        KIRQL oldIrql;
        UINT64 oldCr3;

        if (chunk > remaining) {
            chunk = remaining;
        }
        // A non-canonical VA #GPs on access regardless of PTE contents —
        // verify canonicality before ever touching it swapped.
        if ((INT64)(va << 16) >> 16 != (INT64)va) {
            return STATUS_INVALID_ADDRESS;
        }
        if (!SuspxWalkVaEx(va, Cr3, &pa, &leaf, &shift) || !(leaf & 2)) {
            SuspxLog("KMW-CR3 dst va=%llx unmapped or read-only under cr3=%llx", va, Cr3);
            return STATUS_INVALID_ADDRESS;
        }
        // Swap, copy this page, restore — all at DISPATCH so neither
        // preemption nor a cross-process switch can disturb the CR3.
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        oldCr3 = __readcr3();
        __writecr3(Cr3);
        RtlCopyMemory((PVOID)(ULONG_PTR)va, src + moved, chunk);
        __writecr3(oldCr3);
        KeLowerIrql(oldIrql);
        moved += chunk;
        va += chunk;
        remaining -= chunk;
    }
    *Done = moved;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxKernelMemWrite(_In_ UINT64 Address, _In_ PVOID Src, _In_ SIZE_T Size,
                             _Out_ PSIZE_T Done, _In_ UINT32 Flags2, _In_ UINT64 Cr3,
                             _Out_ PUINT8 WritePath)
{
    NTSTATUS st;
    UINT64 chkVa;
    SIZE_T chkLeft;

    *Done = 0;
    *WritePath = SUSPEX_MEM_WRITE_PATH_UNKNOWN;
    if (!Address || !Src || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Cr3) {
        st = SuspxKernelMemWriteCr3(Cr3, Address, Src, Size, Done);
        if (NT_SUCCESS(st)) {
            *WritePath = SUSPEX_MEM_WRITE_PATH_FOREIGN_CR3;
        }
        return st;
    }

    // Pre-walk every dst page under our own root (the kernel half is
    // identical across CR3s, and the IOCTL thread runs kernel mode on
    // the full root — KVA-shadow user roots never apply here).
    //
    // The walk is not optional hardening: a write fault on a *present
    // but read-only* kernel page is NOT a catchable STATUS_ACCESS_VIOLATION
    // — the fault handler raises PAGE_FAULT_IN_NONPAGED_AREA (0x50)
    // outright, inside the __try, at any IRQL. Only not-present faults
    // ever reach __except. v11 and older therefore had a latent BSOD on
    // ANY write to a read-only kernel page (the phys-remap "fallback"
    // was unreachable). The walk classifies each page before touching it:
    // non-canonical/unmapped/RO pages never see a direct store —
    // STRICT_VA refuses them, non-strict takes the phys remap.
    chkVa = Address;
    chkLeft = Size;
    while (chkLeft) {
        UINT64 pa, leaf;
        UINT32 shift;
        SIZE_T step = (SIZE_T)(PAGE_SIZE - (chkVa & 0xFFFull));

        if (step > chkLeft) {
            step = chkLeft;
        }
        if ((INT64)(chkVa << 16) >> 16 != (INT64)chkVa) {
            break; // non-canonical
        }
        if (!SuspxWalkVaEx(chkVa, __readcr3(), &pa, &leaf, &shift) || !(leaf & 2)) {
            break; // unmapped or not writable at every level
        }
        chkVa += step;
        chkLeft -= step;
    }
    if (chkLeft) {
        SuspxLog("KMWR pre-walk: va=%llx not direct-writable (chkLeft=%llx of %llx)",
                 chkVa, (UINT64)chkLeft, (UINT64)Size);
        if (Flags2 & SUSPEX_MEM_WRF_STRICT_VA) {
            return STATUS_INVALID_ADDRESS;
        }
        // phys remap re-walks each page itself and fails cleanly on what
        // it can't reach — safe on the mixed-range case too.
        st = SuspxPhysWriteKernelVa(Address, Src, Size);
        if (NT_SUCCESS(st)) {
            *Done = Size;
            *WritePath = SUSPEX_MEM_WRITE_PATH_PHYS_REMAP;
        }
        return st;
    }

    __try {
        RtlCopyMemory((PVOID)(ULONG_PTR)Address, Src, Size);
        *Done = Size;
        st = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    if (NT_SUCCESS(st)) {
        *WritePath = SUSPEX_MEM_WRITE_PATH_DIRECT_VA;
        return st;
    }
    if (Flags2 & SUSPEX_MEM_WRF_STRICT_VA) {
        // strict: the remap would bypass the linear VA entirely (DR
        // watchpoints on it never see the store) — refuse instead.
        SuspxLog("KMWR strict: direct va=%llx faulted st=%x, remap refused",
                 Address, st);
        return STATUS_INVALID_ADDRESS;
    }
    // unmapped/RO by TOCTOU: page-table walk + physical map
    st = SuspxPhysWriteKernelVa(Address, Src, Size);
    if (NT_SUCCESS(st)) {
        *Done = Size;
        *WritePath = SUSPEX_MEM_WRITE_PATH_PHYS_REMAP;
    }
    return st;
}

NTSTATUS SuspxKmemAlloc(_In_ UINT64 Size, _Out_ UINT64* Address)
{
    PVOID p;
    PSUSPEX_KALLOC_REC rec;
    KIRQL irql;

    *Address = 0;
    if (!Size || Size > (256ull * 1024 * 1024)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!InterlockedCompareExchange(&SuspxKAllocReady, 1, 1)) {
        return STATUS_DEVICE_NOT_READY;
    }
    p = SuspxAlloc((SIZE_T)Size);
    if (!p) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec = (PSUSPEX_KALLOC_REC)SuspxAlloc(sizeof(*rec));
    if (!rec) {
        SuspxFree(p);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec->Address = (UINT64)(ULONG_PTR)p;
    rec->Size = Size;
    KeAcquireSpinLock(&SuspxKAllocLock, &irql);
    rec->Next = SuspxKAllocHead;
    SuspxKAllocHead = rec;
    KeReleaseSpinLock(&SuspxKAllocLock, irql);
    *Address = rec->Address;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxKmemFree(_In_ UINT64 Address)
{
    PSUSPEX_KALLOC_REC prev = NULL, cur;
    KIRQL irql;

    if (!Address) {
        return STATUS_INVALID_PARAMETER;
    }
    KeAcquireSpinLock(&SuspxKAllocLock, &irql);
    cur = SuspxKAllocHead;
    while (cur) {
        if (cur->Address == Address) {
            if (prev) {
                prev->Next = cur->Next;
            } else {
                SuspxKAllocHead = cur->Next;
            }
            KeReleaseSpinLock(&SuspxKAllocLock, irql);
            SuspxFree((PVOID)(ULONG_PTR)cur->Address);
            SuspxFree(cur);
            return STATUS_SUCCESS;
        }
        prev = cur;
        cur = cur->Next;
    }
    KeReleaseSpinLock(&SuspxKAllocLock, irql);
    // refusing to free untracked pool: only addresses from KMEM_ALLOC
    SuspxLog("KFREE refused untracked addr=%llx", Address);
    return STATUS_INVALID_PARAMETER;
}

// number of live tracked KMEM_ALLOC blocks (unload-time visibility: mapped
// images intentionally stay allocated; the count in the unload log is the
// lab operator's hint that pool is still in use)
ULONG SuspxKmemLeakCount(VOID)
{
    PSUSPEX_KALLOC_REC cur;
    KIRQL irql;
    ULONG n = 0;

    KeAcquireSpinLock(&SuspxKAllocLock, &irql);
    for (cur = SuspxKAllocHead; cur; cur = cur->Next) {
        n++;
    }
    KeReleaseSpinLock(&SuspxKAllocLock, irql);
    return n;
}

