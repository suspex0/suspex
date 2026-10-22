#include "SuspexDriver.h"

// Software (int3) breakpoints plus the two table helpers (alloc/free)
// that BpHw.c also needs. Kernel .text int3 is PatchGuard-unsafe:
// lab-only, prefer HW breakpoints for kernel.

// find a free table slot under the lock; returns NULL when the table is full
PSUSPEX_BP_REC SuspxBpAllocLocked(_Out_ PUINT32 Id)
{
    UINT32 i;
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        if (!SuspxBpTable[i].Used) {
            RtlZeroMemory(&SuspxBpTable[i], sizeof(SuspxBpTable[i]));
            SuspxBpTable[i].Used = 1;
            SuspxBpTable[i].Id = SuspxBpNextId++;
            *Id = SuspxBpTable[i].Id;
            return &SuspxBpTable[i];
        }
    }
    return NULL;
}

VOID SuspxBpFreeLocked(_In_ PSUSPEX_BP_REC Rec)
{
    Rec->Enabled = 0;
    Rec->Used = 0;
}

static PSUSPEX_BP_REC SuspxBpFindSwLocked(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id)
{
    UINT32 i;
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        PSUSPEX_BP_REC r = &SuspxBpTable[i];
        if (r->Kind != SUSPEX_BP_KIND_SW || !r->Used || !r->Enabled) {
            continue;
        }
        if (Id && r->Id == Id) {
            return r;
        }
        if (!Id && Pid && r->Pid == (UINT32)Pid && r->Address == Address) {
            return r;
        }
    }
    return NULL;
}

NTSTATUS SuspxBpSwSet(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PUINT32 Id, _Out_ PUCHAR OrigByte)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    UCHAR orig = 0;
    KIRQL irql;
    PSUSPEX_BP_REC rec = NULL;
    UINT32 newId = 0;

    *Id = 0;
    *OrigByte = 0;
    if (!Pid || !Address) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    rec = SuspxBpAllocLocked(&newId);
    KeReleaseSpinLock(&SuspxBpLock, irql);
    if (!rec) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec->Kind = SUSPEX_BP_KIND_SW;
    rec->Pid = (UINT32)Pid;
    rec->Address = Address;
    rec->Enabled = 1;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        SuspxBpFreeLocked(rec);
        KeReleaseSpinLock(&SuspxBpLock, irql);
        return st;
    }

    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        // probes are no-ops at PreviousMode==KernelMode; SEH is the guard
        orig = *(volatile UCHAR*)(ULONG_PTR)Address;
        *(volatile UCHAR*)(ULONG_PTR)Address = 0xCC;
        st = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    if (!NT_SUCCESS(st)) {
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        SuspxBpFreeLocked(rec);
        KeReleaseSpinLock(&SuspxBpLock, irql);
        return st;
    }
    rec->OrigByte = orig;
    *Id = rec->Id;
    *OrigByte = orig;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxBpSwClear(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    KIRQL irql;
    PSUSPEX_BP_REC rec = NULL;
    UCHAR orig = 0;

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    rec = SuspxBpFindSwLocked(Pid, Address, Id);
    if (!rec) {
        KeReleaseSpinLock(&SuspxBpLock, irql);
        return STATUS_NOT_FOUND;
    }
    orig = rec->OrigByte;
    Pid = rec->Pid;
    Address = rec->Address;
    KeReleaseSpinLock(&SuspxBpLock, irql);

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        // process is gone: the 0CC went away with its address space — retire
        // the record instead of leaking the table slot forever
        SuspxLog("BPSWCLR process gone pid=%llu -> retired id", Pid);
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        SuspxBpFreeLocked(rec);
        KeReleaseSpinLock(&SuspxBpLock, irql);
        return STATUS_NOT_FOUND;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        volatile UCHAR* p = (volatile UCHAR*)(ULONG_PTR)Address;
        if (*p == 0xCC) {
            *p = orig;
            st = STATUS_SUCCESS;
        } else {
            // patched by someone else: do not corrupt, surface mismatch
            SuspxLog("BPSWCLR mismatch addr=%llx cur=%02x", Address, (UINT32)*p);
            st = STATUS_DATA_ERROR;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    if (NT_SUCCESS(st)) {
        SuspxBpFreeLocked(rec);
    }
    KeReleaseSpinLock(&SuspxBpLock, irql);
    return st;
}
