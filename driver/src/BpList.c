#include "SuspexDriver.h"

// Shared breakpoint-table storage plus init/list/cleanup entry points.
// SW set/clear + table alloc/find helpers live in BpSw.c; DR-based HW
// arming plus thread-create notification live in BpHw.c. Split is
// mechanical — logic and locking policy unchanged.

SUSPEX_BP_REC SuspxBpTable[SUSPEX_MAX_BP];
KSPIN_LOCK SuspxBpLock;
UINT32 SuspxBpNextId = 1;
volatile LONG SuspxBpThreadNotifyRegistered = 0;
volatile LONG SuspxThreadNotifyActive = 0;
// v11: live HW-bp record count. Read lock-free by the int1 dispatch path
// when the table spinlock is out of reach (>DISPATCH_LEVEL hits).
volatile LONG SuspxBpHwArmed = 0;

VOID SuspxBpInit(VOID)
{
    KeInitializeSpinLock(&SuspxBpLock);
}

NTSTATUS SuspxBpList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                     _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    KIRQL irql;
    UINT32 i, outIdx = 0;
    UINT32 cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_BP_ENTRY));
    PSUSPEX_BP_ENTRY out = (PSUSPEX_BP_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        PSUSPEX_BP_REC r = &SuspxBpTable[i];
        if (!r->Used || !r->Enabled) {
            continue;
        }
        if (outIdx < cap && out) {
            out[outIdx].Id = r->Id;
            out[outIdx].Kind = r->Kind;
            out[outIdx].Pid = r->Pid;
            out[outIdx].Tid = r->Tid;
            out[outIdx].Slot = r->Slot;
            out[outIdx].Length = r->Length;
            out[outIdx].Access = r->Access;
            out[outIdx].Enabled = r->Enabled;
            out[outIdx].Address = r->Address;
            out[outIdx].OrigByte = r->OrigByte;
            RtlZeroMemory(out[outIdx].Reserved, sizeof(out[outIdx].Reserved));
            outIdx++;
        }
        (*Required)++;
    }
    KeReleaseSpinLock(&SuspxBpLock, irql);
    *Count = outIdx;
    return *Required > outIdx ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

VOID SuspxBpCleanup(VOID)
{
    // best-effort restore of live SW breakpoints so the target does not keep
    // 0xCC traps after unload; must not hold the table lock while clearing
    UINT32 i;
    KIRQL irql;
    SUSPEX_BP_REC snapshot[SUSPEX_MAX_BP];
    UINT32 snapCount = 0;

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        PSUSPEX_BP_REC r = &SuspxBpTable[i];
        if (r->Used && r->Enabled && r->Kind == SUSPEX_BP_KIND_SW) {
            snapshot[snapCount++] = *r;
        }
        r->Used = 0;
        r->Enabled = 0;
    }
    SuspxBpHwArmed = 0;
    KeReleaseSpinLock(&SuspxBpLock, irql);

    for (i = 0; i < snapCount; i++) {
        SuspxBpSwClear(snapshot[i].Pid, snapshot[i].Address, snapshot[i].Id);
    }
}
