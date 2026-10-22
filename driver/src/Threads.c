#include "SuspexDriver.h"

// v10 kernel-side thread list: one ZwQuerySystemInformation(
// SystemProcessInformation) walk (same public layout as Processes.c),
// enriched per thread with
//   * Win32StartAddress — ZwQueryInformationThread(
//       ThreadQuerySetWin32StartAddress)
//   * TebBaseAddress    — ZwQueryInformationThread(ThreadBasicInformation)
// Both ride documented query paths against a kernel handle from
// ObOpenObjectByPointer, so no ETHREAD offsets are assumed. A thread that
// exits between the walk and its enrichment is skipped (a hole is not
// evidence); the batch still reports the rest.

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

NTKERNELAPI NTSTATUS ZwQueryInformationThread(_In_ HANDLE ThreadHandle,
                                              _In_ ULONG ThreadInformationClass,
                                              _Out_ PVOID ThreadInformation,
                                              _In_ ULONG ThreadInformationLength,
                                              _Out_opt_ PULONG ReturnLength);

typedef struct _SUSPEX_TBI {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR UniqueProcess;
    ULONG_PTR UniqueThread;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} SUSPEX_TBI;

// Live enrichment for one TID: Win32StartAddress + TebBaseAddress.
// A thread that exits before the lookup gets base fields only.
static VOID SuspxThreadEnrich(_In_ UINT64 Tid, _Inout_ PSUSPEX_THREAD_ENTRY E)
{
    NTSTATUS st;
    PETHREAD Thread = NULL;
    HANDLE h = NULL;
    ULONG64 win32 = 0;
    ULONG ret = 0;
    SUSPEX_TBI tbi;

    if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &Thread))) {
        return; // exited mid-walk — base fields only
    }
    st = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, NULL,
                               THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &h);
    if (NT_SUCCESS(st)) {
        st = ZwQueryInformationThread(h, ThreadQuerySetWin32StartAddress,
                                      &win32, sizeof(win32), &ret);
        if (NT_SUCCESS(st) && win32) {
            E->Win32StartVa = win32;
            E->Flags |= SUSPEX_THREAD_FLAG_WIN32_START;
        }
        st = ZwQueryInformationThread(h, ThreadBasicInformation,
                                      &tbi, sizeof(tbi), &ret);
        if (NT_SUCCESS(st)) {
            E->Teb = (UINT64)(ULONG_PTR)tbi.TebBaseAddress;
            E->Flags |= SUSPEX_THREAD_FLAG_TEB;
        }
        ZwClose(h);
    }
    ObDereferenceObject(Thread);
}

NTSTATUS SuspxThreadList(_In_ UINT32 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PUCHAR buf = NULL;
    SIZE_T size = 1 << 20;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_THREAD_ENTRY out = (PSUSPEX_THREAD_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_THREAD_ENTRY));
    if (cap > SUSPEX_THREADLIST_MAX) {
        cap = SUSPEX_THREADLIST_MAX;
    }

    for (;;) {
        SuspxFree(buf);
        buf = (PUCHAR)SuspxAlloc(size);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(SUSPEX_SYS_PROC_INFO_CLASS, buf, (ULONG)size, NULL);
        if (NT_SUCCESS(st)) {
            break;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            if (size > (64ull << 20)) {
                SuspxFree(buf);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            size *= 2;
            continue;
        }
        SuspxFree(buf);
        return st;
    }

    PUCHAR cur = buf;
    while (cur) {
        SUSPEX_SYS_PROC_INFO* p = (SUSPEX_SYS_PROC_INFO*)cur;
        UINT32 procPid = (UINT32)(ULONG_PTR)p->UniqueProcessId;
        if (Pid == 0 || Pid == procPid) {
            SUSPEX_SYS_THREAD_INFO* tarr = (SUSPEX_SYS_THREAD_INFO*)(cur + sizeof(SUSPEX_SYS_PROC_INFO));
            for (ULONG t = 0; t < p->NumberOfThreads; t++) {
                SUSPEX_SYS_THREAD_INFO* ti = &tarr[t];
                if (cap && written < cap && out) {
                    PSUSPEX_THREAD_ENTRY e = &out[written];
                    RtlZeroMemory(e, sizeof(*e));
                    e->Tid = (UINT32)(ULONG_PTR)ti->UniqueThread;
                    e->Pid = (UINT32)(ULONG_PTR)ti->UniqueProcess;
                    e->StartVa = (UINT64)(ULONG_PTR)ti->StartAddress;
                    e->State = ti->ThreadState;
                    e->WaitReason = ti->WaitReason;
                    e->BasePriority = ti->BasePriority;
                    SuspxThreadEnrich(e->Tid, e);
                    written++;
                }
                total++;
            }
        }
        cur = p->NextEntryOffset ? cur + p->NextEntryOffset : NULL;
    }
    SuspxFree(buf);
    *Count = written;
    *Required = total;
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
