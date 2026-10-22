#include "SuspexDriver.h"

// Kernel-initiated user APC execution: the APC's normal routine is the user
// target itself, so ntdll's user-APC dispatcher calls Target(Arg1, Arg2, Arg3)
// inside the target process and restores the interrupted context via
// NtContinue afterwards. No stub shellcode is written into the target.

// NT x64 KAPC layout (public ABI, minimal fields)
typedef struct _SUSPEX_KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    PVOID Thread;
    LIST_ENTRY ApcListEntry;
    PVOID KernelRoutine;
    PVOID RundownRoutine;
    PVOID NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    CCHAR ApcMode;
    UCHAR NormalRoutineActive;
    UCHAR SpareByte2;
} SUSPEX_KAPC, *PSUSPEX_KAPC;

C_ASSERT(sizeof(SUSPEX_KAPC) == 0x58);

typedef VOID (*SUSPEX_KERNEL_ROUTINE)(_In_ PSUSPEX_KAPC Apc, _Inout_ PVOID* NormalRoutine,
                                      _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1,
                                      _Inout_ PVOID* SystemArgument2);
typedef VOID (*SUSPEX_RUNDOWN_ROUTINE)(_In_ PSUSPEX_KAPC Apc);

NTKERNELAPI VOID KeInitializeApc(_Out_ PSUSPEX_KAPC Apc, _In_ PVOID Thread,
                                 _In_ SUSPEX_KAPC_ENVIRONMENT Environment,
                                 _In_ SUSPEX_KERNEL_ROUTINE KernelRoutine,
                                 _In_opt_ SUSPEX_RUNDOWN_ROUTINE RundownRoutine,
                                 _In_opt_ PVOID NormalRoutine,
                                 _In_ KPROCESSOR_MODE ApcMode,
                                 _In_opt_ PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(_Inout_ PSUSPEX_KAPC Apc, _In_opt_ PVOID SystemArgument1,
                                     _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);

static VOID SuspxApcKernelRoutine(_In_ PSUSPEX_KAPC Apc, _Inout_ PVOID* NormalRoutine,
                                  _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1,
                                  _Inout_ PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    InterlockedDecrement(&SuspxApcOutstanding);
    SuspxFree(Apc);
}

static VOID SuspxApcRundown(_In_ PSUSPEX_KAPC Apc)
{
    InterlockedDecrement(&SuspxApcOutstanding);
    SuspxFree(Apc);
}

volatile LONG SuspxApcOutstanding = 0;

NTSTATUS SuspxRemoteCall(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                         _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                         _In_ UINT32 Flags, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted)
{
    NTSTATUS st;
    PETHREAD thread;
    PSUSPEX_KAPC apc;
    BOOLEAN queued;
    BOOLEAN kernelMode = (Flags & SUSPEX_RC_FLAG_KERNEL) != 0;

    *Queued = 0;
    *Alerted = 0;
    if (!Pid || !Tid || !Target) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    apc = (PSUSPEX_KAPC)SuspxAlloc(sizeof(*apc));
    if (!apc) {
        ObDereferenceObject(thread);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(apc, thread, SuspxOriginalApcEnvironment,
                    SuspxApcKernelRoutine, SuspxApcRundown,
                    (PVOID)(ULONG_PTR)Target,
                    kernelMode ? KernelMode : UserMode,
                    (PVOID)(ULONG_PTR)Arg1);
    apc->SystemArgument1 = (PVOID)(ULONG_PTR)Arg2;
    apc->SystemArgument2 = (PVOID)(ULONG_PTR)Arg3;

    // account BEFORE inserting: the kernel routine can run the instant the
    // APC is queued, and SuspxEvtDriverUnload must never observe zero with
    // an APC still in flight (the routines live in this driver image).
    InterlockedIncrement(&SuspxApcOutstanding);
    queued = KeInsertQueueApc(apc, apc->SystemArgument1, apc->SystemArgument2, IO_NO_INCREMENT);
    if (!queued && !kernelMode) {
        // plain user APCs need an alertable thread: alert and retry once.
        // kernel APCs deliver on the next runnable moment, no alert needed.
        KeAlertThread(thread, UserMode);
        *Alerted = 1;
        KeInitializeApc(apc, thread, SuspxOriginalApcEnvironment,
                        SuspxApcKernelRoutine, SuspxApcRundown,
                        (PVOID)(ULONG_PTR)Target, UserMode, (PVOID)(ULONG_PTR)Arg1);
        apc->SystemArgument1 = (PVOID)(ULONG_PTR)Arg2;
        apc->SystemArgument2 = (PVOID)(ULONG_PTR)Arg3;
        queued = KeInsertQueueApc(apc, apc->SystemArgument1, apc->SystemArgument2, IO_NO_INCREMENT);
    }
    if (!queued) {
        InterlockedDecrement(&SuspxApcOutstanding); // never entered the queue
        SuspxFree(apc);
    }
    ObDereferenceObject(thread);
    *Queued = queued ? 1 : 0;
    return queued ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
