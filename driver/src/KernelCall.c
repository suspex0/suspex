#include "SuspexDriver.h"

// v13: synchronous kernel function call. The IOCTL thread parks on a KEVENT
// while a WDF work item runs Target at PASSIVE_LEVEL in System context under
// __try/__except (rax + exception capture). The control queue is sequential
// (Device.c), so only one handler owns the slot at a time; the Busy flag
// protects the slot from a timed-out-but-still-running thunk.

typedef UINT64(*SUSPEX_KC_FN)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64,
                              UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);

typedef struct _SUSPEX_KC_SLOT {
    KEVENT Done;                    // signaled by the thunk; cleared per call
    volatile LONG Busy;             // 1 while a call is queued/running
    SUSPEX_KERNEL_CALL_IN In;
    SUSPEX_KERNEL_CALL_OUT Out;
} SUSPEX_KC_SLOT;

static SUSPEX_KC_SLOT g_kc;
static WDFWORKITEM g_kc_wi;         // lazy-created, parented to SuspxDevice

// x64 fastcall ignores surplus register/stack args: a fixed 16-arg typedef
// covers Argc 0..16 and the callee reads only what its signature declares.
// Argc is validated by the handler but not needed by the thunk itself.
static VOID SuspxKcallWorker(_In_ WDFWORKITEM Wi)
{
    UNREFERENCED_PARAMETER(Wi);
    const SUSPEX_KERNEL_CALL_IN* in = &g_kc.In;
    SUSPEX_KC_FN fn = (SUSPEX_KC_FN)(ULONG_PTR)in->Target;
    UINT64 ret = 0;
    __try {
        ret = fn(in->Args[0], in->Args[1], in->Args[2], in->Args[3], in->Args[4],
                 in->Args[5], in->Args[6], in->Args[7], in->Args[8], in->Args[9],
                 in->Args[10], in->Args[11], in->Args[12], in->Args[13], in->Args[14],
                 in->Args[15]);
        g_kc.Out.Completed = 1;
        g_kc.Out.ReturnValue = ret;
        g_kc.Out.Status = (UINT32)STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_kc.Out.Completed = 1;
        g_kc.Out.Exception = 1;
        g_kc.Out.ExceptionCode = (UINT32)GetExceptionCode();
        g_kc.Out.Status = (UINT32)GetExceptionCode();
    }
    // slot is free only AFTER the result is committed and the event signaled
    KeSetEvent(&g_kc.Done, IO_NO_INCREMENT, FALSE);
    InterlockedExchange(&g_kc.Busy, 0);
}

SIZE_T SuspxHandleKernelCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_KERNEL_CALL_IN in;
    PVOID out;
    SUSPEX_KERNEL_CALL_OUT result = {0};
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }

    if (in.Argc > SUSPEX_KC_MAX_ARGS) {
        result.Status = (UINT32)STATUS_INVALID_PARAMETER;
        RtlCopyMemory(out, &result, sizeof(result));
        *Status = STATUS_SUCCESS;
        return sizeof(result);
    }
    // canonical kernel VA unless FORCE (pool-resident / non-module code)
    if (!(in.Flags & SUSPEX_KC_FLAG_FORCE) &&
        (in.Target & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) {
        result.Status = (UINT32)STATUS_INVALID_PARAMETER;
        RtlCopyMemory(out, &result, sizeof(result));
        *Status = STATUS_SUCCESS;
        return sizeof(result);
    }

    // lazy-create persistent work item; safe under the sequential queue
    if (!g_kc_wi) {
        KeInitializeEvent(&g_kc.Done, SynchronizationEvent, FALSE);
        WDF_WORKITEM_CONFIG cfg;
        WDF_WORKITEM_CONFIG_INIT(&cfg, SuspxKcallWorker);
        WDF_OBJECT_ATTRIBUTES attrs;
        WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
        attrs.ParentObject = SuspxDevice;
        st = WdfWorkItemCreate(&cfg, &attrs, &g_kc_wi);
        if (!NT_SUCCESS(st)) {
            *Status = st;
            return 0;
        }
    }
    if (InterlockedCompareExchange(&g_kc.Busy, 1, 0) != 0) {
        // prior call timed out and its thunk is still running (or queued)
        result.Status = (UINT32)STATUS_DEVICE_BUSY;
        RtlCopyMemory(out, &result, sizeof(result));
        *Status = STATUS_SUCCESS;
        return sizeof(result);
    }
    RtlCopyMemory(&g_kc.In, &in, sizeof(in));
    RtlZeroMemory(&g_kc.Out, sizeof(g_kc.Out));
    KeClearEvent(&g_kc.Done);
    WdfWorkItemEnqueue(g_kc_wi);

    LARGE_INTEGER to;
    to.QuadPart = -(LONGLONG)(in.TimeoutMs ? in.TimeoutMs : 30000) * 10000LL;
    st = KeWaitForSingleObject(&g_kc.Done, Executive, KernelMode, FALSE, &to);
    if (st == STATUS_TIMEOUT) {
        // Busy stays 1: the thunk still owns the slot and signals Done when
        // it finishes; the next call's Busy check serializes against it.
        result.Status = (UINT32)STATUS_TIMEOUT;
    } else {
        RtlCopyMemory(&result, &g_kc.Out, sizeof(result));
    }
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("KCALL target=%llx argc=%u flags=%x -> st=%x done=%u ex=%u excode=%x ret=%llx",
             (UINT64)in.Target, (UINT32)in.Argc, (UINT32)in.Flags,
             (UINT32)result.Status, (UINT32)result.Completed, (UINT32)result.Exception,
             (UINT32)result.ExceptionCode, (UINT64)result.ReturnValue);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

// EvtDriverUnload ordering: a queued/running thunk lives in this image, so it
// must finish before the code pages go away. Flush waits for the worker
// (which always signals Done + clears Busy), then the object is deleted.
VOID SuspxKcallShutdown(VOID)
{
    if (g_kc_wi) {
        WdfWorkItemFlush(g_kc_wi);
        WdfObjectDelete(g_kc_wi);
        g_kc_wi = NULL;
    }
}