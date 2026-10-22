#include "SuspexDriver.h"
#include "dispatch_internal.h"

SIZE_T SuspxHandleProcessList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PSUSPEX_PROC_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = SuspxOutput(Request, sizeof(SUSPEX_PROC_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_PROC_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(SUSPEX_PROC_LIST_HDR)) / sizeof(SUSPEX_PROC_ENTRY));

    walk = SuspxProcessList((PUCHAR)buf + sizeof(SUSPEX_PROC_LIST_HDR),
                            (SIZE_T)capacity * sizeof(SUSPEX_PROC_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    SuspxLog("PROCS -> st=%x n=%u/%u", walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_PROC_LIST_HDR) + (SIZE_T)count * sizeof(SUSPEX_PROC_ENTRY);
}

SIZE_T SuspxHandleModules(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _Out_ NTSTATUS* Status)
{
    SUSPEX_MODULES_IN in;
    PVOID out;
    PSUSPEX_MODULES_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = SuspxInOut(Request, sizeof(in), sizeof(SUSPEX_MODULES_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_MODULES_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;

    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(SUSPEX_MODULES_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(SUSPEX_MODULES_HDR)) / sizeof(SUSPEX_MODULE_ENTRY));
        }
    }

    walk = Kernel ? SuspxKernelModules((PUCHAR)out + sizeof(SUSPEX_MODULES_HDR),
                                       (SIZE_T)capacity * sizeof(SUSPEX_MODULE_ENTRY), &count, &required)
                  : SuspxUserModules(in.Pid, (in.Flags & SUSPEX_MOD_FLAG_WOW64) != 0,
                                     (PUCHAR)out + sizeof(SUSPEX_MODULES_HDR),
                                     (SIZE_T)capacity * sizeof(SUSPEX_MODULE_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    SuspxLog("MODS k=%u wow64=%u pid=%llu -> st=%x n=%u/%u", Kernel,
             (in.Flags & SUSPEX_MOD_FLAG_WOW64) != 0, in.Pid, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_MODULES_HDR) + (SIZE_T)count * sizeof(SUSPEX_MODULE_ENTRY);
}

SIZE_T SuspxHandleVadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_VAD_IN in;
    PVOID out;
    PSUSPEX_VAD_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = SuspxInOut(Request, sizeof(in), sizeof(SUSPEX_VAD_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_VAD_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;
    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(SUSPEX_VAD_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(SUSPEX_VAD_HDR)) / sizeof(SUSPEX_VAD_ENTRY));
        }
    }
    walk = SuspxVadList(in.Pid, (PUCHAR)out + sizeof(SUSPEX_VAD_HDR),
                        (SIZE_T)capacity * sizeof(SUSPEX_VAD_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    SuspxLog("VAD pid=%llu -> st=%x n=%u/%u", in.Pid, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_VAD_HDR) + (SIZE_T)count * sizeof(SUSPEX_VAD_ENTRY);
}

SIZE_T SuspxHandleHandleList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_HANDLE_IN in;
    PVOID out;
    PSUSPEX_HANDLE_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = SuspxInOut(Request, sizeof(in), sizeof(SUSPEX_HANDLE_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_HANDLE_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;
    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(SUSPEX_HANDLE_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(SUSPEX_HANDLE_HDR)) / sizeof(SUSPEX_HANDLE_ENTRY));
        }
    }
    walk = SuspxHandleList(in.Pid, in.WantNames != 0, (PUCHAR)out + sizeof(SUSPEX_HANDLE_HDR),
                           (SIZE_T)capacity * sizeof(SUSPEX_HANDLE_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    SuspxLog("HANDLES pid=%llu names=%u -> st=%x n=%u/%u", in.Pid, in.WantNames, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_HANDLE_HDR) + (SIZE_T)count * sizeof(SUSPEX_HANDLE_ENTRY);
}

SIZE_T SuspxHandleCtxGet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_CTX_HDR_IN in;
    PVOID out;
    PSUSPEX_CTX_HDR_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(SUSPEX_CTX_HDR_OUT), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result = (PSUSPEX_CTX_HDR_OUT)out;
    RtlZeroMemory(result, sizeof(*result));
    result->Status = (UINT32)SuspxCtxGet(in.Tid, in.Flags, result->Context);
    result->Flags = in.Flags;
    SuspxLog("CTXGET tid=%llu flags=%x -> st=%x", in.Tid, in.Flags, result->Status);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_CTX_HDR_OUT);
}

SIZE_T SuspxHandleCtxSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_CTX_HDR_IN in;
    PVOID inBuf, out;
    SIZE_T inLen;
    PSUSPEX_CTX_HDR_OUT result;
    // v2 combined layout: [SUSPEX_CTX_HDR_IN][CONTEXT] in the input buffer.
    // (v1 read the context from lpOutBuffer, which METHOD_BUFFERED never
    // delivers, and took Flags from the wrong offset â€” a silent no-op.)
    NTSTATUS st = SuspxInput(Request, sizeof(in) + SUSPEX_CONTEXT_SIZE, &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    st = SuspxOutput(Request, sizeof(SUSPEX_CTX_HDR_OUT), &out, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    result = (PSUSPEX_CTX_HDR_OUT)out;
    {
        __declspec(align(16)) CONTEXT ctx;
        RtlCopyMemory(&ctx, (PUCHAR)inBuf + sizeof(in), sizeof(ctx));
        result->Status = (UINT32)SuspxCtxSet(in.Tid, in.Flags, &ctx);
        result->Flags = in.Flags;
        SuspxLog("CTXSET tid=%llu flags=%x -> st=%x", in.Tid, in.Flags, result->Status);
    }
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_CTX_HDR_OUT);
}
