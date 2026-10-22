#include "SuspexDriver.h"
#include "dispatch_internal.h"

// v10 dispatch: notify ring (SUBSCRIBE/READ/DISABLE/STATS) + kernel
// enumeration (OBJ_ENUM, THREAD_LIST). Same two-phase header+entries
// output format as the process/VAD/handle lists.

SIZE_T SuspxHandleNotifySubscribe(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_NOTIFY_SUBSCRIBE_IN in;
    PVOID out;
    PSUSPEX_NOTIFY_SUBSCRIBE_OUT res;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(SUSPEX_NOTIFY_SUBSCRIBE_OUT), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    res = (PSUSPEX_NOTIFY_SUBSCRIBE_OUT)out;
    RtlZeroMemory(res, sizeof(*res));
    // v11: in.Flags (was Reserved) — CLASS_BP needs FLAG_BP_HOOK_OK.
    res->Status = (UINT32)SuspxNotifySubscribe(in.Classes, in.Flags,
                                               &res->Registered);
    SuspxLog("NOTIFY_SUB classes=%x flags=%x -> st=%x ok=%x",
             in.Classes, in.Flags, res->Status, res->Registered);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_NOTIFY_SUBSCRIBE_OUT);
}

SIZE_T SuspxHandleNotifyRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_NOTIFY_READ_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = SuspxInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    PVOID sys;
    SIZE_T len;
    st = SuspxOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(SUSPEX_NOTIFY_READ_HDR)) {
        *Status = STATUS_BUFFER_TOO_SMALL;
        return 0;
    }

    PSUSPEX_NOTIFY_READ_HDR hdr = (PSUSPEX_NOTIFY_READ_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0;
    UINT64 dropped = 0, lastSeq = 0;
    hdr->Status = (UINT32)SuspxNotifyRead(in.Max, (PSUSPEX_EVT)((PUCHAR)sys + sizeof(*hdr)),
                                          len - sizeof(*hdr), &count, &dropped, &lastSeq);
    hdr->Count = count;
    hdr->Dropped = dropped;
    hdr->LastSeq = lastSeq;
    SuspxLog("NOTIFY_READ max=%u -> n=%u dropped=%llu last=%llu",
             in.Max, count, dropped, lastSeq);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_NOTIFY_READ_HDR) + (SIZE_T)count * sizeof(SUSPEX_EVT);
}

SIZE_T SuspxHandleNotifyDisable(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID out;
    SIZE_T len;
    NTSTATUS st = SuspxOutput(Request, sizeof(SUSPEX_NOTIFY_STATS_OUT), &out, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    PSUSPEX_NOTIFY_STATS_OUT res = (PSUSPEX_NOTIFY_STATS_OUT)out;
    SuspxNotifyDisable();
    RtlZeroMemory(res, sizeof(*res));
    res->Status = 0;
    SuspxLog("NOTIFY_DISABLE");
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_NOTIFY_STATS_OUT);
}

SIZE_T SuspxHandleNotifyStats(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID out;
    SIZE_T len;
    NTSTATUS st = SuspxOutput(Request, sizeof(SUSPEX_NOTIFY_STATS_OUT), &out, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    SuspxNotifyStats((PSUSPEX_NOTIFY_STATS_OUT)out);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_NOTIFY_STATS_OUT);
}

SIZE_T SuspxHandleObjEnum(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_OBJ_ENUM_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = SuspxInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    in.Path[SUSPEX_OBJ_PATH_CCH - 1] = L'\0';

    PVOID sys;
    SIZE_T len;
    st = SuspxOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(SUSPEX_OBJ_HDR) || in.Path[0] != L'\\') {
        *Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
        return 0;
    }

    PSUSPEX_OBJ_HDR hdr = (PSUSPEX_OBJ_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0, required = 0, truncated = 0;
    hdr->Status = (UINT32)SuspxObjEnum(in.Path, in.Depth, in.MaxEntries,
                                       (PUCHAR)sys + sizeof(*hdr),
                                       len - sizeof(*hdr),
                                       &count, &required, &truncated);
    hdr->Count = count;
    hdr->Required = required;
    hdr->Truncated = truncated;
    SuspxLog("OBJENUM path=%S depth=%u -> st=%x n=%u/%u trunc=%u",
             in.Path, in.Depth, hdr->Status, count, required, truncated);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_OBJ_HDR) + (SIZE_T)count * sizeof(SUSPEX_OBJ_ENTRY);
}

SIZE_T SuspxHandleThreadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_THREADLIST_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = SuspxInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    PVOID sys;
    SIZE_T len;
    st = SuspxOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(SUSPEX_THREAD_HDR)) {
        *Status = STATUS_BUFFER_TOO_SMALL;
        return 0;
    }

    PSUSPEX_THREAD_HDR hdr = (PSUSPEX_THREAD_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0, required = 0;
    hdr->Status = (UINT32)SuspxThreadList(in.Pid, (PUCHAR)sys + sizeof(*hdr),
                                          len - sizeof(*hdr), &count, &required);
    hdr->Count = count;
    hdr->Required = required;
    SuspxLog("THREADS pid=%u -> st=%x n=%u/%u", in.Pid, hdr->Status, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_THREAD_HDR) + (SIZE_T)count * sizeof(SUSPEX_THREAD_ENTRY);
}
