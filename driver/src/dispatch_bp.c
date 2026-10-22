#include "SuspexDriver.h"
#include "dispatch_internal.h"

SIZE_T SuspxHandleBpSwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_BP_SW_SET_IN in;
    PVOID out;
    SUSPEX_BP_SW_SET_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxBpSwSet(in.Pid, in.Address, &result.Id, &result.OrigByte);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("BPSWSET pid=%llu addr=%llx -> st=%x id=%u", in.Pid, in.Address, result.Status, result.Id);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleBpSwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_BP_SW_CLEAR_IN in;
    PVOID out;
    SUSPEX_USER_FREE_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)SuspxBpSwClear(in.Pid, in.Address, in.Id);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("BPSWCLR pid=%llu addr=%llx id=%u -> st=%x", in.Pid, in.Address, in.Id, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleBpHwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_BP_HW_SET_IN in;
    PVOID out;
    SUSPEX_BP_HW_SET_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxBpHwSet(in.Pid, in.Tid, in.Address, in.Slot, in.Length, in.Access,
                                         in.Flags,
                                         &result.Id, &result.ThreadsPatched);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("BPHWSET pid=%llu tid=%llu addr=%llx slot=%u flags=%x -> st=%x patched=%u",
             in.Pid, in.Tid, in.Address, in.Slot, in.Flags, result.Status, result.ThreadsPatched);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleBpHwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_BP_HW_CLEAR_IN in;
    PVOID out;
    SUSPEX_BP_HW_CLEAR_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)SuspxBpHwClear(in.Pid, in.Tid, in.Slot, &result.ThreadsPatched);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("BPHWCLR pid=%llu tid=%llu slot=%u -> st=%x", in.Pid, in.Tid, in.Slot, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleBpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PSUSPEX_BP_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st;

    st = SuspxOutput(Request, sizeof(SUSPEX_BP_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_BP_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(SUSPEX_BP_LIST_HDR)) / sizeof(SUSPEX_BP_ENTRY));

    st = SuspxBpList((PUCHAR)buf + sizeof(SUSPEX_BP_LIST_HDR), (SIZE_T)capacity * sizeof(SUSPEX_BP_ENTRY),
                     &count, &required);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = required;
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_BP_LIST_HDR) + (SIZE_T)count * sizeof(SUSPEX_BP_ENTRY);
}
