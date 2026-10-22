#include "SuspexDriver.h"

NTSTATUS SuspxInput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len)
{
    PVOID b;
    SIZE_T l;
    NTSTATUS st = WdfRequestRetrieveInputBuffer(Request, Min, &b, &l);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    *Buf = b;
    *Len = l;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxOutput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len)
{
    PVOID b;
    SIZE_T l;
    NTSTATUS st = WdfRequestRetrieveOutputBuffer(Request, Min, &b, &l);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    *Buf = b;
    *Len = l;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxOutMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len)
{
    PMDL mdl;
    PVOID sys;
    NTSTATUS st = WdfRequestRetrieveOutputWdmMdl(Request, &mdl);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    sys = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!sys) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *Sys = sys;
    *Len = MmGetMdlByteCount(mdl);
    return STATUS_SUCCESS;
}

NTSTATUS SuspxInMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len)
{
    PMDL mdl;
    PVOID sys;
    NTSTATUS st = WdfRequestRetrieveInputWdmMdl(Request, &mdl);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    sys = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!sys) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *Sys = sys;
    *Len = MmGetMdlByteCount(mdl);
    return STATUS_SUCCESS;
}
