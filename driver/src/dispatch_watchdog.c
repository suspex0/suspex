#include "SuspexDriver.h"
#include "dispatch_internal.h"

// v8: watchdog. Arm/Kick/Disarm are point ops; List is variable-length. Every
// handler runs at PASSIVE_LEVEL and does not itself hold the watchdog table
// spinlock — SuspxWatchdogXxx does the locking.
SIZE_T SuspxHandleWatchdogArm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_WDG_ARM_IN in;
    PVOID out;
    SUSPEX_WDG_ARM_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    // guarantee label terminator inside the driver's copy; SuspxWatchdogArm
    // does the same but it never hurts to normalize at the ABI boundary.
    in.Label[SUSPEX_WDG_MAX_LABEL - 1] = '\0';
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxWatchdogArm(in.Id, in.DeadlineMs, in.BugcheckCode,
                                             in.Flags, in.Cookie, in.Label);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("WDGARM id=%u deadline_ms=%u flags=0x%x -> st=%x",
             in.Id, in.DeadlineMs, in.Flags, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleWatchdogKick(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_WDG_KICK_IN in;
    PVOID out;
    SUSPEX_WDG_KICK_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxWatchdogKick(in.Id, in.DeadlineMs, in.Cookie,
                                              &result.KickCount, &result.LastKickUs,
                                              &result.DeadlineUs);
    RtlCopyMemory(out, &result, sizeof(result));
    // Kick is high-cadence; log only on error to keep the log-file growth sane.
    if (result.Status != 0) {
        SuspxLog("WDGKICK id=%u deadline_ms=%u -> st=%x", in.Id, in.DeadlineMs, result.Status);
    }
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleWatchdogDisarm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    SUSPEX_WDG_DISARM_IN in;
    PVOID out;
    SUSPEX_WDG_DISARM_OUT result;
    NTSTATUS st = SuspxInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)SuspxWatchdogDisarm(in.Id);
    RtlCopyMemory(out, &result, sizeof(result));
    SuspxLog("WDGDIS id=%u -> st=%x", in.Id, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T SuspxHandleWatchdogList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PSUSPEX_WDG_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    UINT64 nowUs = 0;
    NTSTATUS st;

    st = SuspxOutput(Request, sizeof(SUSPEX_WDG_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PSUSPEX_WDG_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(SUSPEX_WDG_LIST_HDR)) / sizeof(SUSPEX_WDG_ENTRY));

    st = SuspxWatchdogList((PUCHAR)buf + sizeof(SUSPEX_WDG_LIST_HDR),
                            (SIZE_T)capacity * sizeof(SUSPEX_WDG_ENTRY),
                            &count, &required, &nowUs);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = required;
    hdr->NowUs = nowUs;
    *Status = STATUS_SUCCESS;
    return sizeof(SUSPEX_WDG_LIST_HDR) + (SIZE_T)count * sizeof(SUSPEX_WDG_ENTRY);
}
