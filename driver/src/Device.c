#include "SuspexDriver.h"

// v13: control device handle shared with KernelCall.c (work-item parent).
// Defined here, declared extern in SuspexDriver.h.
WDFDEVICE SuspxDevice = WDF_NO_HANDLE;

// admin/SYSTEM-only SDDL (kernel+system+admins full control, others denied)
static const WCHAR SuspxSddlString[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static const UNICODE_STRING SuspxSddl = {
    sizeof(SuspxSddlString) - sizeof(WCHAR), sizeof(SuspxSddlString), (PWCH)SuspxSddlString
};

// Non-PnP control device: \\.\SuspexDrv with admin/SYSTEM-only SDDL and a
// sequential default queue (all IOCTL handlers therefore run at PASSIVE_LEVEL
// and are serialized, which the breakpoint/APC tables rely on).

NTSTATUS SuspxCreateControlDevice(_In_ WDFDRIVER Driver)
{
    NTSTATUS st;
    PWDFDEVICE_INIT init;
    WDF_IO_QUEUE_CONFIG queueCfg;
    UNICODE_STRING devName;
    UNICODE_STRING symName;
    WDF_OBJECT_ATTRIBUTES attrs;

    RtlInitUnicodeString(&devName, SUSPEX_DEVICE_NAME);
    RtlInitUnicodeString(&symName, SUSPEX_SYMLINK_NAME);

    init = WdfControlDeviceInitAllocate(Driver, &SuspxSddl);
    if (!init) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(init, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(init, FALSE);

    st = WdfDeviceInitAssignName(init, &devName);
    if (!NT_SUCCESS(st)) {
        WdfDeviceInitFree(init);
        return st;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    st = WdfDeviceCreate(&init, &attrs, &SuspxDevice);
    if (!NT_SUCCESS(st)) {
        WdfDeviceInitFree(init);
        return st;
    }

    st = WdfDeviceCreateSymbolicLink(SuspxDevice, &symName);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueCfg, WdfIoQueueDispatchSequential);
    queueCfg.EvtIoDeviceControl = SuspxEvtIoDeviceControl;
    // the kernel-read fallback faults pageable pages in — only legal at
    // PASSIVE_LEVEL, so pin all queue callbacks there
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    st = WdfIoQueueCreate(SuspxDevice, &queueCfg, &attrs, WDF_NO_HANDLE);
    if (!NT_SUCCESS(st)) {
        SuspxLog("queue create failed st=%x", st);
        return st;
    }

    WdfControlFinishInitializing(SuspxDevice);
    SuspxLog("device ready abi=%u drv=%u.%u build=" __DATE__ " " __TIME__,
             SUSPEX_ABI_VERSION, SUSPEX_DRV_VERSION_MAJOR, SUSPEX_DRV_VERSION_MINOR);
    return STATUS_SUCCESS;
}
