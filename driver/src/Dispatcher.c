#include "SuspexDriver.h"
#include "dispatch_internal.h"

static VOID SuspxHandlePing(_Out_ SUSPEX_PING_OUT* Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->VersionMajor = SUSPEX_DRV_VERSION_MAJOR;
    Out->VersionMinor = SUSPEX_DRV_VERSION_MINOR;
    Out->NtBuild = SuspxNtBuild;
    Out->Flags = SuspxSystemFlags();
    Out->AbiVersion = SUSPEX_ABI_VERSION;
}

VOID SuspxEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                             _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength,
                             _In_ ULONG IoControlCode)
{
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    SIZE_T info = 0;
    PVOID buf;
    SIZE_T len;
    NTSTATUS inner = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    __try {
        switch (IoControlCode) {
        case SUSPEX_IOCTL_PING:
            st = SuspxOutput(Request, sizeof(SUSPEX_PING_OUT), &buf, &len);
            if (NT_SUCCESS(st)) {
                SUSPEX_PING_OUT ping;
                SuspxHandlePing(&ping);
                RtlCopyMemory(buf, &ping, sizeof(ping));
                info = sizeof(SUSPEX_PING_OUT);
                st = STATUS_SUCCESS;
            }
            break;

        case SUSPEX_IOCTL_USER_MEM_READ:
            st = SuspxHandleMemRead(Request, FALSE, FALSE, &info);
            break;
        case SUSPEX_IOCTL_USER_MEM_WRITE:
            st = SuspxHandleMemWrite(Request, FALSE, FALSE, &info);
            break;
        case SUSPEX_IOCTL_KERNEL_MEM_READ:
            st = SuspxHandleMemRead(Request, TRUE, FALSE, &info);
            break;
        case SUSPEX_IOCTL_KERNEL_MEM_WRITE:
            st = SuspxHandleMemWrite(Request, TRUE, FALSE, &info);
            break;
        case SUSPEX_IOCTL_PHYS_MEM_READ:
            st = SuspxHandleMemRead(Request, FALSE, TRUE, &info);
            break;
        case SUSPEX_IOCTL_PHYS_MEM_WRITE:
            st = SuspxHandleMemWrite(Request, FALSE, TRUE, &info);
            break;

        case SUSPEX_IOCTL_USER_ALLOC:
            info = SuspxHandleAlloc(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_USER_FREE:
            info = SuspxHandleFree(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_USER_PROTECT:
            info = SuspxHandleProtect(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_KMEM_ALLOC:
            info = SuspxHandleKmemAlloc(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_KMEM_FREE:
            info = SuspxHandleKmemFree(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_USER_MODULES:
            info = SuspxHandleModules(Request, FALSE, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_KERNEL_MODULES:
            info = SuspxHandleModules(Request, TRUE, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_PROCESS_LIST:
            info = SuspxHandleProcessList(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_VAD_LIST:
            info = SuspxHandleVadList(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_HANDLE_LIST:
            info = SuspxHandleHandleList(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_PHYS_RANGES:
            info = SuspxHandlePhysRanges(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_POOL_SCAN:
            info = SuspxHandlePoolScan(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_VA_TRANSLATE:
            info = SuspxHandleVaTranslate(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_CTX_GET:
            info = SuspxHandleCtxGet(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_CTX_SET:
            info = SuspxHandleCtxSet(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_BP_SW_SET:
            info = SuspxHandleBpSwSet(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_BP_SW_CLEAR:
            info = SuspxHandleBpSwClear(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_BP_HW_SET:
            info = SuspxHandleBpHwSet(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_BP_HW_CLEAR:
            info = SuspxHandleBpHwClear(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_BP_LIST:
            info = SuspxHandleBpList(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_REMOTE_CALL:
            info = SuspxHandleRemoteCall(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_KERNEL_CALL:
            info = SuspxHandleKernelCall(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_WATCHDOG_ARM:
            info = SuspxHandleWatchdogArm(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_WATCHDOG_KICK:
            info = SuspxHandleWatchdogKick(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_WATCHDOG_DISARM:
            info = SuspxHandleWatchdogDisarm(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_WATCHDOG_LIST:
            info = SuspxHandleWatchdogList(Request, &inner);
            st = inner;
            break;

        case SUSPEX_IOCTL_NOTIFY_SUBSCRIBE:
            info = SuspxHandleNotifySubscribe(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_NOTIFY_READ:
            info = SuspxHandleNotifyRead(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_NOTIFY_DISABLE:
            info = SuspxHandleNotifyDisable(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_NOTIFY_STATS:
            info = SuspxHandleNotifyStats(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_OBJ_ENUM:
            info = SuspxHandleObjEnum(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_THREAD_LIST:
            info = SuspxHandleThreadList(Request, &inner);
            st = inner;
            break;
        case SUSPEX_IOCTL_IDT_LIST:
            info = SuspxHandleIdtList(Request, &inner);
            st = inner;
            break;

        default:
            SuspxLog("unknown ioctl %x", IoControlCode);
            st = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        SuspxLog("EXCEPT ioctl=%x st=%x", IoControlCode, st);
    }

    WdfRequestCompleteWithInformation(Request, st, info);
}
