#ifndef SUSPEX_DISPATCH_INTERNAL_H
#define SUSPEX_DISPATCH_INTERNAL_H

#include "SuspexDriver.h"

// dispatch_mem.c
NTSTATUS SuspxHandleMemRead(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info);
NTSTATUS SuspxHandleMemWrite(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info);
SIZE_T SuspxHandleAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleProtect(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleKmemAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleKmemFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_proc.c
SIZE_T SuspxHandleProcessList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleModules(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleVadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleHandleList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleCtxGet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleCtxSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_bp.c
SIZE_T SuspxHandleBpSwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleBpSwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleBpHwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleBpHwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleBpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_kernel.c
SIZE_T SuspxHandlePhysRanges(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandlePoolScan(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleVaTranslate(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleIdtList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleRemoteCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleKernelCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_watchdog.c
SIZE_T SuspxHandleWatchdogArm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleWatchdogKick(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleWatchdogDisarm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleWatchdogList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_notify.c (v10)
SIZE_T SuspxHandleNotifySubscribe(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleNotifyRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleNotifyDisable(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleNotifyStats(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleObjEnum(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T SuspxHandleThreadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

#endif // SUSPEX_DISPATCH_INTERNAL_H
