#include "SuspexDriver.h"

// Kernel op log: append-only text file at SUSPEX_KERNEL_LOG_PATH. All call
// sites run at PASSIVE_LEVEL (KMDF sequential queue), so direct ZwWriteFile is
// safe. Records raised above APC_LEVEL (defensive) go to a small pending ring
// flushed by the next passive call.

#define SUSPEX_LOG_MAX 240
#define SUSPEX_LOG_PENDING 16

typedef struct _SUSPEX_LOG_CTX {
    HANDLE File;
    BOOLEAN Initialized;
    CHAR Pending[SUSPEX_LOG_PENDING][SUSPEX_LOG_MAX];
    volatile LONG PendingCount;
} SUSPEX_LOG_CTX;

static SUSPEX_LOG_CTX SuspxLogCtx;

NTSTATUS SuspxLogInit(VOID)
{
    NTSTATUS st;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attrs;
    IO_STATUS_BLOCK iosb;

    SuspxLogCtx.File = NULL;
    SuspxLogCtx.PendingCount = 0;

    RtlInitUnicodeString(&path, SUSPEX_KERNEL_LOG_PATH);
    InitializeObjectAttributes(&attrs, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = ZwCreateFile(&SuspxLogCtx.File,
                      FILE_APPEND_DATA | SYNCHRONIZE,
                      &attrs,
                      &iosb,
                      NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN_IF,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                      NULL,
                      0);
    if (!NT_SUCCESS(st)) {
        SuspxLogCtx.File = NULL;
        return st;
    }
    SuspxLogCtx.Initialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID SuspxLogFlushPending(VOID)
{
    LONG idx;
    CHAR line[SUSPEX_LOG_MAX];

    while (SuspxLogCtx.PendingCount > 0) {
        idx = InterlockedDecrement(&SuspxLogCtx.PendingCount);
        if (idx < 0) {
            InterlockedIncrement(&SuspxLogCtx.PendingCount);
            break;
        }
        if (idx >= SUSPEX_LOG_PENDING) {
            continue;
        }
        RtlCopyMemory(line, SuspxLogCtx.Pending[idx], SUSPEX_LOG_MAX);
        SuspxLog("%s", line);
    }
}

VOID SuspxLogCleanup(VOID)
{
    if (SuspxLogCtx.File) {
        ZwClose(SuspxLogCtx.File);
        SuspxLogCtx.File = NULL;
    }
    SuspxLogCtx.Initialized = FALSE;
}

VOID SuspxLog(_In_ PCSTR Format, ...)
{
    CHAR text[SUSPEX_LOG_MAX];
    CHAR line[SUSPEX_LOG_MAX + 64];
    va_list args;
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    SIZE_T len;
    LARGE_INTEGER now;

    if (!SuspxLogCtx.File) {
        return;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        LONG idx = InterlockedIncrement(&SuspxLogCtx.PendingCount) - 1;
        if (idx < SUSPEX_LOG_PENDING) {
            va_start(args, Format);
            RtlStringCbVPrintfA(SuspxLogCtx.Pending[idx], SUSPEX_LOG_MAX, Format, args);
            va_end(args);
        } else {
            InterlockedDecrement(&SuspxLogCtx.PendingCount);
        }
        return;
    }

    SuspxLogFlushPending();

    va_start(args, Format);
    RtlStringCbVPrintfA(text, sizeof(text), Format, args);
    va_end(args);

    KeQuerySystemTime(&now);
    RtlStringCbPrintfA(line, sizeof(line), "[%I64u] [t%Iu] %s\r\n",
                       (UINT64)now.QuadPart, (UINT64)HandleToUlong(PsGetCurrentThreadId()), text);
    RtlStringCbLengthA(line, sizeof(line), &len);

    // single serialized caller (sequential queue); each append is one
    // synchronous ZwWriteFile issued at PASSIVE_LEVEL
    st = ZwWriteFile(SuspxLogCtx.File, NULL, NULL, NULL, &iosb, (PVOID)line, (ULONG)len, NULL, NULL);

    UNREFERENCED_PARAMETER(st);
}

ULONG SuspxSystemFlags(VOID)
{
    ULONG flags = 0;
    ULONG ret = 0;
    NTSTATUS st;
    SUSPEX_CI_INFO ci;

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation 103
#endif
#ifndef CODEINTEGRITY_OPTION_TESTSIGNING
#define CODEINTEGRITY_OPTION_TESTSIGNING 0x2
#endif
#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_DISABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_DISABLED 0x200
#endif
#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#endif

    ci.Length = sizeof(ci);
    ci.CodeIntegrityOptions = 0;
    st = ZwQuerySystemInformation(SystemCodeIntegrityInformation,
                                  &ci, sizeof(ci), &ret);
    if (NT_SUCCESS(st)) {
        if (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGNING) {
            flags |= SUSPEX_FLAG_TESTSIGNING;
        }
        if (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) {
            flags |= SUSPEX_FLAG_HVCI;
        }
    }
    return flags;
}

ULONG SuspxNtBuild = 0;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver = WDF_NO_HANDLE;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = SuspxEvtDriverUnload;
    config.DriverPoolTag = SUSPEX_POOL_TAG;

    SuspxLogInit();
    SuspxLog("SuspexDrv %u.%u abi=%u DriverEntry",
             SUSPEX_DRV_VERSION_MAJOR, SUSPEX_DRV_VERSION_MINOR, SUSPEX_ABI_VERSION);

    {
        // RtlGetVersion: reliable build capture (the NtBuildNumber import
        // reads garbage without dllimport on this toolchain)
        RTL_OSVERSIONINFOW vi;
        RtlZeroMemory(&vi, sizeof(vi));
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (NT_SUCCESS(RtlGetVersion(&vi))) {
            SuspxNtBuild = vi.dwBuildNumber;
        }
        SuspxLog("build=%u", SuspxNtBuild);
    }

    SuspxKmemInit();
    SuspxBpInit();
    SuspxNotifyInit();

    st = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(st)) {
        SuspxLog("WdfDriverCreate failed st=%x", st);
        SuspxLogCleanup();
        return st;
    }

    st = SuspxCreateControlDevice(driver);
    if (!NT_SUCCESS(st)) {
        SuspxLog("control device failed st=%x", st);
    }

    // all-thread HW breakpoints reach threads created later. The Ex variant
    // requires the image to be linked with /INTEGRITYCHECK (0xC0000022
    // otherwise); fall back to the classic routine when it is refused.
    st = PsSetCreateThreadNotifyRoutineEx(0, SuspxOnThreadNotify);
    if (NT_SUCCESS(st)) {
        SuspxBpThreadNotifyRegistered = 1;
    } else {
        SuspxLog("thread notify Ex failed st=%x (needs /INTEGRITYCHECK), trying classic", st);
        st = PsSetCreateThreadNotifyRoutine(SuspxOnThreadNotifyClassic);
        if (NT_SUCCESS(st)) {
            SuspxBpThreadNotifyRegistered = 2;
        } else {
            SuspxLog("thread notify register failed st=%x (hw bp on new threads disabled)", st);
        }
    }

    st = SuspxPhysRangesInit();
    SuspxLog("phys ranges init st=%x", st);

    // v8: wedge-detector. Best-effort — a failure here does not abort load,
    // but the log line surfaces the state so target_manage(crash_state) has
    // a signal to render.
    {
        NTSTATUS wd = SuspxWatchdogInit();
        SuspxLog("watchdog init st=%x", wd);
    }
    return STATUS_SUCCESS;
}

VOID SuspxEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    LARGE_INTEGER interval;
    ULONG waitedMs;

    UNREFERENCED_PARAMETER(Driver);

    // The APC kernel routine/rundown and the thread-notify callback live in
    // this image. Both must be drained before the code pages go away or a
    // queued APC fires into unmapped memory (BSOD). EvtDriverUnload cannot
    // fail, so we wait (bounded) and log loudly when busy.
    if (SuspxBpThreadNotifyRegistered == 1) {
        PsRemoveCreateThreadNotifyRoutine(SuspxOnThreadNotify);
    } else if (SuspxBpThreadNotifyRegistered == 2) {
        PsRemoveCreateThreadNotifyRoutine(SuspxOnThreadNotifyClassic);
    }
    if (SuspxBpThreadNotifyRegistered) {
        SuspxBpThreadNotifyRegistered = 0;
        waitedMs = 0;
        while (SuspxThreadNotifyActive > 0 && waitedMs < 5000) {
            interval.QuadPart = -10 * 1000; // 1 ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            waitedMs++;
        }
        if (SuspxThreadNotifyActive > 0) {
            SuspxLog("UNLOAD WARNING: thread notify still active=%d", SuspxThreadNotifyActive);
        }
    }

    SuspxBpCleanup();
    SuspxWatchdogShutdown();
    // v10: notify callbacks must be unregistered before the image pages go
    // away, and in-flight callbacks drained (same discipline as the BP
    // thread-notify path above).
    SuspxNotifyDisable();

    // v13: a queued/running kernel-call thunk lives in this image. Flush
    // waits for the worker (it always completes once started), so the
    // deleted work item can never fire into unmapped code.
    SuspxKcallShutdown();

    waitedMs = 0;
    while (SuspxApcOutstanding > 0 && waitedMs < 5000) {
        interval.QuadPart = -10 * 1000; // 1 ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waitedMs++;
    }
    if (SuspxApcOutstanding > 0) {
        SuspxLog("UNLOAD WARNING: %d APC(s) still queued - mapped image may be running", SuspxApcOutstanding);
    }

    SuspxLog("unload (kalloc blocks still tracked: %d)", SuspxKmemLeakCount());
    SuspxLogCleanup();
}
