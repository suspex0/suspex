#ifndef SUSPEX_DRIVER_H
#define SUSPEX_DRIVER_H

#include <ntifs.h> // full KAPC_STATE layout (48 bytes on x64); must precede ntddk/wdm
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "../../comm/suspex_abi.h"

typedef struct _SUSPEX_CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SUSPEX_CI_INFO;

// exported but undocumented / no-longer-declared NT APIs used intentionally (lab tooling)
// NOTE: `extern ULONG NtBuildNumber` without dllimport reads garbage on this
// toolchain — the OS build is captured once via RtlGetVersion into SuspxNtBuild
extern ULONG SuspxNtBuild;
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
                                         _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
                                         _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
                                         _Out_ PSIZE_T ReturnSize);
NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process); // PEB32 on WoW64, NULL otherwise
// PsGetProcessVadRoot is exported by ntoskrnl but missing from the WDK import
// lib; Vad.c resolves it via MmGetSystemRoutineAddress at runtime.
NTKERNELAPI struct _OBJECT_TYPE* ObGetObjectType(_In_ PVOID Object);
NTKERNELAPI BOOLEAN KeAlertThread(_In_ PVOID Thread, _In_ KPROCESSOR_MODE AlertMode);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS* Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);
NTKERNELAPI NTSTATUS PsGetContextThread(_In_ PETHREAD Thread, _Inout_ PVOID ThreadContext, _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI NTSTATUS PsSetContextThread(_In_ PETHREAD Thread, _In_ PVOID ThreadContext, _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI PVOID PsGetProcessDebugPort(_In_ PEPROCESS Process);
NTKERNELAPI BOOLEAN PsIsThreadTerminating(_In_ PETHREAD Thread);
NTKERNELAPI ULONG PsGetThreadFreezeCount(_In_ PETHREAD Thread);
// v0.9.3 HW-BP fix: undocumented but exported since NT 5.x, used by NtSuspendThread.
// Required to make Ps{Get,Set}ContextThread deliver synchronously against the
// target's trap frame � otherwise the pending set APC hasn't executed yet
// when our immediate readback runs, and the verify sees stale zeros in the
// DR area on a thread that was never previously DR-active.
// v0.9.3 HW-BP fix note: the DR-arm path no longer needs the suspend
// envelope; Ps{Suspend,Resume}Thread prototypes removed (unexported).
NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits,
                                             _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTKERNELAPI NTSTATUS ZwFreeVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize,
                                            _In_ ULONG NewProtect, _Out_ PULONG OldProtect);
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(_In_ ULONG SystemInformationClass,
                                              _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                              _In_ ULONG SystemInformationLength,
                                              _Out_opt_ PULONG ReturnLength);
NTKERNELAPI VOID KeStackAttachProcess(_In_ PRKPROCESS Process, _Out_ PVOID ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(_In_ PVOID ApcState);

// KAPC_STATE comes from ntifs.h (48 bytes on x64). The previous hand-rolled
// 32-byte SUSPEX_KAPC_STATE was 16 bytes short: KeStackAttachProcess writes
// the full struct, silently corrupting the caller's stack.

typedef enum _SUSPEX_KAPC_ENVIRONMENT {
    SuspxOriginalApcEnvironment = 0,
    SuspxAttachedApcEnvironment = 1,
    SuspxCurrentApcEnvironment = 2,
    SuspxInsertApcEnvironment = 3
} SUSPEX_KAPC_ENVIRONMENT;

// SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION (public x64 ABI,
// as consumed by ZwQuerySystemInformation(SystemProcessInformation))
#define SUSPEX_SYS_PROC_INFO_CLASS 5

#pragma pack(push, 8)
typedef struct _SUSPEX_SYS_THREAD_INFO {
    LARGE_INTEGER KernelTime;  // 0
    LARGE_INTEGER UserTime;    // 8
    LARGE_INTEGER CreateTime;  // 16
    ULONG WaitTime;            // 24
    ULONG Reserved0;           // 28
    PVOID StartAddress;        // 32
    PVOID UniqueProcess;       // 40 (CLIENT_ID.UniqueProcess)
    PVOID UniqueThread;        // 48 (CLIENT_ID.UniqueThread)
    KPRIORITY Priority;        // 56
    LONG BasePriority;         // 60
    ULONG ContextSwitches;     // 64
    ULONG ThreadState;         // 68
    ULONG WaitReason;          // 72
    ULONG Reserved1;           // 76
} SUSPEX_SYS_THREAD_INFO;

typedef struct _SUSPEX_SYS_PROC_INFO {
    ULONG NextEntryOffset;                   // 0
    ULONG NumberOfThreads;                   // 4
    LARGE_INTEGER WorkingSetPrivateSize;     // 8
    ULONG HardFaultCount;                    // 16
    ULONG NumberOfThreadsHighWatermark;      // 20
    ULONGLONG CycleTime;                     // 24
    LARGE_INTEGER CreateTime;                // 32
    LARGE_INTEGER UserTime;                  // 40
    LARGE_INTEGER KernelTime;                // 48
    UNICODE_STRING ImageName;                // 56
    KPRIORITY BasePriority;                  // 72
    HANDLE UniqueProcessId;                  // 80
    HANDLE InheritedFromProcessId;           // 88
    ULONG HandleCount;                       // 96
    ULONG SessionId;                         // 100
    ULONG_PTR UniqueProcessKey;              // 104
    SIZE_T PeakVirtualSize;                  // 112
    SIZE_T VirtualSize;                      // 120
    ULONG PageFaultCount;                    // 128
    SIZE_T PeakWorkingSetSize;               // 136
    SIZE_T WorkingSetSize;                   // 144
    SIZE_T QuotaPeakPagedPoolUsage;          // 152
    SIZE_T QuotaPagedPoolUsage;              // 160
    SIZE_T QuotaPeakNonPagedPoolUsage;       // 168
    SIZE_T QuotaNonPagedPoolUsage;           // 176
    SIZE_T PagefileUsage;                    // 184
    SIZE_T PeakPagefileUsage;                // 192
    SIZE_T PrivatePageCount;                 // 200
    LARGE_INTEGER ReadOperationCount;        // 208
    LARGE_INTEGER WriteOperationCount;       // 216
    LARGE_INTEGER OtherOperationCount;       // 224
    LARGE_INTEGER ReadTransferCount;         // 232
    LARGE_INTEGER WriteTransferCount;        // 240
    LARGE_INTEGER OtherTransferCount;        // 248
} SUSPEX_SYS_PROC_INFO;
#pragma pack(pop)

C_ASSERT(sizeof(SUSPEX_SYS_THREAD_INFO) == 80);
C_ASSERT(FIELD_OFFSET(SUSPEX_SYS_PROC_INFO, UniqueProcessId) == 80);
C_ASSERT(sizeof(SUSPEX_SYS_PROC_INFO) == 256);

#define SUSPEX_POOL_TAG 'xpsS' // "Spsx" in pool dump order
#define SUSPEX_DEVICE_NAME L"\\Device\\SuspexDrv"
#define SUSPEX_SYMLINK_NAME L"\\??\\SuspexDrv"
#define SUSPEX_KERNEL_LOG_PATH L"\\??\\C:\\Users\\Public\\Desktop\\suspex_kernel.log"

// DriverEntry.c
NTSTATUS SuspxLogInit(VOID);
VOID SuspxLogCleanup(VOID);
VOID SuspxLog(_In_ PCSTR Format, ...);
ULONG SuspxSystemFlags(VOID);

// Device.c
NTSTATUS SuspxCreateControlDevice(_In_ WDFDRIVER Driver);
VOID SuspxEvtDriverUnload(_In_ WDFDRIVER Driver);
// v13: control device handle — work-item parent for KernelCall.c.
extern WDFDEVICE SuspxDevice;

// Dispatcher.c
VOID SuspxEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                             _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength,
                             _In_ ULONG IoControlCode);

// dispatch_io.c — request buffer helpers shared across dispatch TUs
NTSTATUS SuspxInput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len);
NTSTATUS SuspxOutput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len);
NTSTATUS SuspxOutMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len);
NTSTATUS SuspxInMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len);

// dispatch_mem.c — combined in/out fetch used across dispatch TUs
NTSTATUS SuspxInOut(_In_ WDFREQUEST Request, _In_ SIZE_T InSize, _In_ SIZE_T OutSize,
                    _Out_ PVOID* In, _Out_ PVOID* Out);

// Memory.c
VOID SuspxKmemInit(VOID);
NTSTATUS SuspxUserMemRead(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PVOID Dst,
                          _In_ SIZE_T Size, _Out_ PSIZE_T Done);
NTSTATUS SuspxUserMemWrite(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ PVOID Src,
                           _In_ SIZE_T Size, _Out_ PSIZE_T Done);
NTSTATUS SuspxUserAlloc(_In_ UINT64 Pid, _In_ UINT64 Size, _In_ ULONG Protect, _Out_ UINT64* Address);
NTSTATUS SuspxUserFree(_In_ UINT64 Pid, _In_ UINT64 Address);
NTSTATUS SuspxUserProtect(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT64 Size,
                          _In_ ULONG Protect, _Out_ ULONG* OldProtect);
NTSTATUS SuspxKernelMemRead(_In_ UINT64 Address, _Out_ PVOID Dst, _In_ SIZE_T Size,
                            _Out_ PSIZE_T Done, _In_ UINT32 Flags);
// v12: Flags2 = SUSPEX_MEM_WRF_* (STRICT_VA refuses the phys-remap fallback);
// Cr3 != 0 swaps the thread into that address space for the copy (foreign
// write — see SuspxKernelMemWriteCr3); WritePath reports the SUSPEX_MEM_WRITE_PATH_*
// the store took.
NTSTATUS SuspxKernelMemWrite(_In_ UINT64 Address, _In_ PVOID Src, _In_ SIZE_T Size,
                             _Out_ PSIZE_T Done, _In_ UINT32 Flags2, _In_ UINT64 Cr3,
                             _Out_ PUINT8 WritePath);
NTSTATUS SuspxKmemAlloc(_In_ UINT64 Size, _Out_ UINT64* Address);
NTSTATUS SuspxKmemFree(_In_ UINT64 Address);
ULONG SuspxKmemLeakCount(VOID);

// Physical.c
BOOLEAN SuspxPhysRead64(_In_ UINT64 Pa, _Out_ UINT64* Value);
NTSTATUS SuspxPhysRangesInit(VOID);
NTSTATUS SuspxPhysMemRead(_In_ UINT64 PhysicalAddress, _Out_ PVOID Dst, _In_ SIZE_T Size, _Out_ PSIZE_T Done);
NTSTATUS SuspxPhysMemWrite(_In_ UINT64 PhysicalAddress, _In_ PVOID Src, _In_ SIZE_T Size,
                           _Out_ PSIZE_T Done, _In_ BOOLEAN AllowMapWrite);
BOOLEAN SuspxTranslateVa(_In_ UINT64 Va, _Out_ UINT64* PhysicalAddress);
// v12: walk under an explicit Cr3 (0 = resolve from context: Pid's process
// via KeStackAttachProcess for user VAs, system tables for kernel VAs).
// PageSizeShift = 12/21/30 for the leaf that mapped VA; UsedCr3 = the CR3
// the walk ran under.
BOOLEAN SuspxTranslateVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3, _In_ UINT64 Pid,
                           _Out_ UINT64* PhysicalAddress,
                           _Out_opt_ UINT32* PageSizeShift,
                           _Out_opt_ UINT64* UsedCr3);
// v12: same walk but exposes the leaf descriptor itself so callers can
// inspect RW/NX/etc. (foreign-CR3 write pre-verifies dst pages writable).
BOOLEAN SuspxWalkVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3,
                      _Out_ UINT64* PhysicalAddress, _Out_ UINT64* LeafEntry,
                      _Out_ UINT32* PageSizeShift);
NTSTATUS SuspxPhysWriteKernelVa(_In_ UINT64 Va, _In_ PVOID Src, _In_ SIZE_T Size);
NTSTATUS SuspxPhysRangesEnumerate(_Out_writes_to_(Capacity, *Written) SUSPEX_PHYS_RANGE_ENTRY* Out,
                                  _In_ ULONG Capacity, _Out_ PULONG Written, _Out_ PULONG Total);

// Pool.c
NTSTATUS SuspxPoolScan(_In_ const SUSPEX_POOL_SCAN_IN* In,
                       _Out_writes_to_(Capacity, *Written) SUSPEX_POOL_ENTRY* Out,
                       _In_ ULONG Capacity, _Out_ PULONG Written, _Out_ PULONG Required,
                       _Out_ PULONG Considered,
                       _Out_opt_ PULONG Holes,
                       _Out_opt_ PULONG SpanTruncated,
                       _Out_opt_ PULONG LastIndex,
                       _Out_opt_ PULONG NextCursor);

// Context.c
NTSTATUS SuspxCtxGet(_In_ UINT64 Tid, _In_ ULONG Flags, _Out_ PVOID Context);
NTSTATUS SuspxCtxSet(_In_ UINT64 Tid, _In_ ULONG Flags, _In_ PVOID Context);
NTSTATUS SuspxProcessThreadApply(_In_ UINT64 Pid, _In_ UINT64 Tid,
                                 _In_ NTSTATUS (*Fn)(_In_ PETHREAD Thread, _Inout_ PVOID Ctx),
                                 _Inout_ PVOID Ctx, _Out_ PUINT32 Applied);

// Breakpoints — shared table record (defined in BpList.c, used by BpSw.c/BpHw.c)
typedef struct _SUSPEX_BP_REC {
    UINT32 Id;
    UINT32 Kind;
    UINT32 Pid;   // HW: 0 (with Global=1) = system-wide
    UINT32 Tid;   // HW: 0 = all threads of Pid (incl. threads created later)
    UINT32 Slot;
    UINT32 Length;
    UINT32 Access;
    UINT32 Used;    // table slot occupied (Enabled may be 0 while winding down)
    UINT32 Enabled;
    UINT32 Global;  // v6: 1 = system-wide (Pid==0). Kept in-band so the
                    // thread-create notify can arm regardless of parent pid.
    UINT64 Address;
    UCHAR OrigByte;
} SUSPEX_BP_REC, *PSUSPEX_BP_REC;

extern SUSPEX_BP_REC SuspxBpTable[SUSPEX_MAX_BP];
extern KSPIN_LOCK SuspxBpLock;
extern UINT32 SuspxBpNextId;

// BpList.c
VOID SuspxBpInit(VOID);
NTSTATUS SuspxBpList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                     _Out_ PUINT32 Count, _Out_ PUINT32 Required);
VOID SuspxBpCleanup(VOID);

// BpSw.c
PSUSPEX_BP_REC SuspxBpAllocLocked(_Out_ PUINT32 Id);
VOID SuspxBpFreeLocked(_In_ PSUSPEX_BP_REC Rec);
NTSTATUS SuspxBpSwSet(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PUINT32 Id, _Out_ PUCHAR OrigByte);
NTSTATUS SuspxBpSwClear(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id);

// BpHw.c
NTSTATUS SuspxBpHwSet(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Address, _In_ UINT32 Slot,
                      _In_ UINT32 Length, _In_ UINT32 Access, _In_ UINT32 Flags,
                      _Out_ PUINT32 Id, _Out_ PUINT32 Applied);
NTSTATUS SuspxBpHwClear(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT32 Slot, _Out_ PUINT32 Applied);

// thread-create notification so all-thread HW breakpoints reach new threads
VOID SuspxOnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
VOID SuspxOnThreadNotifyClassic(_In_ PEPROCESS Process, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
extern volatile LONG SuspxThreadNotifyActive;    // in-flight callback count for unload ordering
extern volatile LONG SuspxBpThreadNotifyRegistered; // 1 = Ex variant, 2 = classic variant

// RemoteCall.c
NTSTATUS SuspxRemoteCall(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                         _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                         _In_ UINT32 Flags, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted);
extern volatile LONG SuspxApcOutstanding; // queued-but-undelivered APC count

// KernelCall.c — v13 synchronous kernel function call. Defined here with the
// other dispatch entrypoints (dispatch_internal.h); SuspxKcallShutdown is
// called from EvtDriverUnload before the image pages go away.
SIZE_T SuspxHandleKernelCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
VOID   SuspxKcallShutdown(VOID);

// Watchdog.c — v8 wedge-detector. See suspex_abi.h and Watchdog.c header
// comment for the contract.
NTSTATUS SuspxWatchdogInit(VOID);
VOID     SuspxWatchdogShutdown(VOID);
NTSTATUS SuspxWatchdogArm(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                          _In_ UINT32 BugcheckCode, _In_ UINT32 Flags,
                          _In_ UINT64 Cookie, _In_ const CHAR* Label);
NTSTATUS SuspxWatchdogKick(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                           _In_ UINT64 Cookie,
                           _Out_ UINT64* KickCount, _Out_ UINT64* LastKickUs,
                           _Out_ UINT64* DeadlineUs);
NTSTATUS SuspxWatchdogDisarm(_In_ UINT32 Id);
NTSTATUS SuspxWatchdogList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                           _In_ SIZE_T CapacityBytes,
                           _Out_ PUINT32 Count, _Out_ PUINT32 Required,
                           _Out_ PUINT64 NowUs);

// Notify.c — v10 notify event ring (the agent's "ears"). See suspex_abi.h
// "Notify ring" section for the contract. Registration is kernel-visible
// state; the orchestrator gates SUBSCRIBE like driver_load.
VOID     SuspxNotifyInit(VOID);
NTSTATUS SuspxNotifySubscribe(_In_ UINT32 Classes, _In_ UINT32 Flags,
                              _Out_ UINT32* Registered);
VOID     SuspxNotifyDisable(VOID);
// v11: BP_HIT append from the int1 trap path — callable at any IRQL;
// drops (and counts) when the ring lock cannot be taken above PASSIVE.
VOID     SuspxEvtAppendBpHit(_In_ UINT32 Pid, _In_ UINT32 Tid, _In_ UINT64 Rip,
                             _In_ UINT64 Dr6, _In_ UINT32 BpId, _In_ UINT32 Slot,
                             _In_ UINT32 Access, _In_ UINT32 Irql);
NTSTATUS SuspxNotifyRead(_In_ UINT32 Max, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT64 Dropped, _Out_ PUINT64 LastSeq);
NTSTATUS SuspxNotifyStats(_Out_ SUSPEX_NOTIFY_STATS_OUT* Out);

// BpTrap.c + BpTrapAsm.asm — v11 kernel HW-BP hit observability. The
// install path redirects every CPU's IDT[1] to SuspxBpTrapStub by lidt'ing
// a writable per-CPU COPY of its IDT (originals saved for restore); the
// stub calls SuspxBpTrapDispatch which consumes #DBs matching an armed HW
// bp (record + RF + resume) and chains everything else to the saved
// KiTrap01. PatchGuard-sensitive — gated by SUSPEX_NOTIFY_FLAG_BP_HOOK_OK
// plus a no-op lidt probe that fails NOT_SUPPORTED when a hypervisor
// intercepts descriptor-table ops (IDT is EPT-RO there anyway).
NTSTATUS SuspxBpTrapInstall(VOID);
VOID     SuspxBpTrapUninstall(VOID);
BOOLEAN  SuspxBpTrapInstalled(VOID);
extern   volatile LONG SuspxBpTrapOn;        // 1 while the hook owns int1
extern   volatile LONG SuspxBpTrapMissed;    // hits consumed unrecorded
extern   volatile LONG SuspxBpHwArmed;       // armed HW-bp table count (BpHw.c)
extern UINT64 SuspxBpTrapChainTarget;        // asm reads: original KiTrap01

// ObjDir.c — v10 object-directory enumeration (ZwOpen/QueryDirectoryObject)
NTSTATUS SuspxObjEnum(_In_ PCWSTR Path, _In_ UINT32 Depth, _In_ UINT32 MaxEntries,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT32 Truncated);

// Threads.c — v10 kernel-side enriched thread list
NTSTATUS SuspxThreadList(_In_ UINT32 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT32 Required);

// Idt.c — v12 per-CPU IDT dump (__sidt + KIDTENTRY64 decode). Fills
// SUSPEX_IDT_ENTRY_ROWs; FirstBase/FirstLimit get the first CPU's IDTR.
NTSTATUS SuspxIdtList(_In_ UINT32 AllCpus,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT64 FirstBase,
                      _Out_ PUINT32 FirstLimit);

// Modules.c
NTSTATUS SuspxKernelModules(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 Count, _Out_ PUINT32 Required);
NTSTATUS SuspxUserModules(_In_ UINT64 Pid, _In_ BOOLEAN Wow64,
                          _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                          _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// Vad.c
NTSTATUS SuspxVadList(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// Handles.c
NTSTATUS SuspxHandleList(_In_ UINT64 Pid, _In_ BOOLEAN WantNames,
                         _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// Processes.c
NTSTATUS SuspxProcessList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                          _Out_ PUINT32 Count, _Out_ PUINT32 Required);

__forceinline PVOID SuspxAlloc(_In_ SIZE_T Size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, SUSPEX_POOL_TAG);
}

__forceinline VOID SuspxFree(_In_ PVOID P)
{
    if (P) {
        ExFreePoolWithTag(P, SUSPEX_POOL_TAG);
    }
}

#endif // SUSPEX_DRIVER_H

