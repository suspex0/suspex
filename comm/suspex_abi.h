#ifndef SUSPEX_ABI_H
#define SUSPEX_ABI_H

// Wire ABI shared by suspex_driver.sys (kernel, C), comm/ (user, C++) and
// tools/drv_exerciser. Fixed-layout, no pointers, no C++. Any change here is a
// breaking ABI change: bump SUSPEX_ABI_VERSION and the driver epoch.

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
// windows.h first: TUs may include this header before any OS header, and
// winioctl.h cannot be parsed without the winnt.h type definitions.
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// v2 (2026-09): CTX_SET moved to combined input layout [hdr][CONTEXT],
// SUSPEX_MODULES_IN gained Flags (WoW64 walk), VAD + HANDLE_LIST IOCTLs added.
// v4 (2026-09-06): PHYS_RANGES + POOL_SCAN IOCTLs, PhysMemRead reworked
// (MmCopyMemory first, per-call MmGetPhysicalMemoryRanges re-query).
// v5 (2026-09-06): PHYS_MEM_WRITE becomes opt-in via SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE
// and turns fault-tolerant (per-4KB skip + STATUS_PARTIAL_COPY instead of
// aborting on the first unmappable page). No struct layout changes.
// v6 (2026-09-06): SUSPEX_MEM_FLAG_PARTIAL on kernel READ (per-4KB walk,
// stop at first hole, return valid prefix as STATUS_PARTIAL_COPY). HW-BP
// SET honours pid=0 as system-wide (arm every existing thread of every
// process + PsSetCreateThreadNotifyRoutine catches newborns), gated by
// SUSPEX_BP_HW_FLAG_GLOBAL and a per-BP cap. No struct layout changes;
// old drivers ignore the new flag bits, so mixed-version pairings keep
// the v5 behaviour.
// v7 (2026-09-09): No driver-side struct changes. Bumped to gate the new
// agent/comm surfaces on top of an already-shipped IOCTL set:
//   * VA_TRANSLATE (0x857) now first-class over gRPC — the IOCTL shipped
//     in v5 but had no wire surface; Memory.VaTranslate exposes it.
//   * Memory.Watch (agent-side polling, in-agent threads only) uses
//     existing MEM_READ paths.
//   * Files.LogTail + kernel-log rotation live entirely in the agent
//     process (Win32 CreateFile/SetFilePointerEx), no driver IOCTL.
//   * StatusResponse.agent_uptime_ms + RunExeResponse.killed populated.
// A v7 driver + v7 agent + v7 orchestrator ship together; older drivers
// still pair with a v7 agent (agent gates the new surfaces on comm/proto
// only). Rebuild recipe: README "ABI v7 rebuild".
//
// v8 (2026-09-10): wedge-detector watchdog. Four new IOCTLs
// (WATCHDOG_ARM/KICK/DISARM/LIST) driven by a driver-side system thread
// at HIGH_PRIORITY that KeBugCheckEx()'s the target when a caller-armed
// deadline passes without a kick. Turns silent wedges into analyzable
// dumps + auto-reboots — no PatchGuard-sensitive kernel .text hooks.
// Files.LogFollow server-streaming RPC (agent-only, no driver call) rides
// in the same version bump so the "read verdicts out of a live wedge"
// story lands complete. Rebuild recipe: README "ABI v8 rebuild".
// (A brief v9 (2026-09-11) added Windows Sandbox RPCs; withdrawn
// 2026-09-14 — nested-VM WSB proved unstable, emulation covers the use
// case. Version returns to 8.)
//
// v10 (2026-09-20): agent "ears" + kernel eyes. Six new IOCTLs, additive
// (old agents pair fine with a v10 driver — they simply never send the
// new codes):
//   NOTIFY_SUBSCRIBE/READ/DISABLE/STATS (0x8A0-0x8A3): the driver
//     registers PsSet{CreateProcess,CreateThread,LoadImage}NotifyRoutine
//     and rings fixed-size events into a bounded overwrite-oldest ring
//     (never blocks the notifying thread; overflow bumps a dropped
//     counter the reader surfaces as gap evidence).
//   OBJ_ENUM (0x8A4): kernel object-directory enumeration via
//     ZwOpenDirectoryObject + ZwQueryDirectoryObject — version-proof,
//     no _OBJECT_DIRECTORY struct offsets. Depth cap 2, entry cap 4096.
//   THREAD_LIST (0x8A5): kernel SystemProcessInformation walk enriched
//     per-thread with ZwQueryInformationThread(ThreadBasicInformation →
//     TebBaseAddress, ThreadQuerySetWin32StartAddress) — both documented
//     info classes, no ETHREAD offset drift.
// Rebuild recipe: README "ABI v10 rebuild".
//
// v11 (2026-09-22): kernel HW-BP hit observability. Two additive changes,
// same rebuild pairing as v10 (old agents just never request the class):
//   * SUSPEX_EVT grows a BP_HIT tail (Address/Dr6/BpId/Slot/Access/Irql)
//     and a new kind SUSPEX_EVT_KIND_BP_HIT=6 under a new subscription
//     class SUSPEX_EVT_CLASS_BP=0x8. The ring drains through the existing
//     NOTIFY_READ/STATS IOCTLs — no new function codes.
//   * NOTIFY_SUBSCRIBE_IN.Reserved -> Flags (same layout). CLASS_BP is
//     only honored when the caller passes SUSPEX_NOTIFY_FLAG_BP_HOOK_OK:
//     subscribing it installs a per-CPU IDT[1] hook (BpTrap.c) that
//     consumes #DB hits matching the armed HW-BP table, records
//     DR6/RIP/tid into the ring, sets RF, and resumes — the "hits only
//     observable with an attached kd" gap. IDT patching is PatchGuard
//     territory and refused outright when HVCI is on; the flag is the
//     explicit lab consent bit, mirroring BP_HW_FLAG_DANGEROUS_OK.
// Rebuild recipe: README "ABI v11 rebuild".
//
// v12 (2026-09-25): write-path visibility + foreign-CR3 ops + IDT dump.
//   * MEM_WRITE gains an optional extended header (SUSPEX_MEM_WRITE_IN,
//     marker-gated via the old Reserved slot) carrying Cr3 + Flags2, and
//     an optional SUSPEX_MEM_WRITE_OUT reply {Status, WritePath, Done}.
//     Kernel writes now report which store ran: direct VA, phys-remap
//     fallback, or foreign-CR3 — the remap silently bypassed DR
//     watchpoints on the linear address, and callers had no way to know.
//     SUSPEX_MEM_WRF_STRICT_VA refuses the fallback (fault ->
//     STATUS_INVALID_ADDRESS). Cr3 != 0 swaps the IOCTL thread into that
//     address space for the copy (kernel-write only; the driver verifies
//     the foreign tables share the kernel half and pre-faults every dst
//     page at DISPATCH first — rejected cr3 -> STATUS_INVALID_PARAMETER,
//     unmapped dst -> STATUS_INVALID_ADDRESS).
//   * VA_TRANSLATE_IN grows Cr3 + Pid; VA_TRANSLATE_OUT grows
//     PageSizeShift + Cr3 (the walk now runs under an explicit CR3 or a
//     target process's tables via KeStackAttachProcess — the deferred v7
//     USER-space feature).
//   * IDT_LIST (0x8A6, OUT_DIRECT): driver-side per-CPU __sidt walk,
//     decoded KIDTENTRY64 rows + per-row IDTR base.
// Rebuild recipe: README "ABI v12 rebuild".
//
// v13 (2026-10-06): synchronous kernel function call — WDF work-item thunk at
// PASSIVE_LEVEL in System context; SEH-guarded rax + exception capture,
// KEVENT completion with caller timeout. One in-flight call at a time
// (control queue is sequential). Rebuild recipe: README "ABI v13 rebuild".
#define SUSPEX_ABI_VERSION 13

#define SUSPEX_DEVICE_TYPE 0x00008325
#define SUSPEX_DRV_VERSION_MAJOR 1
// v8.1 (2026-09-10): watchdog runner mechanism swap — thread → periodic
// timer DPC. ABI unchanged (SUSPEX_ABI_VERSION stays 8); MINOR bump so a
// field target's Ping() distinguishes the two runners without a wire probe.
// v10.1 (2026-09-20): notify ring + obj_enum + thread_list IOCTLs.
// v10.2 (2026-09-21): partial reads complete STATUS_SUCCESS + short *Done
// instead of STATUS_PARTIAL_COPY — the warning NTSTATUS failed the
// usermode DeviceIoControl (gle=299) and dropped the valid prefix.
// Wire shape unchanged; MINOR bump so Ping distinguishes the runners.
// v11.0 (2026-09-22): BP_HIT ring records + per-CPU int1 hook behind
// NOTIFY_SUBSCRIBE(CLASS_BP, FLAG_BP_HOOK_OK).
// v12.0 (2026-09-25): ext mem-write header (write_path + STRICT_VA + cr3),
// VA_TRANSLATE pid/cr3 + USER walks, IDT_LIST.
// v13.0 (2026-10-06): KERNEL_CALL — synchronous kernel function call.
#define SUSPEX_DRV_VERSION_MINOR 6

// own function-code range, never borrowed from any third-party driver
#define SUSPEX_FUNC_PING 0x830
#define SUSPEX_FUNC_USER_MEM_READ 0x831
#define SUSPEX_FUNC_USER_MEM_WRITE 0x832
#define SUSPEX_FUNC_KERNEL_MEM_READ 0x833
#define SUSPEX_FUNC_KERNEL_MEM_WRITE 0x834
#define SUSPEX_FUNC_PHYS_MEM_READ 0x835
#define SUSPEX_FUNC_PHYS_MEM_WRITE 0x836
#define SUSPEX_FUNC_USER_ALLOC 0x840
#define SUSPEX_FUNC_USER_FREE 0x841
#define SUSPEX_FUNC_USER_PROTECT 0x842
#define SUSPEX_FUNC_KMEM_ALLOC 0x843
#define SUSPEX_FUNC_KMEM_FREE 0x844
#define SUSPEX_FUNC_USER_MODULES 0x850
#define SUSPEX_FUNC_KERNEL_MODULES 0x851
#define SUSPEX_FUNC_PROCESS_LIST 0x852
#define SUSPEX_FUNC_VAD_LIST 0x853
#define SUSPEX_FUNC_HANDLE_LIST 0x854
#define SUSPEX_FUNC_PHYS_RANGES 0x855 // v4: enumerate MmGetPhysicalMemoryRanges
#define SUSPEX_FUNC_POOL_SCAN 0x856   // v4: SystemBigPoolInformation walk + filter
#define SUSPEX_FUNC_VA_TRANSLATE 0x857 // v5: walk current CR3 page tables (Va -> Pa)
#define SUSPEX_FUNC_CTX_GET 0x860
#define SUSPEX_FUNC_CTX_SET 0x861
#define SUSPEX_FUNC_BP_SW_SET 0x870
#define SUSPEX_FUNC_BP_SW_CLEAR 0x871
#define SUSPEX_FUNC_BP_HW_SET 0x872
#define SUSPEX_FUNC_BP_HW_CLEAR 0x873
#define SUSPEX_FUNC_BP_LIST 0x874
#define SUSPEX_FUNC_REMOTE_CALL 0x880
// v8: wedge-detector watchdog. See "Watchdog" section below for struct
// layouts and the DriverEntry-spawned worker's contract.
#define SUSPEX_FUNC_WATCHDOG_ARM    0x890
#define SUSPEX_FUNC_WATCHDOG_KICK   0x891
#define SUSPEX_FUNC_WATCHDOG_DISARM 0x892
#define SUSPEX_FUNC_WATCHDOG_LIST   0x893
// v10: notify event ring + kernel object/thread enumeration
#define SUSPEX_FUNC_NOTIFY_SUBSCRIBE 0x8A0
#define SUSPEX_FUNC_NOTIFY_READ      0x8A1
#define SUSPEX_FUNC_NOTIFY_DISABLE   0x8A2
#define SUSPEX_FUNC_NOTIFY_STATS     0x8A3
#define SUSPEX_FUNC_OBJ_ENUM         0x8A4
#define SUSPEX_FUNC_THREAD_LIST      0x8A5
// v12: per-CPU IDT enumeration (driver decodes KIDTENTRY64 rows)
#define SUSPEX_FUNC_IDT_LIST         0x8A6
// v13: synchronous kernel function call (WDF work item at PASSIVE_LEVEL)
#define SUSPEX_FUNC_KERNEL_CALL      0x8B0

#define SUSPEX_IOCTL(func, method, access) CTL_CODE(SUSPEX_DEVICE_TYPE, func, method, access)

#define SUSPEX_IOCTL_PING SUSPEX_IOCTL(SUSPEX_FUNC_PING, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_MEM_READ SUSPEX_IOCTL(SUSPEX_FUNC_USER_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_MEM_WRITE SUSPEX_IOCTL(SUSPEX_FUNC_USER_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KERNEL_MEM_READ SUSPEX_IOCTL(SUSPEX_FUNC_KERNEL_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KERNEL_MEM_WRITE SUSPEX_IOCTL(SUSPEX_FUNC_KERNEL_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_PHYS_MEM_READ SUSPEX_IOCTL(SUSPEX_FUNC_PHYS_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_PHYS_MEM_WRITE SUSPEX_IOCTL(SUSPEX_FUNC_PHYS_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_ALLOC SUSPEX_IOCTL(SUSPEX_FUNC_USER_ALLOC, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_FREE SUSPEX_IOCTL(SUSPEX_FUNC_USER_FREE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_PROTECT SUSPEX_IOCTL(SUSPEX_FUNC_USER_PROTECT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KMEM_ALLOC SUSPEX_IOCTL(SUSPEX_FUNC_KMEM_ALLOC, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KMEM_FREE SUSPEX_IOCTL(SUSPEX_FUNC_KMEM_FREE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_USER_MODULES SUSPEX_IOCTL(SUSPEX_FUNC_USER_MODULES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KERNEL_MODULES SUSPEX_IOCTL(SUSPEX_FUNC_KERNEL_MODULES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_PROCESS_LIST SUSPEX_IOCTL(SUSPEX_FUNC_PROCESS_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_VAD_LIST SUSPEX_IOCTL(SUSPEX_FUNC_VAD_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_HANDLE_LIST SUSPEX_IOCTL(SUSPEX_FUNC_HANDLE_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_PHYS_RANGES SUSPEX_IOCTL(SUSPEX_FUNC_PHYS_RANGES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_POOL_SCAN SUSPEX_IOCTL(SUSPEX_FUNC_POOL_SCAN, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_VA_TRANSLATE SUSPEX_IOCTL(SUSPEX_FUNC_VA_TRANSLATE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_CTX_GET SUSPEX_IOCTL(SUSPEX_FUNC_CTX_GET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_CTX_SET SUSPEX_IOCTL(SUSPEX_FUNC_CTX_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_BP_SW_SET SUSPEX_IOCTL(SUSPEX_FUNC_BP_SW_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_BP_SW_CLEAR SUSPEX_IOCTL(SUSPEX_FUNC_BP_SW_CLEAR, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_BP_HW_SET SUSPEX_IOCTL(SUSPEX_FUNC_BP_HW_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_BP_HW_CLEAR SUSPEX_IOCTL(SUSPEX_FUNC_BP_HW_CLEAR, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_BP_LIST SUSPEX_IOCTL(SUSPEX_FUNC_BP_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_REMOTE_CALL SUSPEX_IOCTL(SUSPEX_FUNC_REMOTE_CALL, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_WATCHDOG_ARM    SUSPEX_IOCTL(SUSPEX_FUNC_WATCHDOG_ARM,    METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_WATCHDOG_KICK   SUSPEX_IOCTL(SUSPEX_FUNC_WATCHDOG_KICK,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_WATCHDOG_DISARM SUSPEX_IOCTL(SUSPEX_FUNC_WATCHDOG_DISARM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_WATCHDOG_LIST   SUSPEX_IOCTL(SUSPEX_FUNC_WATCHDOG_LIST,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_NOTIFY_SUBSCRIBE SUSPEX_IOCTL(SUSPEX_FUNC_NOTIFY_SUBSCRIBE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_NOTIFY_READ      SUSPEX_IOCTL(SUSPEX_FUNC_NOTIFY_READ,      METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_NOTIFY_DISABLE   SUSPEX_IOCTL(SUSPEX_FUNC_NOTIFY_DISABLE,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_NOTIFY_STATS     SUSPEX_IOCTL(SUSPEX_FUNC_NOTIFY_STATS,     METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_OBJ_ENUM         SUSPEX_IOCTL(SUSPEX_FUNC_OBJ_ENUM,         METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_THREAD_LIST      SUSPEX_IOCTL(SUSPEX_FUNC_THREAD_LIST,      METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_IDT_LIST         SUSPEX_IOCTL(SUSPEX_FUNC_IDT_LIST,         METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define SUSPEX_IOCTL_KERNEL_CALL      SUSPEX_IOCTL(SUSPEX_FUNC_KERNEL_CALL,      METHOD_BUFFERED,  FILE_ANY_ACCESS)

// ping flags
#define SUSPEX_FLAG_TESTSIGNING 0x1
#define SUSPEX_FLAG_HVCI 0x2
#define SUSPEX_FLAG_SECUREBOOT 0x4
#define SUSPEX_FLAG_KERNEL_DEBUGGER 0x8

typedef struct _SUSPEX_PING_OUT {
    UINT32 VersionMajor;
    UINT32 VersionMinor;
    UINT32 NtBuild;
    UINT32 Flags;
    UINT32 AbiVersion;
    UINT32 Reserved;
} SUSPEX_PING_OUT, *PSUSPEX_PING_OUT;

#define SUSPEX_MEM_FLAG_ALLOW_SOFTFAULT 0x1 // kernel read: soft-fault non-resident PAGEDATA
// v6, bit 1: kernel read walks the range per-4KB and returns whatever
// pages MmCopyMemory can serve. First failure stops the walk; caller
// gets STATUS_PARTIAL_COPY with *Done set to the valid prefix length.
// Fixes the "pool sweep fails atomically on an unmapped hole" workflow.
#define SUSPEX_MEM_FLAG_PARTIAL 0x2
// v5, bit 2: physical write opts into the MmMapIoSpaceEx write path. Default
// OFF = clean refusal; when set, unmappable pages are skipped per-4KB and the
// caller sees STATUS_PARTIAL_COPY with Done < Size instead of a hard abort.
#define SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE 0x4

typedef struct _SUSPEX_MEM_REQ {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size; // in: capacity, out: bytes transferred
    UINT32 Flags; // SUSPEX_MEM_FLAG_* (appended in ABI v2; old drivers ignore)
    UINT32 Reserved;
} SUSPEX_MEM_REQ, *PSUSPEX_MEM_REQ;

// ------------------------------------------------------------------ v12 ----
// Extended write header. First 32 bytes are wire-identical to
// SUSPEX_MEM_REQ; the old Reserved slot carries SUSPEX_MEM_WRITE_EXT_MAGIC,
// which is how a v12 driver tells "[32B legacy hdr][payload]" apart from
// "[48B ext hdr][payload]" — an old sender writes Reserved=0 there, never
// the magic. When the marker is present the payload starts at offset 48
// and Cr3/Flags2 apply; otherwise payload starts at 32 and the write is
// legacy-shaped. Input stays METHOD_BUFFERED.
#define SUSPEX_MEM_WRITE_EXT_MAGIC 0x33574D45u  // 'EMW3' little-endian

typedef struct _SUSPEX_MEM_WRITE_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size;      // declared payload size (wire payload may be shorter)
    UINT32 Flags;     // SUSPEX_MEM_FLAG_* (same slot as SUSPEX_MEM_REQ)
    UINT32 ExtLayout; // SUSPEX_MEM_WRITE_EXT_MAGIC (was SUSPEX_MEM_REQ.Reserved)
    UINT64 Cr3;       // foreign address space for KERNEL writes; 0 = current
    UINT32 Flags2;    // SUSPEX_MEM_WRF_*
    UINT32 Reserved;
} SUSPEX_MEM_WRITE_IN, *PSUSPEX_MEM_WRITE_IN;   // 48 bytes

// Flags2 bits (the original Flags slot stays SUSPEX_MEM_FLAG_* for
// read/phys-write semantics).
// STRICT_VA (kernel write): never fall back to the physical-remap path on
// a direct-VA fault — return STATUS_INVALID_ADDRESS instead. The fallback
// walks the page tables and writes through MmMapIoSpace, which bypasses
// the linear address entirely: DR watchpoints / EPT hooks on the target
// VA do not see the store. Callers that care about write observability
// opt out of the silent escape hatch.
#define SUSPEX_MEM_WRF_STRICT_VA 0x1

// WritePath report (SUSPEX_MEM_WRITE_OUT.WritePath; proto write_path).
#define SUSPEX_MEM_WRITE_PATH_UNKNOWN     0 // pre-v12 peer, or no reply path
#define SUSPEX_MEM_WRITE_PATH_DIRECT_VA   1 // RtlCopyMemory on the target VA
#define SUSPEX_MEM_WRITE_PATH_PHYS_REMAP  2 // page-walk + physical map
#define SUSPEX_MEM_WRITE_PATH_FOREIGN_CR3 3 // direct VA under request CR3

// Optional reply for the extended write. When the caller's DeviceIoControl
// carries an output buffer >= 16 bytes the driver always completes
// STATUS_SUCCESS and reports the op result here — even a failed write then
// returns Done/WritePath instead of collapsing to a bare NTSTATUS
// (mirrors the v10.2 lesson: a warning NTSTATUS breaks DeviceIoControl
// delivery). Callers without an output buffer keep the legacy contract
// (NTSTATUS + bytesReturned = Done).
typedef struct _SUSPEX_MEM_WRITE_OUT {
    UINT32 Status;    // NTSTATUS of the write itself
    UINT8  WritePath; // SUSPEX_MEM_WRITE_PATH_*
    UINT8  Reserved[3];
    UINT64 Done;      // bytes actually written
} SUSPEX_MEM_WRITE_OUT, *PSUSPEX_MEM_WRITE_OUT; // 16 bytes

typedef struct _SUSPEX_USER_ALLOC_IN {
    UINT64 Pid;
    UINT64 Size;
    UINT32 Protect; // PAGE_*
    UINT32 Reserved;
} SUSPEX_USER_ALLOC_IN, *PSUSPEX_USER_ALLOC_IN;

typedef struct _SUSPEX_USER_ALLOC_OUT {
    UINT32 Status; // NTSTATUS
    UINT32 Reserved;
    UINT64 Address;
} SUSPEX_USER_ALLOC_OUT, *PSUSPEX_USER_ALLOC_OUT;

typedef struct _SUSPEX_USER_FREE_IN {
    UINT64 Pid;
    UINT64 Address; // region base as returned by USER_ALLOC
} SUSPEX_USER_FREE_IN, *PSUSPEX_USER_FREE_IN;

typedef struct _SUSPEX_USER_FREE_OUT {
    UINT32 Status;
    UINT32 Reserved;
} SUSPEX_USER_FREE_OUT, *PSUSPEX_USER_FREE_OUT;

typedef struct _SUSPEX_USER_PROTECT_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size;
    UINT32 Protect;
    UINT32 Reserved;
} SUSPEX_USER_PROTECT_IN, *PSUSPEX_USER_PROTECT_IN;

typedef struct _SUSPEX_USER_PROTECT_OUT {
    UINT32 Status;
    UINT32 OldProtect;
} SUSPEX_USER_PROTECT_OUT, *PSUSPEX_USER_PROTECT_OUT;

typedef struct _SUSPEX_KMEM_ALLOC_IN {
    UINT64 Size;
} SUSPEX_KMEM_ALLOC_IN, *PSUSPEX_KMEM_ALLOC_IN;

typedef struct _SUSPEX_KMEM_ALLOC_OUT {
    UINT32 Status;
    UINT32 Reserved;
    UINT64 Address;
} SUSPEX_KMEM_ALLOC_OUT, *PSUSPEX_KMEM_ALLOC_OUT;

typedef struct _SUSPEX_KMEM_FREE_IN {
    UINT64 Address; // must come from KMEM_ALLOC
} SUSPEX_KMEM_FREE_IN, *PSUSPEX_KMEM_FREE_IN;

typedef struct _SUSPEX_KMEM_FREE_OUT {
    UINT32 Status;
    UINT32 Reserved;
} SUSPEX_KMEM_FREE_OUT, *PSUSPEX_KMEM_FREE_OUT;

#define SUSPEX_MOD_NAME_CCH 96
#define SUSPEX_MOD_PATH_CCH 192
#define SUSPEX_MAX_MODULES 1024

typedef struct _SUSPEX_MODULE_ENTRY {
    UINT64 Base;
    UINT64 Size;
    WCHAR Name[SUSPEX_MOD_NAME_CCH];
    WCHAR Path[SUSPEX_MOD_PATH_CCH];
} SUSPEX_MODULE_ENTRY, *PSUSPEX_MODULE_ENTRY;

#define SUSPEX_MOD_FLAG_WOW64 0x1 // walk the 32-bit PEB Ldr list (WoW64 target)

typedef struct _SUSPEX_MODULES_IN {
    UINT64 Pid;      // user-mode walk only
    UINT32 Capacity; // caller-provided entry capacity (informational)
    UINT32 Kernel;   // 1 = PsLoadedModuleList walk, Pid ignored
    UINT32 Flags;    // SUSPEX_MOD_FLAG_* (WoW64 walk when set)
    UINT32 Reserved;
} SUSPEX_MODULES_IN, *PSUSPEX_MODULES_IN;

typedef struct _SUSPEX_MODULES_HDR {
    UINT32 Status;     // NTSTATUS of the walk (partial data possible)
    UINT32 Count;      // entries written after this header
    UINT32 Required;   // total modules found
    UINT32 Reserved;
} SUSPEX_MODULES_HDR, *PSUSPEX_MODULES_HDR;

// process enumeration (kernel-side ZwQuerySystemInformation walk)
#define SUSPEX_PROC_NAME_CCH 64

typedef struct _SUSPEX_PROC_ENTRY {
    UINT32 Pid;
    UINT32 ParentPid;
    WCHAR ImageName[SUSPEX_PROC_NAME_CCH];
} SUSPEX_PROC_ENTRY, *PSUSPEX_PROC_ENTRY;

typedef struct _SUSPEX_PROC_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} SUSPEX_PROC_LIST_HDR, *PSUSPEX_PROC_LIST_HDR;

// VAD enumeration (driver walks EPROCESS->VadRoot; build-gated offsets)
#define SUSPEX_VAD_TYPE_NONE 0
#define SUSPEX_VAD_TYPE_MAPPED 1
#define SUSPEX_VAD_TYPE_SECTION 2
#define SUSPEX_VAD_TYPE_SUBSECTION 3
#define SUSPEX_VAD_TYPE_LARGE_PAGES 4

typedef struct _SUSPEX_VAD_ENTRY {
    UINT64 StartVA;   // inclusive
    UINT64 EndVA;     // exclusive
    UINT32 Protect;   // Win32 PAGE_* (guard/nocache variants included)
    UINT32 VadType;   // SUSPEX_VAD_TYPE_*
    UINT64 CommitCharge;
    UINT64 Reserved;
} SUSPEX_VAD_ENTRY, *PSUSPEX_VAD_ENTRY;

typedef struct _SUSPEX_VAD_IN {
    UINT64 Pid;
    UINT32 Flags; // reserved
    UINT32 Reserved;
} SUSPEX_VAD_IN, *PSUSPEX_VAD_IN;

typedef struct _SUSPEX_VAD_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} SUSPEX_VAD_HDR, *PSUSPEX_VAD_HDR;

// handle-table enumeration (SystemExtendedHandleInformation walk filtered by pid)
#define SUSPEX_HANDLE_TYPE_CCH 24
#define SUSPEX_HANDLE_NAME_CCH 96

typedef struct _SUSPEX_HANDLE_ENTRY {
    UINT64 Object;
    UINT64 HandleValue;
    UINT32 GrantedAccess;
    UINT32 ObjectTypeIndex;
    UINT32 Reserved;
    WCHAR TypeName[SUSPEX_HANDLE_TYPE_CCH];
    WCHAR Name[SUSPEX_HANDLE_NAME_CCH];
} SUSPEX_HANDLE_ENTRY, *PSUSPEX_HANDLE_ENTRY;

typedef struct _SUSPEX_HANDLE_IN {
    UINT64 Pid;
    UINT32 WantNames; // 1 = resolve object names (slow; skips File objects)
    UINT32 Reserved;
} SUSPEX_HANDLE_IN, *PSUSPEX_HANDLE_IN;

typedef struct _SUSPEX_HANDLE_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} SUSPEX_HANDLE_HDR, *PSUSPEX_HANDLE_HDR;

// x64 CONTEXT is 1232 bytes, 16-aligned; stored as raw bytes here so the ABI
// header stays OS-header-free. Both sides copy through a CONTEXT-aligned local.
#define SUSPEX_CONTEXT_SIZE 1232

typedef struct _SUSPEX_CTX_HDR_IN {
    UINT64 Tid;
    UINT32 Flags; // CONTEXT_* mask
    UINT32 Reserved;
} SUSPEX_CTX_HDR_IN, *PSUSPEX_CTX_HDR_IN;

// v2 CTX_SET combined input layout (METHOD_BUFFERED, like the mem writes):
//   input  = [SUSPEX_CTX_HDR_IN][UCHAR Context[SUSPEX_CONTEXT_SIZE]]
//   output = SUSPEX_CTX_HDR_OUT (driver fills Status; Flags echoes in.Flags)
// v1 passed the CONTEXT through lpOutBuffer, which METHOD_BUFFERED never
// delivers to the driver, and took the flags from the wrong buffer offset â€”
// the operation silently applied nothing.
typedef struct _SUSPEX_CTX_HDR_OUT {
    UINT32 Status;
    UINT32 Flags;
    UCHAR Context[SUSPEX_CONTEXT_SIZE];
} SUSPEX_CTX_HDR_OUT, *PSUSPEX_CTX_HDR_OUT;

// breakpoints
#define SUSPEX_BP_KIND_SW 0
#define SUSPEX_BP_KIND_HW 1
#define SUSPEX_HW_EXEC 0
#define SUSPEX_HW_WRITE 1
#define SUSPEX_HW_RW 2
#define SUSPEX_MAX_BP 64

typedef struct _SUSPEX_BP_SW_SET_IN {
    UINT64 Pid;
    UINT64 Address;
} SUSPEX_BP_SW_SET_IN, *PSUSPEX_BP_SW_SET_IN;

typedef struct _SUSPEX_BP_SW_SET_OUT {
    UINT32 Status;
    UINT32 Id;
    UCHAR OrigByte;
    UCHAR Reserved[3];
} SUSPEX_BP_SW_SET_OUT, *PSUSPEX_BP_SW_SET_OUT;

typedef struct _SUSPEX_BP_SW_CLEAR_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT32 Id; // 0: match by pid+address, else by id
    UINT32 Reserved;
} SUSPEX_BP_SW_CLEAR_IN, *PSUSPEX_BP_SW_CLEAR_IN;

// v6 flag bits on SUSPEX_BP_HW_SET_IN.Reserved (renamed Flags).
// GLOBAL: Pid=0 arms every thread of every process AND
// PsSetCreateThreadNotifyRoutine catches newborns regardless of parent
// pid. Two-slot cap enforced by the driver to prevent DR starvation.
// DANGEROUS_OK: skip the PatchGuard-expected refusal (kd/lab-only VMs).
#define SUSPEX_BP_HW_FLAG_GLOBAL 0x1
#define SUSPEX_BP_HW_FLAG_DANGEROUS_OK 0x2

typedef struct _SUSPEX_BP_HW_SET_IN {
    UINT64 Pid;
    UINT64 Tid;     // 0 = all threads of Pid; Pid=0 + FLAG_GLOBAL = every thread system-wide
    UINT64 Address;
    UINT32 Slot;    // 0..3
    UINT32 Length;  // 1,2,4,8
    UINT32 Access;  // SUSPEX_HW_*
    UINT32 Flags;   // SUSPEX_BP_HW_FLAG_* (was Reserved pre-v6; old drivers ignored)
} SUSPEX_BP_HW_SET_IN, *PSUSPEX_BP_HW_SET_IN;

typedef struct _SUSPEX_BP_HW_SET_OUT {
    UINT32 Status;
    UINT32 Id;
    UINT32 ThreadsPatched;
    UINT32 Reserved;
} SUSPEX_BP_HW_SET_OUT, *PSUSPEX_BP_HW_SET_OUT;

typedef struct _SUSPEX_BP_HW_CLEAR_IN {
    UINT64 Pid;
    UINT64 Tid;
    UINT32 Slot;
    UINT32 Reserved;
} SUSPEX_BP_HW_CLEAR_IN, *PSUSPEX_BP_HW_CLEAR_IN;

typedef struct _SUSPEX_BP_HW_CLEAR_OUT {
    UINT32 Status;
    UINT32 ThreadsPatched;
} SUSPEX_BP_HW_CLEAR_OUT, *PSUSPEX_BP_HW_CLEAR_OUT;

typedef struct _SUSPEX_BP_ENTRY {
    UINT32 Id;
    UINT32 Kind;
    UINT32 Pid;
    UINT32 Tid;
    UINT32 Slot;
    UINT32 Length;
    UINT32 Access;
    UINT32 Enabled;
    UINT64 Address;
    UCHAR OrigByte;
    UCHAR Reserved[7];
} SUSPEX_BP_ENTRY, *PSUSPEX_BP_ENTRY;

typedef struct _SUSPEX_BP_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} SUSPEX_BP_LIST_HDR, *PSUSPEX_BP_LIST_HDR;

typedef struct _SUSPEX_REMOTE_CALL_IN {
    UINT64 Pid;
    UINT64 Tid;
    UINT64 Target; // user-mode function address, or kernel address w/ SUSPEX_RC_FLAG_KERNEL
    UINT64 Arg1;   // rcx (user) / NormalContext (kernel)
    UINT64 Arg2;   // rdx (user) / SystemArgument1 (kernel)
    UINT64 Arg3;   // r8  (user) / SystemArgument2 (kernel)
    UINT32 Flags;  // SUSPEX_RC_FLAG_*
    UINT32 Reserved;
} SUSPEX_REMOTE_CALL_IN, *PSUSPEX_REMOTE_CALL_IN;

#define SUSPEX_RC_FLAG_KERNEL 0x1 // kernel-mode APC: NormalRoutine = Target runs in kernel

typedef struct _SUSPEX_REMOTE_CALL_OUT {
    UINT32 Status;
    UINT32 Queued;
    UINT32 Alerted;
    UINT32 Reserved;
} SUSPEX_REMOTE_CALL_OUT, *PSUSPEX_REMOTE_CALL_OUT;

// v4: MmGetPhysicalMemoryRanges enumeration. Input is empty; output is a
// SUSPEX_PHYS_RANGES_HDR followed by Count SUSPEX_PHYS_RANGE_ENTRY entries.
// The driver re-queries per call so hotplug RAM (VM balloon, PCIe MMIO
// resize) is reflected. Total system-RAM = sum(Size for Kind=Ram).
#define SUSPEX_MAX_PHYS_RANGES 128

#define SUSPEX_PHYS_KIND_RAM 0

typedef struct _SUSPEX_PHYS_RANGE_ENTRY {
    UINT64 Base; // physical byte address
    UINT64 Size; // bytes
    UINT32 Kind; // SUSPEX_PHYS_KIND_* (currently only RAM; kept for MMIO/ROM later)
    UINT32 Reserved;
} SUSPEX_PHYS_RANGE_ENTRY, *PSUSPEX_PHYS_RANGE_ENTRY;

typedef struct _SUSPEX_PHYS_RANGES_HDR {
    UINT32 Status;
    UINT32 Count;      // entries written after this header
    UINT32 Required;   // total ranges available (may exceed Count)
    UINT32 Reserved;
} SUSPEX_PHYS_RANGES_HDR, *PSUSPEX_PHYS_RANGES_HDR;

// v4: SystemBigPoolInformation walk + optional tag/content filter.
// The kernel's SystemBigPoolInformation only lists >4KB "big pool"
// allocations (single-page LFH lumps are opaque on modern builds); this
// is still exactly the surface interesting to driver RE (large device
// buffers, MDL-backed IO blocks, EDID caches etc.).
//
// Filter semantics: an entry is returned if
//   (TagFilter == 0 OR entry.Tag == TagFilter)
//   AND (PatternLen == 0
//        OR memmem(read(entry.VA + Offset, ContentSpan), Pattern) hits).
// PatternLen<=16, ContentSpan<=4096 (compute+alloc budget). If Pattern is
// set and the entry read fails, the entry is silently skipped (a hole is
// not evidence).

#define SUSPEX_POOL_MAX_ENTRIES 4096
// v1.0.1 Phase 3.2: pattern cap raised 16 -> 64 B, span cap 4 KiB -> 64 KiB.
// Older builds hit the smaller caps as STATUS_INVALID_PARAMETER; new ones
// still accept the smaller sizes.
#define SUSPEX_POOL_PATTERN_MAX 64
#define SUSPEX_POOL_CONTENT_SPAN_MAX (64u * 1024u)

#define SUSPEX_POOL_FLAG_NONPAGED_ONLY 0x1
#define SUSPEX_POOL_FLAG_PAGED_ONLY    0x2

typedef struct _SUSPEX_POOL_SCAN_IN {
    UINT32 TagFilter;    // 4-char tag as UINT32, or 0 for any
    UINT32 Flags;        // SUSPEX_POOL_FLAG_*
    UINT32 MaxResults;   // clamped to SUSPEX_POOL_MAX_ENTRIES
    UINT32 PatternLen;   // 0 = no content filter
    UINT32 ContentSpan;  // bytes to read+scan starting at VA+Offset; 0 = whole
    UINT32 Offset;       // start of the content window inside the entry
    UCHAR  Pattern[SUSPEX_POOL_PATTERN_MAX];
    UCHAR  Mask[SUSPEX_POOL_PATTERN_MAX]; // 0 or '?' = wildcard byte
    // v1.0.1 Phase 3.2: resume index. 0 = fresh scan; otherwise the driver
    // skips entries whose SystemBigPoolInformation index is below the
    // cursor and writes the next cursor into the HDR for the follow-up
    // call. The pool table isn't guaranteed stable across calls — treat
    // cursored scans as "snapshot-ish" and expect new allocations to
    // appear only on fresh calls.
    UINT32 Cursor;
} SUSPEX_POOL_SCAN_IN, *PSUSPEX_POOL_SCAN_IN;

typedef struct _SUSPEX_POOL_ENTRY {
    UINT64 VirtualAddress;
    UINT64 SizeInBytes;
    UINT32 Tag;
    UINT32 NonPaged;      // 1 = non-paged pool, 0 = paged
    UINT64 MatchedOffset; // when PatternLen > 0, absolute VA of the match; else 0
} SUSPEX_POOL_ENTRY, *PSUSPEX_POOL_ENTRY;

typedef struct _SUSPEX_POOL_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;    // total entries the walk saw before filter
    UINT32 Considered;  // total entries after tag/paged filter, before content
    // v1.0.1 Phase 3.2: scan telemetry. `Holes` counts entries whose content
    // read failed (previously silently skipped), `SpanTruncated` counts
    // entries whose content span had to be clipped to the entry size,
    // `LastIndex` is the AllocatedInfo index the driver reached, and
    // `NextCursor` is 0 when the scan completed, else the cursor to pass
    // on the next call.
    UINT32 Holes;
    UINT32 SpanTruncated;
    UINT32 LastIndex;
    UINT32 NextCursor;
} SUSPEX_POOL_HDR, *PSUSPEX_POOL_HDR;

// v5: VA -> PA via the driver's page-table walk (SuspxTranslateVa, current
// CR3 context). Exposed so gates/tests can locate the physical backing of a
// kernel VA (e.g. a KMEM_ALLOC result) without poking at live RAM blindly.
// v12: IN grows Cr3 + Pid (walk under an explicit CR3, or a target
// process's tables via KeStackAttachProcess — the deferred v7 USER-space
// feature). OUT grows PageSizeShift + Cr3 (which CR3 the walk used).
// Both directions degrade cleanly: a v12 caller's 24-byte IN satisfies the
// v11 driver's 16-byte minimum (extra tail ignored -> legacy walk); a v12
// driver fills only the caller's OUT prefix (16-byte caller -> legacy
// reply, PageSizeShift/Cr3 stay zero client-side).
typedef struct _SUSPEX_VA_TRANSLATE_IN {
    UINT64 Va;
    UINT64 Cr3;  // v12 (bytes 8..15 were Reserved[2] pre-v12, always 0 —
                 // a legacy request therefore reads as Cr3=0 = "current")
    UINT64 Pid;  // v12: process whose tables are walked (USER space);
                 // 0 = caller context / system for kernel VAs
} SUSPEX_VA_TRANSLATE_IN, *PSUSPEX_VA_TRANSLATE_IN;

typedef struct _SUSPEX_VA_TRANSLATE_OUT {
    UINT32 Status;        // NTSTATUS of the walk (STATUS_INVALID_ADDRESS when unmapped)
    UINT32 PageSizeShift; // v12 (was Reserved): 12/21/30 for the leaf that
                          // mapped VA; 0 on failure or a v11 driver
    UINT64 PhysicalAddress;
    UINT64 Cr3;           // v12: CR3 the walk actually ran under
} SUSPEX_VA_TRANSLATE_OUT, *PSUSPEX_VA_TRANSLATE_OUT;

// ------------------------------------------------------------------ v12 ----
// Per-CPU IDT enumeration. The driver parks on each requested processor
// (GROUP_AFFINITY, the BpTrap.c pattern), __sidt's it, and decodes the
// KIDTENTRY64 gate descriptors itself — no agent-side kernel reads needed
// per entry. Output is [SUSPEX_IDT_LIST_HDR][Count x SUSPEX_IDT_ENTRY_ROW];
// Required is the total row count across all CPUs so a truncated caller
// can size the retry. Each row carries the IDTR.Base it was read from:
// KIDT is per-processor on x64, and a per-CPU base drift is a real detour
// signature worth keeping per-row.

#define SUSPEX_IDT_VECTORS      256
#define SUSPEX_IDT_MAX_CPUS     64
#define SUSPEX_IDT_MAX_ENTRIES  (SUSPEX_IDT_VECTORS * SUSPEX_IDT_MAX_CPUS)

typedef struct _SUSPEX_IDT_LIST_IN {
    UINT32 AllCpus;  // 0 = only the CPU servicing this request
    UINT32 Reserved;
} SUSPEX_IDT_LIST_IN, *PSUSPEX_IDT_LIST_IN;

typedef struct _SUSPEX_IDT_ENTRY_ROW {
    UINT32 Cpu;       // processor index the row was read on
    UINT32 Vector;    // 0..255
    UINT64 HandlerVa; // decoded offset_lo|mid|hi
    UINT32 Selector;
    UINT32 Ist;
    UINT32 Dpl;
    UINT32 Type;      // 5-bit gate type field
    UINT32 Present;   // P bit
    UINT32 Reserved;  // alignment pad ahead of IdtBase
    UINT64 IdtBase;   // IDTR.Base of that CPU
} SUSPEX_IDT_ENTRY_ROW, *PSUSPEX_IDT_ENTRY_ROW; // 48 bytes

typedef struct _SUSPEX_IDT_LIST_HDR {
    UINT32 Status;    // NTSTATUS of the walk
    UINT32 Count;     // rows written after this header
    UINT32 Required;  // total rows across all CPUs
    UINT32 IdtLimit;  // IDTR.Limit of the first CPU read
    UINT64 IdtBase;   // IDTR.Base of the first CPU read
} SUSPEX_IDT_LIST_HDR, *PSUSPEX_IDT_LIST_HDR;   // 24 bytes

// ------------------------------------------------------------ kernel call ----
// v13: synchronous kernel function call. The driver runs Target inside a
// WDF work item at PASSIVE_LEVEL in System context, guarded by __try/__except
// (rax + exception capture), and parks the IOCTL thread on a KEVENT until the
// thunk signals or the caller's timeout expires.
//
// Contract:
//   * Target must be a canonical kernel VA unless SUSPEX_KC_FLAG_FORCE is set
//     (pool-resident / non-module code) — the driver refuses otherwise.
//   * Argc <= SUSPEX_KC_MAX_ARGS; x64 fastcall ignores surplus register/stack
//     args, so thunking a fixed 16-arg signature covers Argc 0..16. Args[0..3]
//     go to rcx/rdx/r8/r9, Args[4..15] to the stack in ms64 order.
//   * Only rax (ReturnValue) is captured — rdx:rax/struct returns out of scope.
//   * Caller wait is TimeoutMs (0 = 30000). On timeout the call returns
//     STATUS_TIMEOUT and the target thread keeps running; the slot stays Busy
//     and later calls report STATUS_DEVICE_BUSY until the thunk finishes.
//   * PASSIVE_LEVEL, System context only — APC/DISPATCH-only target routines
//     are out of contract.

#define SUSPEX_KC_MAX_ARGS 16
#define SUSPEX_KC_FLAG_FORCE      0x1 // skip canonical-VA refusal (pool-resident code)
#define SUSPEX_KC_FLAG_VALIDATED  0x2 // informational: agent pre-checked module range

typedef struct _SUSPEX_KERNEL_CALL_IN {
    UINT64 Target;
    UINT32 Argc;                    // <= SUSPEX_KC_MAX_ARGS
    UINT32 Flags;                   // SUSPEX_KC_FLAG_*
    UINT64 Args[SUSPEX_KC_MAX_ARGS];
    UINT32 TimeoutMs;               // 0 = 30000
    UINT32 Reserved[3];
} SUSPEX_KERNEL_CALL_IN, *PSUSPEX_KERNEL_CALL_IN;
C_ASSERT(sizeof(SUSPEX_KERNEL_CALL_IN) == 8 + 4 + 4 + 128 + 4 + 12); // 160

typedef struct _SUSPEX_KERNEL_CALL_OUT {
    UINT32 Status;                  // NTSTATUS of the call operation itself
    UINT32 Completed;               // 1 = target ran to return
    UINT32 Exception;               // 1 = SEH caught inside the call
    UINT32 ExceptionCode;           // GetExceptionCode() when Exception=1
    UINT64 ReturnValue;             // rax
} SUSPEX_KERNEL_CALL_OUT, *PSUSPEX_KERNEL_CALL_OUT;
C_ASSERT(sizeof(SUSPEX_KERNEL_CALL_OUT) == 24);

// --------------------------------------------------------------- Watchdog ----
// v8/v8.1: wedge-detector. A driver-owned 8-slot table holds absolute
// QPC-microsecond deadlines; on the first deadline that passes without a
// KICK, the driver calls
//   KeBugCheckEx(SUSPEX_BUGCHECK_MANUALLY_INITIATED,
//                Id, DeadlineUs, LastKickUs, Cookie)
// so the resulting dump self-identifies as a watchdog fire under
// `!analyze -v` — Arg1..Arg4 carry the slot's provenance directly.
//
// Runner: v8 used a HIGH_PRIORITY system thread; v8.1 (SUSPEX_DRV_VERSION_MINOR
// = 1) uses a periodic KTIMER + KDPC at 100 ms so wedges that starve threads
// (dispatcher-lock spins, DPC storms pinning every CPU at DISPATCH+, scheduler
// bugs) still fire — a DPC runs off the per-CPU clock interrupt above the
// thread scheduler. Wire ABI is unchanged; the runner swap is opaque to
// user-mode callers.
//
// Contract:
//   * IDs are caller-chosen non-zero UINT32. ID collision on ARM without
//     SUSPEX_WDG_FLAG_REPLACE returns STATUS_OBJECT_NAME_COLLISION.
//   * DeadlineMs upper-bound = 3_600_000 (1 h). Larger values are refused.
//   * KICK on an unarmed ID returns STATUS_NOT_FOUND — the caller learns
//     their Arm dropped without waiting for a bugcheck.
//   * On-wire evidence of a fire is the MEMORY DUMP: the four KeBugCheckEx
//     args (Id, DeadlineUs, LastKickUs, Cookie), plus a "SuspexDrv WDG FIRE"
//     line captured in the KdPrintCircularBuffer readable via `!dbgprint` in
//     windbg. v8.1 does NOT write "WDG FIRE …" to the on-disk kernel log at
//     fire time (ZwWriteFile is illegal at DISPATCH_LEVEL from the DPC path),
//     so Files.LogTail / target_manage(crash_state) kernel_log_tail no longer
//     carry a fire marker — read the dump instead. (v8 did write on disk from
//     the retired system thread; that path is gone. Arm/Kick/Disarm calls
//     still emit routine on-disk audit lines from PASSIVE_LEVEL.)

#define SUSPEX_WATCHDOG_MAX 8
#define SUSPEX_WDG_MAX_LABEL 32
#define SUSPEX_WDG_MAX_DEADLINE_MS (60u * 60u * 1000u)  // 1 hour

#define SUSPEX_WDG_FLAG_REPLACE 0x1  // overwrite an existing entry with same Id

// Bug-check code the worker uses when it fires. Documented as
// MANUALLY_INITIATED_CRASH (0xE2). Callers may override via BugcheckCode.
#define SUSPEX_BUGCHECK_MANUALLY_INITIATED 0xE2u

typedef struct _SUSPEX_WDG_ARM_IN {
    UINT32 Id;            // caller-chosen; nonzero
    UINT32 DeadlineMs;    // relative deadline from Arm
    UINT32 BugcheckCode;  // 0 = 0xE2 MANUALLY_INITIATED_CRASH
    UINT32 Flags;         // SUSPEX_WDG_FLAG_*
    UINT64 Cookie;        // opaque; passed as the 4th bugcheck arg
    CHAR   Label[SUSPEX_WDG_MAX_LABEL]; // NUL-terminated best-effort tag
} SUSPEX_WDG_ARM_IN, *PSUSPEX_WDG_ARM_IN;

typedef struct _SUSPEX_WDG_ARM_OUT {
    UINT32 Status;
    UINT32 Reserved;
} SUSPEX_WDG_ARM_OUT, *PSUSPEX_WDG_ARM_OUT;

typedef struct _SUSPEX_WDG_KICK_IN {
    UINT32 Id;
    UINT32 DeadlineMs;    // new relative deadline; 0 = keep existing
    UINT64 Cookie;        // new cookie; 0 = keep existing
} SUSPEX_WDG_KICK_IN, *PSUSPEX_WDG_KICK_IN;

typedef struct _SUSPEX_WDG_KICK_OUT {
    UINT32 Status;
    UINT32 Reserved;
    UINT64 KickCount;
    UINT64 LastKickUs;
    UINT64 DeadlineUs;    // absolute QPC-us after this kick
} SUSPEX_WDG_KICK_OUT, *PSUSPEX_WDG_KICK_OUT;

typedef struct _SUSPEX_WDG_DISARM_IN {
    UINT32 Id;
    UINT32 Reserved;
} SUSPEX_WDG_DISARM_IN, *PSUSPEX_WDG_DISARM_IN;

typedef struct _SUSPEX_WDG_DISARM_OUT {
    UINT32 Status;
    UINT32 Reserved;
} SUSPEX_WDG_DISARM_OUT, *PSUSPEX_WDG_DISARM_OUT;

typedef struct _SUSPEX_WDG_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
    UINT64 NowUs;         // driver's QPC-us at read time (compare to DeadlineUs)
} SUSPEX_WDG_LIST_HDR, *PSUSPEX_WDG_LIST_HDR;

typedef struct _SUSPEX_WDG_ENTRY {
    UINT32 Id;
    UINT32 BugcheckCode;
    UINT64 DeadlineUs;
    UINT64 LastKickUs;
    UINT64 KickCount;
    UINT64 Cookie;
    UINT64 ArmedUs;       // when the slot was armed
    CHAR   Label[SUSPEX_WDG_MAX_LABEL];
} SUSPEX_WDG_ENTRY, *PSUSPEX_WDG_ENTRY;

// ------------------------------------------------------------- Notify ring ----
// v10: the agent's "ears". The driver registers kernel notification
// callbacks (process create/exit, thread create/exit, image load — kernel
// images included, so driver loads fall out for free) and appends
// fixed-size records to a static overwrite-oldest ring. The ring lives in
// the driver image (nonpaged); callbacks only take a spinlock and copy, so
// process creation is never stalled. NOTIFY_READ drains oldest-first and
// returns the cumulative dropped counter — a reader that saw seq N and
// later sees LastSeq jump by more than the events delivered knows the ring
// overflowed in between (gap), and `dropped` increasing proves loss.
//
// Classes are subscribed via NOTIFY_SUBSCRIBE (bitmask; 0 = all three) and
// unregistered by NOTIFY_DISABLE and at unload. Registration is refcount-
// free by design: subscribe = kernel-visible state change, so the
// orchestrator gates it like driver_load.

#define SUSPEX_EVT_KIND_PROC_CREATE  1
#define SUSPEX_EVT_KIND_PROC_EXIT    2
#define SUSPEX_EVT_KIND_IMAGE_LOAD   3
#define SUSPEX_EVT_KIND_THREAD_CREATE 4
#define SUSPEX_EVT_KIND_THREAD_EXIT  5
#define SUSPEX_EVT_KIND_BP_HIT       6 // v11: armed HW bp fired (int1 hook)

#define SUSPEX_EVT_CLASS_PROC   0x1
#define SUSPEX_EVT_CLASS_IMAGE  0x2
#define SUSPEX_EVT_CLASS_THREAD 0x4
// v11: DR0-3 breakpoint hits. Subscribing installs the driver's int1
// (IDT vector 1) hook on every CPU — kernel-visible and PatchGuard-
// sensitive, so the class is ignored unless the subscribe call also
// carries SUSPEX_NOTIFY_FLAG_BP_HOOK_OK. Unsubscribed hits chain to the
// original KiTrap01 (unchanged pre-hook behaviour).
#define SUSPEX_EVT_CLASS_BP     0x8
#define SUSPEX_EVT_CLASS_ALL    (SUSPEX_EVT_CLASS_PROC | SUSPEX_EVT_CLASS_IMAGE | SUSPEX_EVT_CLASS_THREAD | SUSPEX_EVT_CLASS_BP)

#define SUSPEX_EVT_RING 1024
#define SUSPEX_EVT_IMAGE_CCH 128

typedef struct _SUSPEX_EVT {
    UINT64 Seq;       // monotonic per-boot, starts at 1
    UINT64 TsMs;      // QPC milliseconds at ring time
    UINT32 Kind;      // SUSPEX_EVT_KIND_*
    UINT32 Pid;
    UINT32 ParentPid; // proc-create only
    UINT32 Tid;       // thread events only
    UINT64 ImageBase; // image-load only
    UINT64 ImageSize; // image-load only
    WCHAR  Image[SUSPEX_EVT_IMAGE_CCH]; // NT path, NUL-truncated
    // ---- v11 tail: BP_HIT payload (zero for other kinds) ----
    UINT64 Address;   // faulting RIP
    UINT64 Dr6;       // raw DR6 snapshot at trap entry
    UINT32 BpId;      // matched suspex bp id (0 when the table lock wasn't taken)
    UINT32 Slot;      // DR slot that fired, 0-3 (0xFF = unresolved)
    UINT32 Access;    // matched bp's SUSPEX_HW_* access (0 when unmatched)
    UINT32 Irql;      // KeGetCurrentIrql() at hit
} SUSPEX_EVT, *PSUSPEX_EVT;

// v11: subscribe Flags (field was Reserved; same wire layout)
#define SUSPEX_NOTIFY_FLAG_BP_HOOK_OK 0x1 // consent for the IDT[1] hook

typedef struct _SUSPEX_NOTIFY_SUBSCRIBE_IN {
    UINT32 Classes;   // SUSPEX_EVT_CLASS_* bitmask; 0 = all
    UINT32 Flags;     // SUSPEX_NOTIFY_FLAG_* (v11; was Reserved)
} SUSPEX_NOTIFY_SUBSCRIBE_IN, *PSUSPEX_NOTIFY_SUBSCRIBE_IN;

typedef struct _SUSPEX_NOTIFY_SUBSCRIBE_OUT {
    UINT32 Status;
    UINT32 Registered; // classes actually registered
} SUSPEX_NOTIFY_SUBSCRIBE_OUT, *PSUSPEX_NOTIFY_SUBSCRIBE_OUT;

typedef struct _SUSPEX_NOTIFY_READ_IN {
    UINT32 Max;       // events to drain (clamped to SUSPEX_EVT_RING)
    UINT32 Reserved;
} SUSPEX_NOTIFY_READ_IN, *PSUSPEX_NOTIFY_READ_IN;

typedef struct _SUSPEX_NOTIFY_READ_HDR {
    UINT32 Status;
    UINT32 Count;     // SUSPEX_EVT records following the header
    UINT64 Dropped;   // overwrite-oldest counter, cumulative since load
    UINT64 LastSeq;   // highest seq in this batch
} SUSPEX_NOTIFY_READ_HDR, *PSUSPEX_NOTIFY_READ_HDR;

typedef struct _SUSPEX_NOTIFY_STATS_OUT {
    UINT32 Status;
    UINT32 Registered;  // SUSPEX_EVT_CLASS_* bitmask actually registered
    UINT32 ProcVariant; // 1 = Ex routine, 2 = classic, 0 = not registered
    UINT32 BpTrapMissed; // v11 (was Reserved): int1 hits consumed without a
                         // ring record (lock contention / teardown window)
    UINT64 Buffered;    // events currently in the ring
    UINT64 Dropped;     // cumulative overwrite-oldest count
    UINT64 Seq;         // highest seq issued
    UINT64 Total;       // cumulative events appended
} SUSPEX_NOTIFY_STATS_OUT, *PSUSPEX_NOTIFY_STATS_OUT;

// ------------------------------------------------------- object enumeration ----
// v10: \Device / \Driver / \FileSystem / \BaseNamedObjects / \Callback /
// \ObjectTypes walk via ZwOpenDirectoryObject + ZwQueryDirectoryObject.
// No _OBJECT_DIRECTORY layout assumptions. Depth is clamped to 2,
// MaxEntries to SUSPEX_OBJ_MAX_ENTRIES; Truncated=1 means the namespace
// had more than the caller's budget (a fact, not an error).

#define SUSPEX_OBJ_PATH_CCH 128
#define SUSPEX_OBJ_NAME_CCH 64
#define SUSPEX_OBJ_MAX_ENTRIES 4096
#define SUSPEX_OBJ_MAX_DEPTH 2

typedef struct _SUSPEX_OBJ_ENUM_IN {
    WCHAR Path[SUSPEX_OBJ_PATH_CCH]; // e.g. L"\Device"; leading '\' required
    UINT32 Depth;                    // 1 = flat, 2 = one subdirectory level
    UINT32 MaxEntries;               // clamped to SUSPEX_OBJ_MAX_ENTRIES
} SUSPEX_OBJ_ENUM_IN, *PSUSPEX_OBJ_ENUM_IN;

typedef struct _SUSPEX_OBJ_ENTRY {
    WCHAR Name[SUSPEX_OBJ_NAME_CCH];
    WCHAR TypeName[SUSPEX_OBJ_NAME_CCH];
    UINT32 IsDirectory; // 1 = object directory (recursed when depth allows)
    // v1.0.1 Phase 3.1: object body VA + type-index resolved via
    // ObpRootDirectoryObject hash-bucket walk (populated iff `Source == 1`;
    // zero on the ZwQueryDirectoryObject fallback path, `Source == 0`).
    UINT32 Reserved;
    UINT64 Address;
    UINT32 TypeIndex;
    UINT32 Source;      // 0 = zwquery, 1 = walk
} SUSPEX_OBJ_ENTRY, *PSUSPEX_OBJ_ENTRY;

typedef struct _SUSPEX_OBJ_HDR {
    UINT32 Status;    // NTSTATUS of the walk (partial data possible)
    UINT32 Count;     // entries written after this header
    UINT32 Required;  // total entries seen (may exceed Count)
    UINT32 Truncated; // 1 = budget hit before the walk finished
} SUSPEX_OBJ_HDR, *PSUSPEX_OBJ_HDR;

// ---------------------------------------------------------- thread list ----
// v10: kernel-side SystemProcessInformation walk enriched per-thread with
// ZwQueryInformationThread(ThreadBasicInformation → TebBaseAddress) and
// (ThreadQuerySetWin32StartAddress → Win32StartAddress). Both documented
// info classes — no ETHREAD offsets. Flags bit0 = Win32Start valid,
// bit1 = Teb valid (system threads have no TEB; Win32Start may be 0 for
// system-created threads).

#define SUSPEX_THREAD_FLAG_WIN32_START 0x1
#define SUSPEX_THREAD_FLAG_TEB         0x2
#define SUSPEX_THREADLIST_MAX          8192

typedef struct _SUSPEX_THREADLIST_IN {
    UINT32 Pid;      // 0 = every process
    UINT32 Reserved;
} SUSPEX_THREADLIST_IN, *PSUSPEX_THREADLIST_IN;

typedef struct _SUSPEX_THREAD_ENTRY {
    UINT32 Tid;
    UINT32 Pid;
    UINT32 State;       // KTHREAD_STATE
    UINT32 WaitReason;
    LONG   BasePriority;
    UINT32 Flags;       // SUSPEX_THREAD_FLAG_*
    UINT64 StartVa;     // SystemThreadInformation.StartAddress
    UINT64 Win32StartVa;
    UINT64 Teb;
} SUSPEX_THREAD_ENTRY, *PSUSPEX_THREAD_ENTRY;

typedef struct _SUSPEX_THREAD_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} SUSPEX_THREAD_HDR, *PSUSPEX_THREAD_HDR;

#ifdef __cplusplus
}
#endif

#endif // SUSPEX_ABI_H


