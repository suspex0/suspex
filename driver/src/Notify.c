#include "SuspexDriver.h"

// Ps{Set,Remove}CreateProcessNotifyRoutine{,Ex}: the Set variants are in
// ntoskrnl.lib, but the Remove variants are missing from the WDK import
// lib in this configuration — resolve all four at runtime via
// MmGetSystemRoutineAddress (same pattern as PsGetProcessVadRoot in Vad.c).
typedef NTSTATUS (*SUSPEX_PROC_NOTIFY_SET_FN)(PVOID NotifyRoutine, BOOLEAN Remove);
typedef NTSTATUS (*SUSPEX_PROC_NOTIFY_RM_FN)(PVOID NotifyRoutine);
static SUSPEX_PROC_NOTIFY_SET_FN SuspxProcSetEx;   // PsSetCreateProcessNotifyRoutineEx
static SUSPEX_PROC_NOTIFY_RM_FN SuspxProcRemoveEx; // PsRemoveCreateProcessNotifyRoutineEx
static SUSPEX_PROC_NOTIFY_SET_FN SuspxProcSet;     // PsSetCreateProcessNotifyRoutine
static SUSPEX_PROC_NOTIFY_RM_FN SuspxProcRemove;   // PsRemoveCreateProcessNotifyRoutine
NTKERNELAPI NTSTATUS PsSetLoadImageNotifyRoutine(_In_ PVOID NotifyRoutine);
NTKERNELAPI NTSTATUS PsRemoveLoadImageNotifyRoutine(_In_ PVOID NotifyRoutine);

// v10 notify ring: the agent's "ears". PsSet{CreateProcess,CreateThread,
// LoadImage}NotifyRoutine callbacks append fixed-size records to a static
// overwrite-oldest ring; NOTIFY_READ drains oldest-first under the spinlock.
//
// Callback contract: they run at <=DISPATCH_LEVEL in an arbitrary process
// context while the process/thread/image machinery holds its own locks.
// The only legal work here is a bounded spinlock-guarded copy — no Zw*,
// no paging, no allocation, no logging. The ring never blocks the
// notifying thread: on overflow the oldest record is overwritten and
// SuspxEvtDropped counts the loss so readers can report the gap honestly.

static SUSPEX_EVT SuspxEvtRing[SUSPEX_EVT_RING];
static KSPIN_LOCK SuspxEvtLock;
static UINT32 SuspxEvtHead;         // next write slot
static UINT32 SuspxEvtBuffered;     // entries currently in the ring
static UINT64 SuspxEvtNextSeq = 1;  // next seq to issue
static UINT64 SuspxEvtDropped;      // overwrite-oldest counter
static UINT64 SuspxEvtTotal;        // cumulative events appended
static volatile UINT32 SuspxEvtSubscribed; // registered class bitmask
static volatile LONG SuspxEvtInFlight;     // callbacks executing

// registration state: 0 = not registered, 1 = Ex variant, 2 = classic
static volatile LONG SuspxRegProc;
static volatile LONG SuspxRegImage;
static volatile LONG SuspxRegThread;

static LARGE_INTEGER SuspxEvtQpcFreq;

VOID SuspxNotifyInit(VOID)
{
    KeInitializeSpinLock(&SuspxEvtLock);
    SuspxEvtHead = 0;
    SuspxEvtBuffered = 0;
    SuspxEvtNextSeq = 1;
    SuspxEvtDropped = 0;
    SuspxEvtTotal = 0;
    SuspxEvtSubscribed = 0;
    SuspxEvtInFlight = 0;
    SuspxRegProc = 0;
    SuspxRegImage = 0;
    SuspxRegThread = 0;
    SuspxEvtQpcFreq = KeQueryPerformanceCounter(NULL);

    // runtime-resolve the process-notify registry entry points (missing
    // from the WDK import lib; see the comment above)
    {
        UNICODE_STRING s;
        RtlInitUnicodeString(&s, L"PsSetCreateProcessNotifyRoutineEx");
        SuspxProcSetEx = (SUSPEX_PROC_NOTIFY_SET_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsRemoveCreateProcessNotifyRoutineEx");
        SuspxProcRemoveEx = (SUSPEX_PROC_NOTIFY_RM_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsSetCreateProcessNotifyRoutine");
        SuspxProcSet = (SUSPEX_PROC_NOTIFY_SET_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsRemoveCreateProcessNotifyRoutine");
        SuspxProcRemove = (SUSPEX_PROC_NOTIFY_RM_FN)MmGetSystemRoutineAddress(&s);
    }
}

// shared ring-write tail: caller holds SuspxEvtLock (at whatever IRQL it
// was acquired — the routine itself is IRQL-agnostic).
static VOID SuspxEvtAppendLocked(_In_ UINT32 Kind, _In_ UINT32 Pid,
                                 _In_ UINT32 ParentPid, _In_ UINT32 Tid,
                                 _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                 _In_ PCWSTR Image, _In_ UINT64 Address,
                                 _In_ UINT64 Dr6, _In_ UINT32 BpId,
                                 _In_ UINT32 Slot, _In_ UINT32 Access,
                                 _In_ UINT32 Irql)
{
    SUSPEX_EVT* e;
    LARGE_INTEGER qpc;

    qpc = KeQueryPerformanceCounter(&SuspxEvtQpcFreq);
    e = &SuspxEvtRing[SuspxEvtHead];
    RtlZeroMemory(e, sizeof(*e));
    e->Seq = SuspxEvtNextSeq++;
    e->TsMs = SuspxEvtQpcFreq.QuadPart
                  ? (UINT64)(qpc.QuadPart / (SuspxEvtQpcFreq.QuadPart / 1000))
                  : 0;
    e->Kind = Kind;
    e->Pid = Pid;
    e->ParentPid = ParentPid;
    e->Tid = Tid;
    e->ImageBase = ImageBase;
    e->ImageSize = ImageSize;
    e->Address = Address;
    e->Dr6 = Dr6;
    e->BpId = BpId;
    e->Slot = Slot;
    e->Access = Access;
    e->Irql = Irql;
    if (Image) {
        SIZE_T cch = 0;
        while (cch < SUSPEX_EVT_IMAGE_CCH - 1 && Image[cch]) {
            cch++;
        }
        RtlCopyMemory(e->Image, Image, cch * sizeof(WCHAR));
    }
    SuspxEvtHead = (SuspxEvtHead + 1) % SUSPEX_EVT_RING;
    if (SuspxEvtBuffered < SUSPEX_EVT_RING) {
        SuspxEvtBuffered++;
    } else {
        SuspxEvtDropped++; // head overwrote the oldest entry
    }
    SuspxEvtTotal++;
}

static VOID SuspxEvtAppend(UINT32 Kind, UINT32 Pid, UINT32 ParentPid, UINT32 Tid,
                           UINT64 ImageBase, UINT64 ImageSize, PCWSTR Image)
{
    KIRQL irql;

    // kind -> owning class (the subscription bitmask is class-grained)
    switch (Kind) {
    case SUSPEX_EVT_KIND_PROC_CREATE:
    case SUSPEX_EVT_KIND_PROC_EXIT:
        if (!(SuspxEvtSubscribed & SUSPEX_EVT_CLASS_PROC)) return;
        break;
    case SUSPEX_EVT_KIND_IMAGE_LOAD:
        if (!(SuspxEvtSubscribed & SUSPEX_EVT_CLASS_IMAGE)) return;
        break;
    case SUSPEX_EVT_KIND_THREAD_CREATE:
    case SUSPEX_EVT_KIND_THREAD_EXIT:
        if (!(SuspxEvtSubscribed & SUSPEX_EVT_CLASS_THREAD)) return;
        break;
    default:
        return;
    }
    InterlockedIncrement(&SuspxEvtInFlight);

    KeAcquireSpinLock(&SuspxEvtLock, &irql);
    SuspxEvtAppendLocked(Kind, Pid, ParentPid, Tid, ImageBase, ImageSize,
                         Image, 0, 0, 0, 0xFF, 0, 0);
    KeReleaseSpinLock(&SuspxEvtLock, irql);
    InterlockedDecrement(&SuspxEvtInFlight);
}

// v11: BP_HIT append from the int1 trap path (BpTrap.c). Callable at any
// IRQL — the trap handler may run at DISPATCH or above, where a raising
// acquire would corrupt IRQL — so at DISPATCH+ the lock is try-acquired
// and a contention loss is counted via SuspxBpTrapMissed instead of
// spinning (the alternative is a deadlock when the lock holder lives on
// the same CPU).
VOID SuspxEvtAppendBpHit(_In_ UINT32 Pid, _In_ UINT32 Tid, _In_ UINT64 Rip,
                         _In_ UINT64 Dr6, _In_ UINT32 BpId, _In_ UINT32 Slot,
                         _In_ UINT32 Access, _In_ UINT32 Irql)
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN locked = FALSE;

    if (!(SuspxEvtSubscribed & SUSPEX_EVT_CLASS_BP)) {
        return;
    }
    InterlockedIncrement(&SuspxEvtInFlight);
    if (Irql < DISPATCH_LEVEL) {
        KeAcquireSpinLock(&SuspxEvtLock, &oldIrql);
        locked = TRUE;
    } else {
        locked = KeTryToAcquireSpinLockAtDpcLevel(&SuspxEvtLock);
    }
    if (!locked) {
        InterlockedIncrement(&SuspxBpTrapMissed);
        InterlockedDecrement(&SuspxEvtInFlight);
        return;
    }
    SuspxEvtAppendLocked(SUSPEX_EVT_KIND_BP_HIT, Pid, 0, Tid,
                         0, 0, NULL, Rip, Dr6, BpId, Slot, Access, Irql);
    if (Irql < DISPATCH_LEVEL) {
        KeReleaseSpinLock(&SuspxEvtLock, oldIrql);
    } else {
        KeReleaseSpinLockFromDpcLevel(&SuspxEvtLock);
    }
    InterlockedDecrement(&SuspxEvtInFlight);
}

// --- process notify (Ex preferred: carries the image path; classic fallback)
// NOTE: the Ex callback signature is (PEPROCESS, HANDLE ProcessId,
// PS_CREATE_NOTIFY_INFO*) — three parameters. A two-parameter callback
// misreads ProcessId as CreateInfo and dereferences a HANDLE as a pointer
// on the first process event (bugcheck — learned the hard way).

static VOID SuspxOnEvtProcEx(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                             _Inout_ PS_CREATE_NOTIFY_INFO* CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UINT32 pid = (UINT32)(ULONG_PTR)ProcessId;
    if (CreateInfo) {
        PCWSTR img = (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer)
                         ? CreateInfo->ImageFileName->Buffer : NULL;
        SuspxEvtAppend(SUSPEX_EVT_KIND_PROC_CREATE, pid,
                       (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId, 0,
                       0, 0, img);
    } else {
        SuspxEvtAppend(SUSPEX_EVT_KIND_PROC_EXIT, pid, 0, 0, 0, 0, NULL);
    }
}

static VOID SuspxOnEvtProcClassic(_In_ HANDLE ParentId, _In_ HANDLE ProcessId,
                                  _In_ BOOLEAN Create)
{
    SuspxEvtAppend(Create ? SUSPEX_EVT_KIND_PROC_CREATE : SUSPEX_EVT_KIND_PROC_EXIT,
                   (UINT32)(ULONG_PTR)ProcessId, (UINT32)(ULONG_PTR)ParentId,
                   0, 0, 0, NULL);
}

// --- image load notify (fires for kernel images too, so driver loads
// surface as IMAGE_LOAD events with SystemModeImage set in the name path)

static VOID SuspxOnEvtImage(_In_opt_ PUNICODE_STRING FullImageName,
                            _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    SuspxEvtAppend(SUSPEX_EVT_KIND_IMAGE_LOAD,
                   (UINT32)(ULONG_PTR)ProcessId, 0, 0,
                   (UINT64)ImageInfo->ImageBase, ImageInfo->ImageSize,
                   FullImageName ? FullImageName->Buffer : NULL);
}

// --- thread notify (classic variant; coexists with the BP feature's own
// registration — the OS allows up to 64 notify callbacks)

static VOID SuspxOnEvtThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                             _In_ BOOLEAN Create)
{
    SuspxEvtAppend(Create ? SUSPEX_EVT_KIND_THREAD_CREATE : SUSPEX_EVT_KIND_THREAD_EXIT,
                   (UINT32)(ULONG_PTR)ProcessId, 0, (UINT32)(ULONG_PTR)ThreadId,
                   0, 0, NULL);
}

NTSTATUS SuspxNotifySubscribe(_In_ UINT32 Classes, _In_ UINT32 Flags,
                              _Out_ UINT32* Registered)
{
    NTSTATUS st;
    // Classes=0 means "all" — but the BP class installs an IDT hook, so it
    // is excluded from the wildcard: callers must name CLASS_BP explicitly
    // AND pass FLAG_BP_HOOK_OK.
    UINT32 want = Classes ? Classes : (SUSPEX_EVT_CLASS_ALL & ~SUSPEX_EVT_CLASS_BP);
    UINT32 ok = 0;
    NTSTATUS bpSt = STATUS_SUCCESS;

    *Registered = 0;

    if (want & SUSPEX_EVT_CLASS_PROC && !SuspxRegProc) {
        if (!SuspxProcSetEx || !SuspxProcSet) {
            SuspxLog("notify: proc routines unresolved (skipping proc class)");
        } else {
            st = SuspxProcSetEx(SuspxOnEvtProcEx, FALSE);
            if (NT_SUCCESS(st)) {
                SuspxRegProc = 1;
            } else {
                st = SuspxProcSet(SuspxOnEvtProcClassic, FALSE);
                if (!NT_SUCCESS(st)) {
                    SuspxLog("notify: proc register failed st=%x", st);
                    return st;
                }
                SuspxRegProc = 2;
                SuspxLog("notify: proc Ex refused, classic registered (no image path)");
            }
        }
    }
    if (want & SUSPEX_EVT_CLASS_PROC) {
        ok |= SUSPEX_EVT_CLASS_PROC;
    }

    if (want & SUSPEX_EVT_CLASS_IMAGE && !SuspxRegImage) {
        st = PsSetLoadImageNotifyRoutine(SuspxOnEvtImage);
        if (!NT_SUCCESS(st)) {
            SuspxLog("notify: image register failed st=%x", st);
            return st;
        }
        SuspxRegImage = 1;
    }
    if (want & SUSPEX_EVT_CLASS_IMAGE) {
        ok |= SUSPEX_EVT_CLASS_IMAGE;
    }

    if (want & SUSPEX_EVT_CLASS_THREAD && !SuspxRegThread) {
        st = PsSetCreateThreadNotifyRoutine(SuspxOnEvtThread);
        if (!NT_SUCCESS(st)) {
            SuspxLog("notify: thread register failed st=%x", st);
            return st;
        }
        SuspxRegThread = 1;
    }
    if (want & SUSPEX_EVT_CLASS_THREAD) {
        ok |= SUSPEX_EVT_CLASS_THREAD;
    }

    // v11: CLASS_BP = the int1 hook, not a Ps callback. Refused without
    // FLAG_BP_HOOK_OK (IDT patching is PG-sensitive) and under HVCI
    // (install itself fails there). A refused/failed BP class does not
    // sink the other classes — the bit's absence in *Registered is the
    // honest signal; bpSt propagates when BP was the sole request.
    if (want & SUSPEX_EVT_CLASS_BP) {
        if (!(Flags & SUSPEX_NOTIFY_FLAG_BP_HOOK_OK)) {
            SuspxLog("notify: CLASS_BP refused (no FLAG_BP_HOOK_OK)");
            bpSt = STATUS_ACCESS_DENIED;
        } else {
            bpSt = SuspxBpTrapInstall();
            if (NT_SUCCESS(bpSt)) {
                ok |= SUSPEX_EVT_CLASS_BP;
            } else {
                SuspxLog("notify: CLASS_BP install failed st=%x", bpSt);
            }
        }
    }

    InterlockedOr((volatile LONG*)&SuspxEvtSubscribed, ok);
    SuspxLog("notify subscribe want=%x flags=%x ok=%x bpSt=%x", want, Flags,
             ok, bpSt);
    *Registered = ok;
    if (!NT_SUCCESS(bpSt) && !(ok & ~SUSPEX_EVT_CLASS_BP)) {
        return bpSt; // BP was the only class asked for — surface it
    }
    return STATUS_SUCCESS;
}

VOID SuspxNotifyDisable(VOID)
{
    // Snapshot-then-clear: each registered callback is removed exactly once.
    // InterlockedExchange returns the previous value, so a concurrent
    // DISABLE cannot double-remove.
    LONG proc = InterlockedExchange(&SuspxRegProc, 0);
    LONG img = InterlockedExchange(&SuspxRegImage, 0);
    LONG thr = InterlockedExchange(&SuspxRegThread, 0);

    if (proc == 1) {
        if (SuspxProcRemoveEx) {
            SuspxProcRemoveEx(SuspxOnEvtProcEx);
        }
    } else if (proc == 2) {
        if (SuspxProcRemove) {
            SuspxProcRemove(SuspxOnEvtProcClassic);
        }
    }
    if (img) {
        PsRemoveLoadImageNotifyRoutine(SuspxOnEvtImage);
    }
    if (thr) {
        PsRemoveCreateThreadNotifyRoutine(SuspxOnEvtThread);
    }

    // bounded in-flight drain: callbacks may still run on other CPUs
    {
        LARGE_INTEGER interval;
        ULONG waitedMs = 0;
        while (SuspxEvtInFlight > 0 && waitedMs < 5000) {
            interval.QuadPart = -10 * 1000; // 1 ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            waitedMs++;
        }
        if (SuspxEvtInFlight > 0) {
            SuspxLog("NOTIFY WARNING: %d callback(s) still in flight", SuspxEvtInFlight);
        }
    }
    // v11: drop the int1 hook before ungating the class bit — hits during
    // teardown chain to KiTrap01 rather than recording into a dead ring.
    InterlockedAnd((volatile LONG*)&SuspxEvtSubscribed, ~SUSPEX_EVT_CLASS_BP);
    SuspxBpTrapUninstall();

    InterlockedExchange((volatile LONG*)&SuspxEvtSubscribed, 0);
    SuspxLog("notify disabled (buffered=%u dropped=%llu)",
             SuspxEvtBuffered, SuspxEvtDropped);
}

NTSTATUS SuspxNotifyRead(_In_ UINT32 Max, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT64 Dropped, _Out_ PUINT64 LastSeq)
{
    KIRQL irql;
    PSUSPEX_EVT out = (PSUSPEX_EVT)Buffer;
    UINT32 cap, n = 0, tail;

    *Count = 0;
    *Dropped = 0;
    *LastSeq = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_EVT));
    if (cap > SUSPEX_EVT_RING) {
        cap = SUSPEX_EVT_RING;
    }
    if (Max && cap > Max) {
        cap = Max;
    }

    KeAcquireSpinLock(&SuspxEvtLock, &irql);
    tail = (SuspxEvtHead + SUSPEX_EVT_RING - SuspxEvtBuffered) % SUSPEX_EVT_RING;
    while (n < cap && SuspxEvtBuffered > 0) {
        RtlCopyMemory(&out[n], &SuspxEvtRing[tail], sizeof(SUSPEX_EVT));
        tail = (tail + 1) % SUSPEX_EVT_RING;
        SuspxEvtBuffered--;
        n++;
    }
    *Dropped = SuspxEvtDropped;
    if (n) {
        *LastSeq = out[n - 1].Seq;
    }
    KeReleaseSpinLock(&SuspxEvtLock, irql);
    *Count = n;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxNotifyStats(_Out_ SUSPEX_NOTIFY_STATS_OUT* Out)
{
    KIRQL irql;
    RtlZeroMemory(Out, sizeof(*Out));
    KeAcquireSpinLock(&SuspxEvtLock, &irql);
    Out->Buffered = SuspxEvtBuffered;
    Out->Dropped = SuspxEvtDropped;
    Out->Seq = SuspxEvtNextSeq - 1;
    Out->Total = SuspxEvtTotal;
    KeReleaseSpinLock(&SuspxEvtLock, irql);
    Out->Registered = SuspxEvtSubscribed;
    Out->ProcVariant = (UINT32)SuspxRegProc;
    Out->BpTrapMissed = (UINT32)InterlockedCompareExchange(&SuspxBpTrapMissed, 0, 0);
    return STATUS_SUCCESS;
}
