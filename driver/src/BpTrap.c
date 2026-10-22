#include "SuspexDriver.h"
#include <intrin.h>

// BpTrap.c — v11 kernel HW-BP hit observability.
//
// Armed DR0-3 breakpoints raise #DB on the hitting CPU; without a kernel
// debugger that vector resolves to KiDispatchException and a bugcheck, so
// hits were invisible (the reviewer's "kd-only" gap). Subscribing the
// SUSPEX_EVT_CLASS_BP notify class redirects every CPU's IDT[1] to
// SuspxBpTrapStub (BpTrapAsm.asm): hits whose DR6 B0-B3 bit resolves to an
// armed suspex HW bp are recorded in the notify ring and resumed (RF set
// so exec bps don't re-fault); everything else chains to the saved
// KiTrap01 unchanged.
//
// The IDT entry itself is unwritable on modern builds — the page is RO
// even via a writable alias. Instead each CPU gets a full writable COPY
// of its IDT in our nonpaged pool with entry[1] retargeted, and the CPU
// is switched to it via lidt. Install first probes a no-op lidt of the
// unchanged IDTR: hypervisors with descriptor-table exiting (observed on
// a Hyper-V guest, build 26200 — IDT page EPT-RO, lidt/CR0.WP both
// intercepted) make the probe fault and install fails NOT_SUPPORTED
// instead of corrupting anything. Kernel vectored handlers don't exist
// in the kernel (no RtlAddVectoredExceptionHandler export), so this is
// the only kernel-side mechanism.
//
// Safety notes:
//   * IDT redirection is PatchGuard territory — install is gated on
//     SUSPEX_NOTIFY_FLAG_BP_HOOK_OK and the lidt probe.
//   * The dispatch path never blocks and never allocates. Above
//     DISPATCH_LEVEL the bp-table/ring locks are skipped; a likely-ours
//     hit still consumes (counted) rather than chaining into a bugcheck.
//   * A per-CPU busy flag makes reentrant hits consume without
//     recording instead of recursing to a stack overflow.
//   * DR7.GD: a foreign "general detect" would fault on our own dr
//     reads; no in-kernel code keeps GD armed permanently, and the lab
//     gate documents the residual risk.

#pragma pack(push, 1)
typedef struct _SUSPX_IDT_ENTRY {
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT16 IstIndex : 3;
    UINT16 Reserved0 : 5;
    UINT16 Type : 5;
    UINT16 Dpl : 2;
    UINT16 Present : 1;
    UINT16 OffsetMiddle;
    UINT32 OffsetHigh;
    UINT32 Reserved1;
} SUSPX_IDT_ENTRY, *PSUSPX_IDT_ENTRY;

// __sidt emits a 10-byte operand {limit:2, base:8} — must stay packed or
// Base reads at offset 8 instead of 2 (wild pointer -> AV on deref).
typedef struct _SUSPX_IDTR {
    UINT16 Limit;
    UINT64 Base;
} SUSPX_IDTR, *PSUSPX_IDTR;
#pragma pack(pop)

#define SUSPX_TRAP_MAX_CPUS 1024
#define EFLAGS_RF 0x10000

extern VOID SuspxBpTrapStub(VOID);

volatile LONG SuspxBpTrapOn = 0;          // 1 while the hook owns int1
volatile LONG SuspxBpTrapInStub = 0;      // in-flight stub executions
volatile LONG SuspxBpTrapMissed = 0;      // hits consumed but not recorded
volatile LONG SuspxBpTrapCpuBusy[SUSPX_TRAP_MAX_CPUS];
UINT64 SuspxBpTrapChainTarget = 0;        // asm jmp target (orig KiTrap01)

static UINT64 SuspxIdtTarget(_In_ const SUSPX_IDT_ENTRY* E)
{
    return (UINT64)E->OffsetLow
         | ((UINT64)E->OffsetMiddle << 16)
         | ((UINT64)E->OffsetHigh << 32);
}

static VOID SuspxIdtSetTarget(_Inout_ SUSPX_IDT_ENTRY* E, _In_ UINT64 Addr)
{
    E->OffsetLow = (UINT16)(Addr & 0xFFFF);
    E->OffsetMiddle = (UINT16)((Addr >> 16) & 0xFFFF);
    E->OffsetHigh = (UINT32)(Addr >> 32);
}

typedef struct _SUSPX_BP_TRAP_CTX {
    UINT64 StubAddr;
    BOOLEAN Uninstall;
    UINT32 Patched;
    UINT32 Restored;
    UINT32 Foreign;      // cpus whose IDTR was neither ours nor original
    UINT32 Unmapped;     // cpus without a writable IDT copy (skipped)
} SUSPX_BP_TRAP_CTX;

// per-CPU patch state: a writable copy of the cpu's own IDT with
// entry[1] -> our stub, plus the original IDTR for restore.
typedef struct _SUSPX_BP_TRAP_CPU {
    SUSPX_IDTR OrigIdtr;     // this cpu's original IDTR (restore target)
    PVOID      CopyBase;     // page-aligned writable IDT copy
} SUSPX_BP_TRAP_CPU;
static SUSPX_BP_TRAP_CPU* SuspxBpTrapCpus = NULL;
static ULONG SuspxBpTrapCpuCount = 0;

// KeGetCurrentProcessorIndexEx isn't exported by this WDK's ntoskrnl —
// ProcessorNumberEx + IndexFromNumber covers the same ground (Vista+).
static ULONG SuspxBpTrapCpuIndex(VOID)
{
    PROCESSOR_NUMBER pn;
    ULONG idx = KeGetCurrentProcessorNumberEx(&pn);
    UNREFERENCED_PARAMETER(idx);
    return KeGetProcessorIndexFromNumber(&pn);
}

// runs at IPI_LEVEL on every processor (KeIpiGenericCall). lidt is
// locally atomic here: an int1 can only fire from code executing on this
// CPU, and this CPU is inside the callback.
static ULONG_PTR SuspxBpTrapPatchCpu(_In_ ULONG_PTR Ctx)
{
    SUSPX_BP_TRAP_CTX* c = (SUSPX_BP_TRAP_CTX*)Ctx;
    SUSPX_IDTR idtr, next;
    ULONG cpu = SuspxBpTrapCpuIndex();

    if (cpu >= SuspxBpTrapCpuCount || !SuspxBpTrapCpus
        || !SuspxBpTrapCpus[cpu].CopyBase) {
        InterlockedIncrement((volatile LONG*)&c->Unmapped);
        return 0;
    }

    if (!c->Uninstall) {
        __sidt(&idtr);
        if (idtr.Base == (UINT64)(ULONG_PTR)SuspxBpTrapCpus[cpu].CopyBase) {
            return 0; // already ours (IPI may include the caller)
        }
        next = SuspxBpTrapCpus[cpu].OrigIdtr;
        next.Base = (UINT64)(ULONG_PTR)SuspxBpTrapCpus[cpu].CopyBase;
        __lidt(&next);
        InterlockedIncrement((volatile LONG*)&c->Patched);
        return 0;
    }

    // uninstall: restore this cpu's original IDTR.
    __sidt(&idtr);
    if (idtr.Base == (UINT64)(ULONG_PTR)SuspxBpTrapCpus[cpu].CopyBase) {
        __lidt(&SuspxBpTrapCpus[cpu].OrigIdtr);
        InterlockedIncrement((volatile LONG*)&c->Restored);
    } else {
        // someone re-hooked after us — leave their state, log-worthy
        InterlockedIncrement((volatile LONG*)&c->Foreign);
    }
    return 0;
}

// PASSIVE: park the caller on each cpu in turn, capture its IDTR, and
// build the writable copy with entry[1] -> SuspxBpTrapStub.
static NTSTATUS SuspxBpTrapMapIdts(_In_ ULONG Ncpu, _In_ UINT64 StubAddr)
{
    ULONG i;
    NTSTATUS st;
    SuspxBpTrapCpus = (SUSPX_BP_TRAP_CPU*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, Ncpu * sizeof(SUSPX_BP_TRAP_CPU), 'pcBS');
    if (!SuspxBpTrapCpus) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(SuspxBpTrapCpus, Ncpu * sizeof(SUSPX_BP_TRAP_CPU));
    SuspxBpTrapCpuCount = Ncpu;

    for (i = 0; i < Ncpu; i++) {
        PROCESSOR_NUMBER pn;
        GROUP_AFFINITY ga, old;
        SUSPX_IDTR idtr;
        SIZE_T copyLen;

        st = KeGetProcessorNumberFromIndex(i, &pn);
        if (!NT_SUCCESS(st)) {
            continue; // hole in the index space — leave unmapped
        }
        RtlZeroMemory(&ga, sizeof(ga));
        ga.Group = pn.Group;
        ga.Mask = (KAFFINITY)1 << pn.Number;
        KeSetSystemGroupAffinityThread(&ga, &old);
        __sidt(&idtr);
        KeRevertToUserGroupAffinityThread(&old);

        copyLen = (SIZE_T)idtr.Limit + 1;
        if (copyLen > PAGE_SIZE) {
            SuspxLog("BPTRAP map cpu%u: idt limit %x > page", i, idtr.Limit);
            continue;
        }
        SuspxBpTrapCpus[i].OrigIdtr = idtr;
        // PAGE_SIZE pool allocations come back page-aligned.
        SuspxBpTrapCpus[i].CopyBase = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, PAGE_SIZE, 'icBS');
        if (!SuspxBpTrapCpus[i].CopyBase) {
            SuspxLog("BPTRAP map cpu%u: copy alloc failed", i);
            continue;
        }
        RtlCopyMemory(SuspxBpTrapCpus[i].CopyBase,
                      (PVOID)(ULONG_PTR)idtr.Base, copyLen);
        SuspxIdtSetTarget(
            &((PSUSPX_IDT_ENTRY)SuspxBpTrapCpus[i].CopyBase)[1], StubAddr);
    }
    return STATUS_SUCCESS;
}

static VOID SuspxBpTrapUnmapIdts(VOID)
{
    ULONG i;
    if (!SuspxBpTrapCpus) {
        return;
    }
    for (i = 0; i < SuspxBpTrapCpuCount; i++) {
        if (SuspxBpTrapCpus[i].CopyBase) {
            ExFreePoolWithTag(SuspxBpTrapCpus[i].CopyBase, 'icBS');
        }
    }
    ExFreePoolWithTag(SuspxBpTrapCpus, 'pcBS');
    SuspxBpTrapCpus = NULL;
    SuspxBpTrapCpuCount = 0;
}

// capability probe: reloading the identical IDTR is architecturally a
// no-op. A fault means the hypervisor intercepts descriptor-table ops —
// the IDT-copy hook can't work, and neither could an in-place write
// (the page was already proven EPT-RO). Fail cleanly instead.
static BOOLEAN SuspxBpTrapLidtOk(VOID)
{
    BOOLEAN ok = TRUE;
    __try {
        SUSPX_IDTR cur;
        __sidt(&cur);
        __lidt(&cur);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

NTSTATUS SuspxBpTrapInstall(VOID)
{
    SUSPX_BP_TRAP_CTX ctx;
    SUSPX_IDTR idtr;
    NTSTATUS st;
    ULONG ncpu;

    if (InterlockedCompareExchange(&SuspxBpTrapOn, 0, 0) == 1) {
        return STATUS_SUCCESS; // already installed
    }
    if (SuspxSystemFlags() & SUSPEX_FLAG_HVCI) {
        SuspxLog("BPTRAP refused: HVCI on (IDT read-only)");
        return STATUS_NOT_SUPPORTED;
    }
    if (!SuspxBpTrapLidtOk()) {
        SuspxLog("BPTRAP refused: descriptor-table exiting (hypervisor)");
        return STATUS_NOT_SUPPORTED;
    }

    ncpu = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (!ncpu || ncpu > SUSPX_TRAP_MAX_CPUS) {
        ncpu = SUSPX_TRAP_MAX_CPUS;
    }

    st = SuspxBpTrapMapIdts(ncpu, (UINT64)(ULONG_PTR)SuspxBpTrapStub);
    if (!NT_SUCCESS(st)) {
        goto fail;
    }

    // the chain target is whatever vector 1 resolves to right now on the
    // caller's CPU (KiTrap01 on a stock kernel). Every CPU's kernel IDT
    // entry points at the same handler on sane hosts; a mismatch still
    // chains correctly because it only affects the jmp target.
    __sidt(&idtr);
    SuspxBpTrapChainTarget = SuspxIdtTarget(&((PSUSPX_IDT_ENTRY)idtr.Base)[1]);

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.StubAddr = (UINT64)(ULONG_PTR)SuspxBpTrapStub;
    ctx.Uninstall = FALSE;
    SuspxBpTrapPatchCpu((ULONG_PTR)&ctx);   // caller's CPU first
    KeIpiGenericCall(SuspxBpTrapPatchCpu, (ULONG_PTR)&ctx);

    SuspxLog("BPTRAP installed: patched=%u unmapped=%u chain=%llx",
             ctx.Patched, ctx.Unmapped, SuspxBpTrapChainTarget);
    if (!ctx.Patched) {
        SuspxLog("BPTRAP install failed: 0/%u cpus patched", ncpu);
        st = STATUS_UNSUCCESSFUL;
        goto fail;
    }
    InterlockedExchange(&SuspxBpTrapOn, 1);
    return STATUS_SUCCESS;

fail:
    SuspxBpTrapUnmapIdts();
    return st;
}

VOID SuspxBpTrapUninstall(VOID)
{
    SUSPX_BP_TRAP_CTX ctx;
    LARGE_INTEGER interval;
    ULONG waitedMs = 0;

    if (InterlockedCompareExchange(&SuspxBpTrapOn, 0, 0) == 0) {
        return;
    }
    // stop consuming first: in-flight and future hits chain to KiTrap01.
    InterlockedExchange(&SuspxBpTrapOn, 0);

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.StubAddr = (UINT64)(ULONG_PTR)SuspxBpTrapStub;
    ctx.Uninstall = TRUE;
    SuspxBpTrapPatchCpu((ULONG_PTR)&ctx);
    KeIpiGenericCall(SuspxBpTrapPatchCpu, (ULONG_PTR)&ctx);

    // drain stubs still mid-dispatch on any CPU (bounded)
    while (InterlockedCompareExchange(&SuspxBpTrapInStub, 0, 0) != 0
           && waitedMs < 5000) {
        interval.QuadPart = -10 * 1000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waitedMs++;
    }
    SuspxLog("BPTRAP uninstalled: restored=%u foreign=%u inStub=%ld missed=%ld",
             ctx.Restored, ctx.Foreign,
             InterlockedCompareExchange(&SuspxBpTrapInStub, 0, 0),
             SuspxBpTrapMissed);

    SuspxBpTrapUnmapIdts();
}

BOOLEAN SuspxBpTrapInstalled(VOID)
{
    return InterlockedCompareExchange(&SuspxBpTrapOn, 0, 0) == 1;
}

// called by the asm stub with interrupts masked (vector gate semantics):
// return nonzero to consume (record queued + RF set) or 0 to chain.
UINT32 SuspxBpTrapDispatch(_In_ UINT64 Rip, _In_ UINT64 Cs,
                           _Inout_ UINT64* RflagsSlot)
{
    UINT64 dr6;
    UINT32 bbits;
    UINT32 cpu;
    UINT32 pid, tid;
    KIRQL irql;
    UINT32 i;
    UINT32 bpId = 0, slot = 0xFF, access = 0;
    BOOLEAN tableScanned = FALSE;

    UNREFERENCED_PARAMETER(Cs);

    dr6 = __readdr(6);
    bbits = (UINT32)(dr6 & 0xF);            // B0-B3 = DR0-3 condition bits
    if (!bbits) {
        return 0;                           // BS/GD/BT — not a DR bp hit
    }

    cpu = SuspxBpTrapCpuIndex();
    if (cpu < SUSPX_TRAP_MAX_CPUS) {
        if (InterlockedCompareExchange(&SuspxBpTrapCpuBusy[cpu], 1, 0) != 0) {
            // reentrant hit on this CPU — consume without touching state
            // (records the loss via the missed counter below)
            InterlockedIncrement(&SuspxBpTrapMissed);
            *RflagsSlot |= EFLAGS_RF;
            return 1;
        }
    }

    irql = KeGetCurrentIrql();
    pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    tid = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    // Match the fired slot(s) against the armed bp table. The lock is
    // only reachable at <=DISPATCH_LEVEL; above that we record a minimal
    // hit (slot + drn address) whenever suspex bps are armed at all —
    // chaining to KiTrap01 with our bp still armed would bugcheck.
    if (irql <= DISPATCH_LEVEL) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&SuspxBpLock, &oldIrql);
        for (i = 0; i < SUSPEX_MAX_BP; i++) {
            PSUSPEX_BP_REC r = &SuspxBpTable[i];
            UINT64 drn;
            if (!(r->Used && r->Enabled && r->Kind == SUSPEX_BP_KIND_HW)) {
                continue;
            }
            if (!(bbits & (1u << r->Slot))) {
                continue;
            }
            // scope: per-thread, per-process, all-of-pid, or global
            if (!r->Global && r->Pid && r->Pid != pid) {
                continue;
            }
            if (r->Tid && r->Tid != tid) {
                continue;
            }
            switch (r->Slot) { // __readdr needs a constant index
            case 0: drn = __readdr(0); break;
            case 1: drn = __readdr(1); break;
            case 2: drn = __readdr(2); break;
            case 3: drn = __readdr(3); break;
            default: drn = ~0ull; break;
            }
            if (drn != r->Address) {
                continue; // stale/foreign DR contents
            }
            bpId = r->Id;
            slot = r->Slot;
            access = r->Access;
            break;
        }
        KeReleaseSpinLock(&SuspxBpLock, oldIrql);
        tableScanned = TRUE;
    }

    if (!tableScanned) {
        // resolve the first set B-bit without the table
        for (i = 0; i < 4; i++) {
            if (bbits & (1u << i)) {
                slot = i;
                break;
            }
        }
    }

    if (!SuspxBpTrapOn) {
        // teardown window: hook still installed, subscription gone —
        // chaining armed bp hits here would bugcheck; consume silently.
        InterlockedIncrement(&SuspxBpTrapMissed);
        *RflagsSlot |= EFLAGS_RF;
        goto out_consumed;
    }
    if (tableScanned) {
        // definitive answer: no matching armed record -> not ours.
        if (!bpId) {
            goto out_foreign;
        }
    } else if (SuspxBpHwArmed <= 0) {
        // couldn't scan (>DISPATCH) and nothing armed — foreign hit.
        goto out_foreign;
    }

    SuspxEvtAppendBpHit(pid, tid, Rip, dr6, bpId, slot, access,
                        (UINT32)irql);
    *RflagsSlot |= EFLAGS_RF; // skip the refire on exec bps

out_consumed:
    if (cpu < SUSPX_TRAP_MAX_CPUS) {
        InterlockedExchange(&SuspxBpTrapCpuBusy[cpu], 0);
    }
    return 1;

out_foreign:
    if (cpu < SUSPX_TRAP_MAX_CPUS) {
        InterlockedExchange(&SuspxBpTrapCpuBusy[cpu], 0);
    }
    return 0;
}
