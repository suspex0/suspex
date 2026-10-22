#include "SuspexDriver.h"
#include <intrin.h>

// Hardware (DR0-3/DR7) breakpoints: DR7 bit layout, DebugActive gate,
// kernel-APC DR arming worker, per-thread apply/clear callbacks, plus
// the public SuspxBpHw{Set,Clear} entry points and the thread-create
// notification that reaches threads born after the bp was set.

static UINT64 SuspxDr7Bits(_In_ UINT32 Slot, _In_ UINT32 Len, _In_ UINT32 Access)
{
    UINT64 rw, ln;

    switch (Access) {
    case SUSPEX_HW_WRITE: rw = 1; break;
    case SUSPEX_HW_RW: rw = 3; break;
    case SUSPEX_HW_EXEC:
    default: rw = 0; break;
    }
    switch (Len) {
    case 2: ln = 1; break;
    case 8: ln = 2; break;
    case 4: ln = 3; break;
    case 1:
    default: ln = 0; break;
    }
    // DR7 local-enable bits are L0..L3 = bits 0..3 (NOT 2*slot); RWn/LENn
    // pairs start at bit 16 with 4 bits per slot.
    return (1ull << Slot) |
           (rw << (16 + Slot * 4)) |
           (ln << (18 + Slot * 4));
}

// context ops are declared in Context.c: the attach+target-user-buffer path
// (SuspxThreadCtxOp) is the only DR-reliable mechanism on 24H2+ builds
NTSTATUS SuspxThreadCtxOp(_In_ PETHREAD Thread, _Inout_ PCONTEXT Ctx, _In_ BOOLEAN Set);

// ---- v0.9.4: kernel-APC DR arming ------------------------------------
// PsSetContextThread(CONTEXT_DEBUG_REGISTERS) does not stick on 26200.1
// (verified: read-back returns 0/0 after the set, 6x20ms retries). The
// reliable mechanism is a kernel normal APC that runs ON the target thread
// and writes the debug registers directly against the live CPU state.
// Reuses the SuspxRemoteCall APC machinery from RemoteCall.c: the "target"
// function is SuspxDrArmWorker below, executed on the target thread in
// kernel mode with (slot|clear, address, dr7bits) marshalled through the
// three remote-call arguments.

// ---- v0.9.5: DebugActive gate -----------------------------------------
// Root cause of the v0.9.4 non-persistence: on 26200.1 the kernel filters
// DR state for threads whose dispatcher-header DebugActive byte is clear
// (bit0 = ActiveDR7). PsSetContextThread drops the write (read-back 0/0),
// and a kernel-mode __writedr from the ARM APC is undone at the next
// context switch because the kernel restores the thread's saved (zeroed)
// DR state. Offsets from ntkrnlmp.pdb 72C69E72-6C64-8BC1-8257-AF38FA78A2F2
// age 1 (26200.1): _KTHREAD.Header.DebugActive = KTHREAD+0x03;
// _EPROCESS.Pcb shares the dispatcher header layout, EPROCESS+0x03.
// Setting bit0 marks the thread DR-active: the kernel then saves/restores
// live DRs across switches and the CONTEXT_DEBUG_REGISTERS path un-filters.
// Gates stay set on clear (matches the v0.9.4 comment; harmless for a lab).
#define SUSPEX_DBGACTIVE_OFFSET 0x03
#define SUSPEX_DBGACTIVE_ACTIVEDR7 0x01

static VOID SuspxDrGateEnable(_In_ PEPROCESS Proc, _In_ PETHREAD Thread)
{
    volatile UCHAR* tGate = (volatile UCHAR*)((ULONG_PTR)Thread + SUSPEX_DBGACTIVE_OFFSET);
    volatile UCHAR* pGate = (volatile UCHAR*)((ULONG_PTR)Proc + SUSPEX_DBGACTIVE_OFFSET);
    UCHAR before = *tGate;
    InterlockedOr8((volatile CHAR*)tGate, SUSPEX_DBGACTIVE_ACTIVEDR7);
    InterlockedOr8((volatile CHAR*)pGate, SUSPEX_DBGACTIVE_ACTIVEDR7);
    if (!(before & SUSPEX_DBGACTIVE_ACTIVEDR7)) {
        SuspxLog("DRGATE tid=%llu Header.DebugActive 0->1 (process gate too)",
                 (UINT64)(ULONG_PTR)PsGetThreadId(Thread));
    }
}

VOID SuspxDrArmWorker(UINT64 a1, UINT64 a2, UINT64 a3)
{
    ULONG slot = (ULONG)(a1 & 0xFF);
    BOOLEAN clear = (a1 >> 8) & 1;
    UINT64 dr7;
    SuspxLog("DRARM ran tid=%llu slot=%llu clear=%llu addr=%llx",
             (UINT64)(ULONG_PTR)PsGetCurrentThreadId(), (UINT64)slot,
             (UINT64)(clear ? 1 : 0), a2);
    if (!clear) {
        SuspxDrGateEnable(PsGetCurrentProcess(), PsGetCurrentThread());
    }
    if (clear) {
        switch (slot) {
        case 0: __writedr(0, 0); break;
        case 1: __writedr(1, 0); break;
        case 2: __writedr(2, 0); break;
        case 3: __writedr(3, 0); break;
        }
        dr7 = __readdr(7);
        dr7 &= ~a3;
        __writedr(7, dr7);
    } else {
        switch (slot) {
        case 0: __writedr(0, a2); break;
        case 1: __writedr(1, a2); break;
        case 2: __writedr(2, a2); break;
        case 3: __writedr(3, a2); break;
        }
        dr7 = __readdr(7);
        dr7 |= a3;
        __writedr(7, dr7);
    }
}
static NTSTATUS SuspxHwApplyFn(_In_ PETHREAD Thread, _Inout_ PVOID Ctx)
{
    SUSPEX_BP_REC* rec = (SUSPEX_BP_REC*)Ctx;
    CONTEXT ctx;
    NTSTATUS st;
    UINT64 tid = (UINT64)(ULONG_PTR)PsGetThreadId(Thread);
    UINT64 pid = (UINT64)(ULONG_PTR)PsGetProcessId(IoThreadToProcess(Thread));
    UINT64 dr7bits = SuspxDr7Bits(rec->Slot, rec->Length, rec->Access);
    UINT32 slotPack = (rec->Slot & 0xFF) | ((rec->Slot >> 8) << 8); /* identity */
    UINT32 queued = 0, alerted = 0;
    UNREFERENCED_PARAMETER(slotPack);

    // v0.9.5: set the DebugActive gate FIRST — this is what makes the
    // context write (and DR persistence) work on 26200.1 at all.
    SuspxDrGateEnable(IoThreadToProcess(Thread), Thread);

    // best-effort context write: with the gate set, PsSetContextThread
    // should now commit (verify via read-back below). Skipped entirely
    // when the thread can't deliver the APC the ctx op waits on — a
    // debuggee (debug subsystem owns the DRs anyway, and the write
    // provably doesn't stick there), a frozen thread (debug stop or
    // NtSuspendProcess), or a terminating one. The device queue is
    // sequential: one blocked ctx op wedges every ioctl behind it.
    // The remote APC below is the real arm in all these cases.
    {
        PEPROCESS proc = IoThreadToProcess(Thread);
        BOOLEAN debuggee = proc && PsGetProcessDebugPort(proc) != NULL;
        BOOLEAN frozen = PsGetThreadFreezeCount(Thread) != 0;
        BOOLEAN dying = PsIsThreadTerminating(Thread);
        if (debuggee || frozen || dying) {
            SuspxLog("BPHWSET ctx skip tid=%llu dbg=%d frozen=%d dying=%d (remote APC will arm)",
                     tid, (int)debuggee, (int)frozen, (int)dying);
            if (debuggee) {
                // the debug port owns this process's DRs — a foreign arm
                // fires hits the debugger can't attribute, and a resumed
                // exec-bp hit refires forever (no RF management). Hits are
                // covered by the dbgeng mirror instead.
                SuspxLog("BPHWSET apc skip tid=%llu (debuggee: debug port owns DRs)", tid);
                return STATUS_SUCCESS;
            }
        } else {
            RtlZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            (&ctx.Dr0)[rec->Slot] = rec->Address;
            ctx.Dr7 |= (UINT32)dr7bits;
            st = SuspxThreadCtxOp(Thread, &ctx, TRUE);
            if (!NT_SUCCESS(st)) {
                SuspxLog("BPHWSET ctx write tid=%llu slot=%u st=%x (continuing: remote APC will arm)",
                         tid, rec->Slot, st);
            }
            {
                CONTEXT chk;
                RtlZeroMemory(&chk, sizeof(chk));
                chk.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (NT_SUCCESS(SuspxThreadCtxOp(Thread, &chk, FALSE))) {
                    SuspxLog("BPHWSET ctx readback tid=%llu slot=%u Dr0=%llx Dr%u=%llx dr7=%llx",
                             tid, rec->Slot, chk.Dr0, rec->Slot, (&chk.Dr0)[rec->Slot],
                             (UINT64)chk.Dr7);
                } else {
                    SuspxLog("BPHWSET ctx readback FAILED tid=%llu st=%x", tid, st);
                }
            }
        }
    }

    // guaranteed arm: remote kernel APC executes SuspxDrArmWorker on the
    // target thread (live CPU DR state)
    st = SuspxRemoteCall(pid, tid, (UINT64)SuspxDrArmWorker,
                         (rec->Slot & 0xFF) | ((UINT64)0 << 8),
                         rec->Address, dr7bits,
                         SUSPEX_RC_FLAG_KERNEL, &queued, &alerted);
    return st;
}
static NTSTATUS SuspxHwClearFn(_In_ PETHREAD Thread, _Inout_ PVOID Ctx)
{
    SUSPEX_BP_REC* rec = (SUSPEX_BP_REC*)Ctx;
    CONTEXT ctx;
    NTSTATUS st;
    UINT64 tid = (UINT64)(ULONG_PTR)PsGetThreadId(Thread);
    UINT64 pid = (UINT64)(ULONG_PTR)PsGetProcessId(IoThreadToProcess(Thread));
    UINT64 dr7clear = ~SuspxDr7Bits(rec->Slot, rec->Length, rec->Access);
    UINT32 queued = 0, alerted = 0;
    UINT64 pack = (rec->Slot & 0xFF) | (0x100); /* clear flag in bit 8 */

    // best-effort context clear (DebugActive stays set; harmless) —
    // skipped for debugged/frozen/terminating threads for the same
    // reason as SuspxHwApplyFn: a thread that can't run never delivers
    // the APC Ps*ContextThread waits on, and one blocked call wedges
    // the (sequential) device queue.
    {
        PEPROCESS proc = IoThreadToProcess(Thread);
        BOOLEAN debuggee = proc && PsGetProcessDebugPort(proc) != NULL;
        BOOLEAN frozen = PsGetThreadFreezeCount(Thread) != 0;
        BOOLEAN dying = PsIsThreadTerminating(Thread);
        if (debuggee || frozen || dying) {
            st = STATUS_SUCCESS;
        } else {
            RtlZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            (&ctx.Dr0)[rec->Slot] = 0;
            ctx.Dr7 &= (UINT32)~SuspxDr7Bits(rec->Slot, rec->Length, rec->Access);
            st = SuspxThreadCtxOp(Thread, &ctx, TRUE);
            if (!NT_SUCCESS(st) && st != STATUS_INVALID_CID && st != STATUS_THREAD_IS_TERMINATING) {
                SuspxLog("BPHWCLR ctx write tid=%llu slot=%u st=%x (continuing: remote APC will clear)",
                         tid, rec->Slot, st);
            }
        }
    }

    NTSTATUS st2 = SuspxRemoteCall(pid, tid, (UINT64)SuspxDrArmWorker,
                           pack, 0, dr7clear,
                           SUSPEX_RC_FLAG_KERNEL, &queued, &alerted);
    // dead-thread NOT_FOUND (either leg) = idempotent success
    if (!NT_SUCCESS(st) && st2 == STATUS_NOT_FOUND) {
        st = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(st2)) {
        st = STATUS_SUCCESS;
    }
    return st;
}

NTSTATUS SuspxBpHwSet(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Address, _In_ UINT32 Slot,
                      _In_ UINT32 Length, _In_ UINT32 Access, _In_ UINT32 Flags,
                      _Out_ PUINT32 Id, _Out_ PUINT32 Applied)
{
    NTSTATUS st;
    KIRQL irql;
    SUSPEX_BP_REC rec;
    PSUSPEX_BP_REC slotRec;
    UINT32 newId = 0;
    UINT32 patched = 0;
    const BOOLEAN Global = (Flags & SUSPEX_BP_HW_FLAG_GLOBAL) != 0;
    const BOOLEAN DangerousOk = (Flags & SUSPEX_BP_HW_FLAG_DANGEROUS_OK) != 0;

    *Id = 0;
    *Applied = 0;
    // v6: Pid=0 legal ONLY with GLOBAL. Otherwise keep the historical
    // guard so a stray pid=0 request doesn't accidentally arm every
    // thread system-wide.
    if ((!Pid && !Global) || !Address || Slot > 3) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Access != SUSPEX_HW_EXEC && Access != SUSPEX_HW_WRITE && Access != SUSPEX_HW_RW) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Access == SUSPEX_HW_EXEC && Length != 1) {
        return STATUS_INVALID_PARAMETER; // exec DRs are always length 1
    }

    // v6: global-BP safety gates.
    //   * Cap at 2 simultaneous global BPs — otherwise a runaway caller
    //     could pin every DR slot on every thread system-wide, DoS'ing
    //     the target's own debug DRs.
    //   * If PatchGuard is expected (SuspxSystemFlags surfaces it via
    //     ping.Flags) refuse without DangerousOk — DR writes shouldn't
    //     trip PG, but defensive when we're arming ntoskrnl threads.
    if (Global) {
        UINT32 globalCount = 0;
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        for (UINT32 i = 0; i < SUSPEX_MAX_BP; i++) {
            PSUSPEX_BP_REC r = &SuspxBpTable[i];
            if (r->Used && r->Kind == SUSPEX_BP_KIND_HW && r->Global) {
                globalCount++;
            }
        }
        KeReleaseSpinLock(&SuspxBpLock, irql);
        if (globalCount >= 2) {
            SuspxLog("BPHWSET refused global: 2-BP cap hit");
            return STATUS_QUOTA_EXCEEDED;
        }
        if (!DangerousOk && (SuspxSystemFlags() & 0) /* PG expected marker */) {
            // Placeholder — SuspxSystemFlags doesn't currently expose PG
            // separately; when it does, gate here. Leaving the branch
            // in place so the flag is honored the moment the marker
            // lands, without another Breakpoints.c edit.
            (void)0;
        }
        SuspxLog("BPHWSET global tid=%llu addr=%llx slot=%u", Tid, Address, Slot);
    }

    RtlZeroMemory(&rec, sizeof(rec));
    rec.Kind = SUSPEX_BP_KIND_HW;
    rec.Pid = (UINT32)Pid;   // 0 when Global
    rec.Tid = (UINT32)Tid;
    rec.Slot = Slot;
    rec.Length = Length;
    rec.Access = Access;
    rec.Address = Address;
    rec.Enabled = 1;
    rec.Global = Global ? 1u : 0u;

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    slotRec = SuspxBpAllocLocked(&newId);
    KeReleaseSpinLock(&SuspxBpLock, irql);
    if (!slotRec) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // SuspxProcessThreadApply handles Pid==0 as "walk every process"
    // when Tid==0 too. Tid!=0 with Pid==0 doesn't really make sense
    // (a tid uniquely identifies a thread already) but we let it through.
    st = SuspxProcessThreadApply(Pid, Tid, SuspxHwApplyFn, &rec, &patched);
    if (!NT_SUCCESS(st) && !Global) {
        // Non-global failures roll back. Global mode ate at least some
        // per-thread failures (defunct threads); tolerate partial as
        // long as *something* was patched. If nothing at all was
        // patched, still roll back.
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        SuspxBpFreeLocked(slotRec);
        KeReleaseSpinLock(&SuspxBpLock, irql);
        return st;
    }
    // v0.9.2: patched==0 for a non-global arm is now a hard failure.
    // Pre-v0.9.2 kept the registry entry even when SuspxHwApplyFn's
    // new verify pass rejected every thread — the caller then saw a
    // successful add with applied=0 and no signal the bp was inert.
    // Roll back so bp_manage add surfaces the reality directly.
    if (patched == 0) {
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        SuspxBpFreeLocked(slotRec);
        KeReleaseSpinLock(&SuspxBpLock, irql);
        SuspxLog("BPHWSET no thread armed pid=%llu tid=%llu slot=%u global=%u -> rollback",
                 Pid, Tid, Slot, Global);
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    *slotRec = rec;
    slotRec->Used = 1;
    slotRec->Id = newId;
    InterlockedIncrement(&SuspxBpHwArmed);

    *Id = newId;
    *Applied = patched;
    return STATUS_SUCCESS;
}

NTSTATUS SuspxBpHwClear(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT32 Slot, _Out_ PUINT32 Applied)
{
    NTSTATUS st;
    KIRQL irql;
    SUSPEX_BP_REC rec;
    UINT32 patched = 0, i;
    BOOLEAN found = FALSE;

    *Applied = 0;
    // v6: Pid==0 is valid — matches the global registry entry.
    if (Slot > 3) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        PSUSPEX_BP_REC r = &SuspxBpTable[i];
        if (r->Kind == SUSPEX_BP_KIND_HW && r->Used && r->Enabled && r->Pid == (UINT32)Pid &&
            r->Slot == Slot && (!Tid || r->Tid == (UINT32)Tid)) {
            rec = *r;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&SuspxBpLock, irql);
    if (!found) {
        // v0.9.2: idempotent clear. The pre-v0.9.2 behavior surfaced
        // STATUS_NOT_FOUND (c0000225) to the caller whenever the entry
        // was already gone — a double-clear, or a clear following the
        // auto-prune on thread-exit. The correct end state (no bp) is
        // already reached, so return success with Applied=0.
        SuspxLog("BPHWCLR already-clean pid=%llu tid=%llu slot=%u", Pid, Tid, Slot);
        return STATUS_SUCCESS;
    }

    st = SuspxProcessThreadApply(Pid, rec.Tid, SuspxHwClearFn, &rec, &patched);

    KeAcquireSpinLock(&SuspxBpLock, &irql);
    for (i = 0; i < SUSPEX_MAX_BP; i++) {
        PSUSPEX_BP_REC r = &SuspxBpTable[i];
        if (r->Used && r->Id == rec.Id) {
            SuspxBpFreeLocked(r);
            InterlockedDecrement(&SuspxBpHwArmed);
        }
    }
    KeReleaseSpinLock(&SuspxBpLock, irql);

    *Applied = patched;
    return st;
}

// all-thread HW breakpoints must also reach threads created after the bp was
// set; runs at PASSIVE_LEVEL from the thread-create notification
VOID SuspxOnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UINT32 i;
    KIRQL irql;
    PETHREAD thread;
    SUSPEX_BP_REC snap[SUSPEX_MAX_BP];
    UINT32 snapCount = 0;
    UINT32 pruned = 0;

    if (!Create) {
        // v0.9.2: auto-prune per-thread HW BPs when the armed thread
        // exits. Without this the registry accretes stale entries
        // that only surface as an error at the next bp_manage remove.
        // Global BPs (r->Global=1) are kept — they cover future
        // threads, and their per-thread arming is bookkept elsewhere.
        // Tid==0 (all-threads-of-pid) entries are also kept — the pid
        // may still have other live threads; the entry only stops
        // mattering when the process itself exits, and process-exit
        // notifications reap the whole pid via a separate callback.
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        for (i = 0; i < SUSPEX_MAX_BP; i++) {
            PSUSPEX_BP_REC r = &SuspxBpTable[i];
            if (r->Used && r->Enabled && r->Kind == SUSPEX_BP_KIND_HW &&
                !r->Global && r->Tid && r->Tid == (UINT32)(ULONG_PTR)ThreadId) {
                SuspxBpFreeLocked(r);
                InterlockedDecrement(&SuspxBpHwArmed);
                pruned++;
            }
        }
        KeReleaseSpinLock(&SuspxBpLock, irql);
        if (pruned) {
            SuspxLog("BPHWPRN thread-exit pid=%llu tid=%llu -> pruned=%u",
                     (UINT64)(ULONG_PTR)ProcessId,
                     (UINT64)(ULONG_PTR)ThreadId, pruned);
        }
        return;
    }

    InterlockedIncrement(&SuspxThreadNotifyActive);
    __try {
        KeAcquireSpinLock(&SuspxBpLock, &irql);
        for (i = 0; i < SUSPEX_MAX_BP; i++) {
            PSUSPEX_BP_REC r = &SuspxBpTable[i];
            if (!(r->Used && r->Enabled && r->Kind == SUSPEX_BP_KIND_HW && r->Tid == 0)) {
                continue;
            }
            // v6: Global BPs arm newborns regardless of parent pid;
            // per-pid BPs still only arm children of their pid.
            if (r->Global || r->Pid == (UINT32)(ULONG_PTR)ProcessId) {
                snap[snapCount++] = *r;
            }
        }
        KeReleaseSpinLock(&SuspxBpLock, irql);

        if (!snapCount) {
            return;
        }
        if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) {
            return;
        }
        for (i = 0; i < snapCount; i++) {
            SuspxHwApplyFn(thread, &snap[i]);
        }
        ObDereferenceObject(thread);
    } __finally {
        InterlockedDecrement(&SuspxThreadNotifyActive);
    }
}

// classic (non-Ex) callback: receives the PEPROCESS instead of the pid — used
// as a fallback because PsSetCreateThreadNotifyRoutineEx demands /INTEGRITYCHECK
VOID SuspxOnThreadNotifyClassic(_In_ PEPROCESS Process, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    // v0.9.2: forward BOTH create and exit notifications. The pre-v0.9.2
    // guard bailed on !Create, so on classic-callback builds the auto-
    // prune of dead per-thread HW BPs never ran and the registry
    // accumulated stale entries.
    if (!Process) {
        return;
    }
    SuspxOnThreadNotify(PsGetProcessId(Process), ThreadId, Create);
}
